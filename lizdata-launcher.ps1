param(
  [string]$Browser = '',
  [string]$Page = '',
  [string]$Api = '',          # nombre del driver RP1210 (ej. NULN2R32). Vacio = buscar NEXIQ
  [int]$Port = 8764
)
# ============================================================================
# LIZ-DATA launcher + NEXIQ link
# Abre LIZ-DATA y queda en segundo plano como enlace con el NEXIQ (RP1210).
# Solo toma el NEXIQ cuando LIZ-DATA lo pide (Conectar) y se cierra solo
# cuando se cierra LIZ-DATA. Corre en PowerShell de 32 bits (drivers RP1210 de 32 bits).
# ============================================================================
$ErrorActionPreference = 'Stop'
try { $Host.UI.RawUI.WindowTitle = 'LIZ-DATA' } catch { }
$script:logFile = Join-Path $env:LOCALAPPDATA 'LIZ-DATA\launcher.log'
function Log([string]$t) { try { Add-Content -Path $script:logFile -Value ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $t) } catch { } }
# Cualquier error que cierre el enlace queda escrito en el registro (con la linea)
trap { Log ('ERROR que cerro el enlace: ' + $_.Exception.Message + ' (linea ' + $_.InvocationInfo.ScriptLineNumber + ')'); break }
Log ("Inicio del enlace LIZ-DATA (PID $PID)")
# Un solo enlace a la vez. Si el icono se abre dos veces, el segundo NO cierra al primero:
# espera a que el primero atienda y solo abre la ventana.
$creado = $false
$script:mutex = New-Object System.Threading.Mutex($true, 'Local\LIZ-DATA-Link', [ref]$creado)
if (-not $creado) {
  Log 'Ya hay un enlace arrancando o funcionando: solo se abre la ventana'
  $wc = New-Object System.Net.WebClient
  for ($i = 0; $i -lt 40; $i++) { try { [void]$wc.DownloadString("http://localhost:$Port/ping"); break } catch { Start-Sleep -Milliseconds 500 } }
  if ($Browser) { Start-Process -FilePath $Browser -ArgumentList "--app=`"http://localhost:$Port/`" --window-size=1200,820" }
  exit 0
}

Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class LizRp1210 {
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)] static extern IntPtr LoadLibrary(string f);
  [DllImport("kernel32", CharSet = CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr h, string n);

  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  delegate short ConnectD(IntPtr hwnd, short dev, [MarshalAs(UnmanagedType.LPStr)] string proto, int tx, int rx, short pack);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate short DisconnectD(short c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate short ReadD(short c, byte[] buf, short size, short block);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate short SendD(short c, byte[] msg, short size, short notify, short block);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate short CmdD(short cmd, short c, byte[] data, short size);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate short ErrD(short code, StringBuilder sb);

  ConnectD fConnect; DisconnectD fDisconnect; ReadD fRead; SendD fSend; CmdD fCmd; ErrD fErr;
  short client = -1;
  Thread reader;
  volatile bool running;

  class Entry { public int pgn, sa, count; public byte[] data; public DateTime first, last;
                public byte[] noise = new byte[8]; public DateTime[] lastEvt = new DateTime[8]; }
  // Detector de switches (WATCH)
  volatile bool watchOn;
  DateTime quietUntil;
  readonly List<string> events = new List<string>();
  int eventId;
  public void WatchStart() {
    lock (table) {
      foreach (Entry e in table.Values) { e.noise = new byte[8]; e.lastEvt = new DateTime[8]; }
      events.Clear(); quietUntil = DateTime.Now.AddSeconds(3); watchOn = true;
    }
  }
  public void WatchStop() { watchOn = false; }
  public string WatchState() { return !watchOn ? "off" : (DateTime.Now < quietUntil ? "quiet" : "ready"); }
  public string EventsJson(int since) {
    StringBuilder sb = new StringBuilder("[");
    lock (table) {
      bool first = true;
      foreach (string ev in events) {
        int id = int.Parse(ev.Substring(6, ev.IndexOf(',') - 6));
        if (id <= since) continue;
        if (!first) sb.Append(','); first = false; sb.Append(ev);
      }
    }
    return sb.Append(']').ToString();
  }
  void AddEvent(Entry e, int k, int bit, int width, int from, int to) {
    eventId++;
    events.Add("{\"id\":" + eventId + ",\"pgn\":" + e.pgn + ",\"sa\":" + e.sa + ",\"byte\":" + (k + 1) + ",\"bit\":" + bit +
               ",\"width\":" + width + ",\"from\":" + from + ",\"to\":" + to + "}");
    if (events.Count > 500) events.RemoveAt(0);
  }
  void WatchCheck(Entry e, byte[] d) {
    if (e.pgn == 60928 || e.pgn == 59904 || e.pgn == 60416 || e.pgn == 60160) return;
    bool prop = e.pgn >= 65280 || (e.pgn & 0x3FF00) == 61184;
    DateTime now = DateTime.Now;
    for (int k = 0; k < 8; k++) {
      int ch = (e.data[k] ^ d[k]) & ~e.noise[k] & 0xFF;
      if (ch == 0) continue;
      if ((now - e.lastEvt[k]).TotalMilliseconds < 150) { e.noise[k] |= (byte)ch; continue; }
      e.lastEvt[k] = now;
      bool rep = false;
      for (int off = 0; off < 8; off += 2) {
        if (((ch >> off) & 3) == 0) continue;
        int va = (e.data[k] >> off) & 3, vb = (d[k] >> off) & 3;
        if (va >= 2 || vb >= 2) continue;
        rep = true; AddEvent(e, k, off + 1, 2, va, vb);
      }
      if (!rep && prop)
        for (int b = 0; b < 8; b++)
          if (((ch >> b) & 1) != 0) AddEvent(e, k, b + 1, 1, (e.data[k] >> b) & 1, (d[k] >> b) & 1);
    }
  }
  readonly Dictionary<int, Entry> table = new Dictionary<int, Entry>();
  readonly Dictionary<int, string> ids = new Dictionary<int, string>();
  readonly Dictionary<int, string> dms = new Dictionary<int, string>();
  // Llantas (PGN 65268): una trama por posicion, se guardan por SA + posicion
  readonly Dictionary<int, string> tires = new Dictionary<int, string>();
  readonly Dictionary<int, DateTime> tiresAt = new Dictionary<int, DateTime>();
  public string TiresJson() {
    StringBuilder sb = new StringBuilder("[");
    lock (table) {
      bool first = true;
      foreach (KeyValuePair<int, string> kv in tires) {
        if ((DateTime.Now - tiresAt[kv.Key]).TotalSeconds > 30) continue;
        if (!first) sb.Append(','); first = false;
        sb.Append("{\"sa\":").Append(kv.Key >> 8).Append(",\"data\":\"").Append(kv.Value).Append("\"}");
      }
    }
    return sb.Append(']').ToString();
  }
  readonly List<string> acks = new List<string>();
  int ackId;
  public string DmJson() {
    StringBuilder sb = new StringBuilder("[");
    lock (table) {
      bool first = true;
      foreach (KeyValuePair<int, string> kv in dms) {
        if (!first) sb.Append(','); first = false;
        sb.Append("{\"pgn\":").Append(kv.Key >> 8).Append(",\"sa\":").Append(kv.Key & 0xFF).Append(",\"data\":\"").Append(kv.Value).Append("\"}");
      }
    }
    return sb.Append(']').ToString();
  }
  public string AcksJson(int since) {
    StringBuilder sb = new StringBuilder("[");
    lock (table) {
      bool first = true;
      foreach (string a in acks) {
        int id = int.Parse(a.Substring(6, a.IndexOf(',') - 6));
        if (id <= since) continue;
        if (!first) sb.Append(','); first = false; sb.Append(a);
      }
    }
    return sb.Append(']').ToString();
  }
  public void ClearDm() { lock (table) { dms.Clear(); } }
  // Request a una direccion concreta (da) o a todos (255)
  public string RequestTo(int pgn, int da) {
    if (client < 0) return "sin conexion";
    byte[] m = new byte[] { 0x00, 0xEA, 0x00, 6, 249, (byte)da, (byte)(pgn & 0xFF), (byte)((pgn >> 8) & 0xFF), (byte)((pgn >> 16) & 0x03) };
    short r = fSend(client, m, (short)m.Length, 0, 0);
    return r == 0 ? null : ErrorText(r);
  }
  static string Esc(string s) { return s.Replace("\\", "\\\\").Replace("\"", "\\\""); }
  public string IdsJson() {
    StringBuilder sb = new StringBuilder("[");
    lock (table) {
      bool first = true;
      foreach (KeyValuePair<int, string> kv in ids) {
        if (!first) sb.Append(','); first = false;
        sb.Append("{\"pgn\":").Append(kv.Key >> 8).Append(",\"sa\":").Append(kv.Key & 0xFF)
          .Append(",\"text\":\"").Append(Esc(kv.Value)).Append("\"}");
      }
    }
    return sb.Append(']').ToString();
  }
  // Pide un PGN a todos los modulos (Request PGN 59904) desde la direccion 249
  public string Request(int pgn) {
    return Send(59904, new byte[] { (byte)(pgn & 0xFF), (byte)((pgn >> 8) & 0xFF), (byte)((pgn >> 16) & 0x03) });
  }
  public long Frames;
  public string Protocol = "";

  T Fn<T>(IntPtr lib, string name) where T : class {
    IntPtr p = GetProcAddress(lib, name);
    if (p == IntPtr.Zero) throw new Exception("Function " + name + " is missing in the driver.");
    return Marshal.GetDelegateForFunctionPointer(p, typeof(T)) as T;
  }

  public void Load(string dll) {
    IntPtr lib = LoadLibrary(dll);
    if (lib == IntPtr.Zero) throw new Exception("Could not load " + dll + " (error " + Marshal.GetLastWin32Error() + ").");
    fConnect = Fn<ConnectD>(lib, "RP1210_ClientConnect");
    fDisconnect = Fn<DisconnectD>(lib, "RP1210_ClientDisconnect");
    fRead = Fn<ReadD>(lib, "RP1210_ReadMessage");
    fSend = Fn<SendD>(lib, "RP1210_SendMessage");
    fCmd = Fn<CmdD>(lib, "RP1210_SendCommand");
    try { fErr = Fn<ErrD>(lib, "RP1210_GetErrorMsg"); } catch { fErr = null; }
  }

  public string ErrorText(int code) {
    if (fErr == null) return "error " + code;
    StringBuilder sb = new StringBuilder(256);
    fErr((short)code, sb);
    return sb.ToString() + " (" + code + ")";
  }

  // Devuelve null si conecto, o el texto del error.
  public string Connect(short device, string protocol) {
    short r = fConnect(IntPtr.Zero, device, protocol, 8192, 16384, 0);
    if (r < 0 || r > 127) return ErrorText(r);
    client = r; Protocol = protocol;
    fCmd(3, client, new byte[0], 0);   // RP1210_Set_All_Filters_States_to_Pass
    running = true;
    reader = new Thread(ReadLoop); reader.IsBackground = true; reader.Start();
    return null;
  }

  public void Disconnect() {
    running = false;
    if (client >= 0) { try { fDisconnect(client); } catch { } client = -1; }
  }

  void ReadLoop() {
    byte[] buf = new byte[4096];
    while (running) {
      short n = fRead(client, buf, (short)buf.Length, 0);
      if (n <= 0) { Thread.Sleep(2); continue; }
      if (n < 10) continue;
      // Formato J1939 RP1210: 4 timestamp, 3 PGN (LSB primero), 1 prioridad, 1 SA, 1 DA, datos
      int pgn = buf[4] | (buf[5] << 8) | ((buf[6] & 0x03) << 16);
      int sa = buf[8];
      int full = n - 10;
      if (pgn == 65260 || pgn == 65259 || pgn == 65242 || pgn == 64965) {   // identificacion (VIN, componentes, software, ECU)
        StringBuilder t = new StringBuilder();
        for (int i = 0; i < full; i++) {
          byte c = buf[10 + i];
          if (pgn == 65242 && i == 0) { t.Append(c).Append('*'); continue; }
          t.Append(c >= 32 && c < 127 ? (char)c : '.');
        }
        lock (table) { ids[(pgn << 8) | buf[8]] = t.ToString(); }
      }
      if (pgn == 65268 && full >= 8) {                                       // llantas (TPMS)
        lock (table) { int tk = (sa << 8) | buf[10]; tires[tk] = BitConverter.ToString(buf, 10, 8).Replace('-', ' '); tiresAt[tk] = DateTime.Now; }
      }
      if (pgn == 65226 || pgn == 65227) {                                    // DM1 / DM2 completos
        lock (table) { dms[(pgn << 8) | buf[8]] = BitConverter.ToString(buf, 10, full).Replace('-', ' '); }
      }
      if (pgn == 59392 && full >= 8) {                                       // ACK / NACK
        int apgn = buf[15] | (buf[16] << 8) | (buf[17] << 16);
        if (apgn == 65228 || apgn == 65235 || apgn == 65227) {
          string[] t = { "ACK", "NACK", "DENIED", "BUSY" };
          lock (table) { ackId++; acks.Add("{\"id\":" + ackId + ",\"sa\":" + buf[8] + ",\"pgn\":" + apgn + ",\"result\":\"" + (buf[10] < 4 ? t[buf[10]] : "?") + "\"}"); }
        }
      }
      int len = Math.Min(full, 8);
      byte[] d = new byte[8];
      for (int i = 0; i < 8; i++) d[i] = i < len ? buf[10 + i] : (byte)0xFF;
      lock (table) {
        Entry e; int key = (pgn << 8) | sa;
        if (!table.TryGetValue(key, out e)) {
          e = new Entry(); e.pgn = pgn; e.sa = sa; e.first = DateTime.Now; table[key] = e;
        }
        if (watchOn && e.data != null) {
          if (DateTime.Now < quietUntil) { for (int k = 0; k < 8; k++) e.noise[k] |= (byte)(e.data[k] ^ d[k]); }
          else WatchCheck(e, d);
        }
        e.count++; e.data = d; e.last = DateTime.Now;
        Frames++;
      }
    }
  }

  public string TableJson() {
    StringBuilder sb = new StringBuilder("[");
    lock (table) {
      bool first = true;
      foreach (Entry e in table.Values) {
        if (!first) sb.Append(','); first = false;
        sb.Append("{\"pgn\":").Append(e.pgn).Append(",\"sa\":").Append(e.sa).Append(",\"n\":").Append(e.count)
          .Append(",\"data\":\"").Append(BitConverter.ToString(e.data).Replace('-', ' ')).Append("\"}");
      }
    }
    return sb.Append(']').ToString();
  }

  public void Clear() { lock (table) { table.Clear(); Frames = 0; } }

  // Mensaje de prueba desde la direccion 249 (herramienta de servicio), prioridad 6, a todos.
  public string Send(int pgn, byte[] data) {
    if (client < 0) return "sin conexion";
    byte[] m = new byte[6 + data.Length];
    m[0] = (byte)(pgn & 0xFF); m[1] = (byte)((pgn >> 8) & 0xFF); m[2] = (byte)((pgn >> 16) & 0x03);
    m[3] = 6; m[4] = 249; m[5] = 0xFF;
    Array.Copy(data, 0, m, 6, data.Length);
    short r = fSend(client, m, (short)m.Length, 0, 0);
    return r == 0 ? null : ErrorText(r);
  }
}
"@

function Leer-Ini([string]$ruta) {
  $ini = @{}; $seccion = ''
  if (-not (Test-Path $ruta)) { return $ini }
  foreach ($l in Get-Content $ruta) {
    $l = $l.Trim()
    if ($l -match '^\[(.+)\]$') { $seccion = $matches[1]; $ini[$seccion] = @{}; continue }
    if ($seccion -and $l -match '^([^=;]+)=(.*)$') { $ini[$seccion][$matches[1].Trim()] = $matches[2].Trim() }
  }
  return $ini
}

function Abrir-LizData {
  # Con el enlace funcionando, la pagina se sirve desde el propio enlace (http://localhost):
  # asi el navegador no bloquea la comunicacion entre la pagina y el enlace.
  $url = if ($script:sirviendo) { "http://localhost:$Port/" } else { $Page }
  Log "Abriendo LIZ-DATA: $url"
  if ($Browser -and $url) { try { Start-Process -FilePath $Browser -ArgumentList "--app=`"$url`" --window-size=1200,820" } catch { Log ('No se pudo abrir el navegador: ' + $_.Exception.Message) } }
}
$script:sirviendo = $false
$script:dir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------- Servidor local (si ya hay uno abierto, solo se abre la ventana) ----------
# ---- Modulo LIZ-DATA por USB (puerto serie), sin que el navegador pida elegir el puerto ----
try {
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.IO.Ports;
using System.Text;
public class LizSerial {
  SerialPort sp; readonly StringBuilder rx = new StringBuilder(); public string PortName = "";
  public string Open(string name) {
    try {
      Close();
      sp = new SerialPort(name, 115200, Parity.None, 8, StopBits.One);
      sp.DtrEnable = false; sp.RtsEnable = false; sp.NewLine = "\n"; sp.Encoding = Encoding.UTF8;
      sp.DataReceived += (o, e) => { try { string t = sp.ReadExisting(); lock (rx) { rx.Append(t); if (rx.Length > 2000000) rx.Remove(0, rx.Length - 1000000); } } catch { } };
      sp.Open(); PortName = name; return null;
    } catch (Exception ex) { sp = null; PortName = ""; return ex.Message; }
  }
  public bool IsOpen { get { try { return sp != null && sp.IsOpen; } catch { return false; } } }
  public string Read() { lock (rx) { string t = rx.ToString(); rx.Clear(); return t; } }
  public string Write(string line) { try { if (!IsOpen) return "closed"; sp.Write(line + "\n"); return null; } catch (Exception ex) { return ex.Message; } }
  public void Close() { try { if (sp != null) { sp.Close(); sp.Dispose(); } } catch { } sp = null; PortName = ""; }
}
"@
$script:ser = New-Object LizSerial
} catch { Log ('Error al preparar el puerto serie: ' + $_.Exception.Message); $script:ser = $null }
function Buscar-Modulo {
  # CP210x (Silicon Labs) y CH340: el puerto COM del modulo LIZ-DATA
  foreach ($id in @('VID_10C4&PID_EA60', 'VID_1A86&PID_7523')) {
    $d = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "DeviceID LIKE 'USB%$id%'" -ErrorAction SilentlyContinue)
    foreach ($x in $d) { if ($x.Name -match '\((COM\d+)\)') { return $Matches[1] } }
  }
  return $null
}
function Buscar-NexiqUsb {
  # Hay un NEXIQ enchufado? (por nombre en el administrador de dispositivos)
  $d = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*USB-Link*' -or $_.Manufacturer -like '*NEXIQ*' })
  return ($d.Count -gt 0)
}

# (los enlaces de versiones anteriores los cierra el instalador)
$http = $null
foreach ($intento in 1..3) {
  try {
    $http = New-Object System.Net.HttpListener
    $http.Prefixes.Add("http://localhost:$Port/")
    $http.Start(); break
  } catch {
    Log ('No se pudo abrir el puerto ' + $Port + ' (intento ' + $intento + '): ' + $_.Exception.Message)
    try { $http.Close() } catch { }
    $http = $null; Start-Sleep -Milliseconds 800
  }
}
if (-not $http) { Abrir-LizData; exit 0 }
$script:sirviendo = $true
Log "Enlace escuchando en el puerto $Port"
Abrir-LizData

# ---------- Buscar adaptadores RP1210: NEXIQ, Cat Comm Adapter 3 y cualquier otro instalado ----------
function Marca-De([string]$api, [string]$vendor, [string]$desc) {
  $t = "$api $vendor $desc"
  if ($t -match 'NULN|NXUL|NEXIQ') { return 'nexiq' }
  if ($t -match 'Caterpillar|\bCAT\b|Comm Adapter|CommAdapter') { return 'cat' }
  return 'other'
}
function Buscar-Candidatos([string]$pref = '') {
  $principal = Leer-Ini (Join-Path $env:windir 'RP121032.ini')
  $lista = @()
  foreach ($sec in @('RP1210Support', 'RP1210_Support')) {
    if ($principal[$sec] -and $principal[$sec]['APIImplementations']) {
      $lista = $principal[$sec]['APIImplementations'] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }; break
    }
  }
  $cands = @()
  foreach ($a in $lista) {
    if ($Api -and $a -ne $Api) { continue }
    $v = Leer-Ini (Join-Path $env:windir ($a + '.ini'))
    $nombre = if ($v['VendorInformation']) { $v['VendorInformation']['Name'] } else { '' }
    $devs = @()
    foreach ($k in $v.Keys) {
      if ($k -match '^DeviceInformation') {
        $id = $v[$k]['DeviceID']; $desc = $v[$k]['DeviceDescription']
        if ($id) { $devs += [pscustomobject]@{ Api = $a; Vendor = $nombre; Id = [int]$id; Desc = $desc; Brand = (Marca-De $a $nombre $desc) } }
      }
    }
    if (-not $devs) { $devs = @([pscustomobject]@{ Api = $a; Vendor = $nombre; Id = 1; Desc = 'device 1'; Brand = (Marca-De $a $nombre '') }) }
    # pref: vacio o nexiq = solo NEXIQ (como antes) · cat · any = cualquiera · o el nombre exacto del driver
    if ($pref -eq '' -or $pref -eq 'nexiq') { $devs = @($devs | Where-Object { $_.Brand -eq 'nexiq' }) }
    elseif ($pref -eq 'cat') { $devs = @($devs | Where-Object { $_.Brand -eq 'cat' }) }
    elseif ($pref -ne 'any') { $devs = @($devs | Where-Object { $_.Api -eq $pref }) }
    if (-not $devs) { continue }
    # Primero el cable USB, luego Bluetooth / Wi-Fi (USB-Link 3)
    $cands += ($devs | Sort-Object @{ Expression = { if ($_.Desc -match 'USB') { 0 } elseif ($_.Desc -match 'Bluetooth|BT') { 2 } elseif ($_.Desc -match 'Wi-?Fi|WLAN|Wireless') { 3 } else { 1 } } }, Id)
  }
  # NEXIQ primero, luego Cat, luego los demas
  $cands = @($cands | Sort-Object @{ Expression = { switch ($_.Brand) { 'nexiq' { 0 } 'cat' { 1 } default { 2 } } } })
  return ,$cands
}
function Adaptadores-Json {
  $l = Buscar-Candidatos 'any'
  $p = @($l | ForEach-Object { '{"api":' + (Json-Texto $_.Api) + ',"id":' + $_.Id + ',"brand":' + (Json-Texto $_.Brand) + ',"vendor":' + (Json-Texto $_.Vendor) + ',"desc":' + (Json-Texto $_.Desc) + ',"model":' + (Json-Texto (Modelo $_)) + '}' })
  return '[' + ($p -join ',') + ']'
}
function Modelo($c) {
  $t = "$($c.Api) $($c.Vendor) $($c.Desc)"
  if ($c.Brand -eq 'cat') { if ($t -match '3') { return 'Cat Comm Adapter 3' } else { return 'Cat Comm Adapter' } }
  if ($c.Brand -eq 'other') { return $(if ($c.Vendor) { "$($c.Vendor) ($($c.Api))" } else { "RP1210 ($($c.Api))" }) }
  if ($t -match 'Link\s*3|ULN3|NXUL3|UL3') { return 'NEXIQ USB-Link 3' }
  if ($t -match 'Link\s*2|NULN2|ULN2') { return 'NEXIQ USB-Link 2' }
  return "NEXIQ ($($c.Api))"
}

$script:rp = $null; $script:estado = ''; $script:error = ''; $script:dlls = @{}
function Conectar-Nexiq([string]$pref = '') {
  if ($script:rp) { return }
  if ($Api -and -not $pref) { $pref = $Api }
  $cands = Buscar-Candidatos $pref
  if (-not $cands -or $cands.Count -eq 0) {
    $script:error = $(if ($pref -eq 'cat') { 'No Cat Comm Adapter driver is installed on this computer (install Cat ET or the Comm Adapter 3 drivers).' } elseif ($pref -eq 'any') { 'No RP1210 adapter driver is installed on this computer.' } else { 'No NEXIQ driver is installed on this computer.' })
    return
  }
  foreach ($c in $cands) {
    if (-not $script:dlls.ContainsKey($c.Api)) {
      $x = New-Object LizRp1210
      try { $x.Load($c.Api + '.dll'); $script:dlls[$c.Api] = $x } catch { $script:dlls[$c.Api] = $null; $script:error = $_.Exception.Message }
    }
    $x = $script:dlls[$c.Api]
    if (-not $x) { continue }
    foreach ($proto in @('J1939:Baud=Auto', 'J1939:Baud=250', 'J1939:Baud=500', 'J1939')) {
      $err = $x.Connect([int16]$c.Id, $proto)
      if (-not $err) { $x.Clear(); $script:rp = $x; $script:estado = "$(Modelo $c) · $($c.Desc) · $proto"; $script:error = ''; return }
      $script:error = "$(Modelo $c) ($($c.Desc)): $err"
    }
  }
}
function Desconectar-Nexiq { if ($script:rp) { $script:rp.Disconnect(); $script:rp = $null; $script:estado = '' } }

# ---------- Actualizacion: instala solo el LIZ-DATA / lizdata-launcher mas nuevo de Descargas ----------
function Carpeta-App { if ($script:dir) { return $script:dir } else { return (Split-Path -Parent $PSCommandPath) } }
function Carpeta-Descargas {
  try { $p = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path; if ($p -and (Test-Path $p)) { return $p } } catch { }
  return (Join-Path $env:USERPROFILE 'Downloads')
}
function Buscar-Nuevo([string]$patron, [string]$marca) {
  $d = Carpeta-Descargas
  $f = @(Get-ChildItem -LiteralPath $d -Filter $patron -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  foreach ($x in $f) {
    try { $t = [IO.File]::ReadAllText($x.FullName); if ($t.Contains($marca)) { return $x } } catch { }
  }
  return $null
}
function Comparar-Archivo($nuevo, [string]$instalado) {
  # devuelve el objeto con: nombre, fecha, tamano y si es mas nuevo que el instalado
  if (-not $nuevo) { return $null }
  $mas = $true
  if (Test-Path -LiteralPath $instalado) {
    $i = Get-Item -LiteralPath $instalado
    try { $mismo = (Get-FileHash -LiteralPath $nuevo.FullName).Hash -eq (Get-FileHash -LiteralPath $instalado).Hash } catch { $mismo = $false }
    $mas = (-not $mismo) -and ($nuevo.LastWriteTime -gt $i.LastWriteTime)
  }
  return [pscustomobject]@{ File = $nuevo; Newer = $mas }
}
function Info-Actualizacion {
  $app = Carpeta-App
  $h = Comparar-Archivo (Buscar-Nuevo 'LIZ-DATA*.html' 'LIZ-DATA') (Join-Path $app 'LIZ-DATA.html')
  $l = Comparar-Archivo (Buscar-Nuevo 'lizdata-launcher*.ps1' 'LIZ-DATA launcher') (Join-Path $app 'lizdata-launcher.ps1')
  $inst = Join-Path $app 'LIZ-DATA.html'
  $fi = if (Test-Path -LiteralPath $inst) { (Get-Item -LiteralPath $inst).LastWriteTime.ToString('yyyy-MM-dd HH:mm') } else { '' }
  $j = { param($x) if (-not $x) { 'null' } else { '{"name":' + (Json-Texto $x.File.Name) + ',"date":' + (Json-Texto $x.File.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) + ',"size":' + $x.File.Length + ',"newer":' + $(if ($x.Newer) { 'true' } else { 'false' }) + '}' } }
  $bak = Test-Path -LiteralPath (Join-Path $app 'LIZ-DATA.bak.html')
  return '{"ok":true,"installed":' + (Json-Texto $fi) + ',"html":' + (& $j $h) + ',"launcher":' + (& $j $l) + ',"backup":' + $(if ($bak) { 'true' } else { 'false' }) + '}'
}
function Instalar-Uno($x, [string]$destino, [string]$respaldo) {
  if (-not $x -or -not $x.Newer) { return $false }
  if (Test-Path -LiteralPath $destino) { Copy-Item -LiteralPath $destino -Destination $respaldo -Force }
  Copy-Item -LiteralPath $x.File.FullName -Destination $destino -Force
  try { Unblock-File -LiteralPath $destino } catch { }
  (Get-Item -LiteralPath $destino).LastWriteTime = $x.File.LastWriteTime
  Log ('Actualizado ' + $destino + ' desde ' + $x.File.FullName)
  return $true
}
function Aplicar-Actualizacion {
  $app = Carpeta-App
  $h = Comparar-Archivo (Buscar-Nuevo 'LIZ-DATA*.html' 'LIZ-DATA') (Join-Path $app 'LIZ-DATA.html')
  $l = Comparar-Archivo (Buscar-Nuevo 'lizdata-launcher*.ps1' 'LIZ-DATA launcher') (Join-Path $app 'lizdata-launcher.ps1')
  $a = Instalar-Uno $h (Join-Path $app 'LIZ-DATA.html') (Join-Path $app 'LIZ-DATA.bak.html')
  $b = Instalar-Uno $l (Join-Path $app 'lizdata-launcher.ps1') (Join-Path $app 'lizdata-launcher.bak.ps1')
  return '{"ok":true,"html":' + $(if ($a) { 'true' } else { 'false' }) + ',"launcher":' + $(if ($b) { 'true' } else { 'false' }) + '}'
}
function Volver-Atras {
  $app = Carpeta-App; $bk = Join-Path $app 'LIZ-DATA.bak.html'
  if (-not (Test-Path -LiteralPath $bk)) { return '{"ok":false,"error":"No backup"}' }
  Copy-Item -LiteralPath $bk -Destination (Join-Path $app 'LIZ-DATA.html') -Force
  Log 'Se volvio a la version anterior de LIZ-DATA.html'
  return '{"ok":true}'
}

# ---------- Actualizacion por internet: lee version.json de una direccion (por ejemplo GitHub) ----------
# version.json = {"build":"...","notes":"...","files":[{"name":"LIZ-DATA.html","sha256":"..."},{"name":"lizdata-launcher.ps1","sha256":"..."}]}
# Los archivos se bajan de la misma carpeta que version.json (o de "url" si viene en cada archivo).
function Web-Cliente {
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
  $w = New-Object System.Net.WebClient
  $w.Headers.Add('User-Agent', 'LIZ-DATA'); $w.Headers.Add('Cache-Control', 'no-cache')
  $w.Encoding = [Text.Encoding]::UTF8
  return $w
}
function Hash-Archivo([string]$f) { if (Test-Path -LiteralPath $f) { return (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() } else { return '' } }
function Leer-Feed([string]$url) {
  $w = Web-Cliente
  $txt = $w.DownloadString($url + $(if ($url -match '\?') { '&' } else { '?' }) + 't=' + [DateTime]::Now.Ticks)
  $feed = $txt | ConvertFrom-Json
  $base = $url.Substring(0, $url.LastIndexOf('/') + 1)
  $app = Carpeta-App
  $lista = @()
  foreach ($f in @($feed.files)) {
    $n = [IO.Path]::GetFileName([string]$f.name)
    if ($n -ne 'LIZ-DATA.html' -and $n -ne 'lizdata-launcher.ps1') { continue }   # solo estos dos, por seguridad
    $u = if ($f.url) { [string]$f.url } else { $base + $n }
    $h = ([string]$f.sha256).ToLower()
    $lista += [pscustomobject]@{ Name = $n; Url = $u; Sha = $h; Newer = ($h -and $h -ne (Hash-Archivo (Join-Path $app $n))) }
  }
  return [pscustomobject]@{ Build = [string]$feed.build; Notes = [string]$feed.notes; Files = $lista }
}
function Online-Check([string]$url) {
  if (-not $url) { return '{"ok":false,"error":"no url"}' }
  try { $f = Leer-Feed $url } catch { return '{"ok":false,"error":' + (Json-Texto $_.Exception.Message) + '}' }
  $p = @($f.Files | ForEach-Object { '{"name":' + (Json-Texto $_.Name) + ',"newer":' + $(if ($_.Newer) { 'true' } else { 'false' }) + '}' })
  $hay = @($f.Files | Where-Object { $_.Newer }).Count -gt 0
  return '{"ok":true,"build":' + (Json-Texto $f.Build) + ',"notes":' + (Json-Texto $f.Notes) + ',"newer":' + $(if ($hay) { 'true' } else { 'false' }) + ',"files":[' + ($p -join ',') + ']}'
}
function Online-Apply([string]$url) {
  if (-not $url) { return '{"ok":false,"error":"no url"}' }
  try {
    $f = Leer-Feed $url; $app = Carpeta-App; $w = Web-Cliente; $hechos = @()
    foreach ($x in @($f.Files | Where-Object { $_.Newer })) {
      $tmp = Join-Path $env:TEMP ('liz-' + $x.Name)
      $w.DownloadFile($x.Url + '?t=' + [DateTime]::Now.Ticks, $tmp)
      if ((Hash-Archivo $tmp) -ne $x.Sha) { Remove-Item -LiteralPath $tmp -Force; throw ('Checksum mismatch for ' + $x.Name + ' (download damaged or changed)') }
      $dest = Join-Path $app $x.Name
      $bak = Join-Path $app $(if ($x.Name -like '*.html') { 'LIZ-DATA.bak.html' } else { 'lizdata-launcher.bak.ps1' })
      if (Test-Path -LiteralPath $dest) { Copy-Item -LiteralPath $dest -Destination $bak -Force }
      Move-Item -LiteralPath $tmp -Destination $dest -Force
      try { Unblock-File -LiteralPath $dest } catch { }
      Log ('Actualizado por internet: ' + $x.Name + ' (' + $f.Build + ')')
      $hechos += $x.Name
    }
    return '{"ok":true,"html":' + $(if ($hechos -contains 'LIZ-DATA.html') { 'true' } else { 'false' }) + ',"launcher":' + $(if ($hechos -contains 'lizdata-launcher.ps1') { 'true' } else { 'false' }) + '}'
  } catch { return '{"ok":false,"error":' + (Json-Texto $_.Exception.Message) + '}' }
}

function Responder($ctx, [int]$code, [string]$body) {
  $r = $ctx.Response
  $r.StatusCode = $code
  $r.ContentType = 'application/json; charset=utf-8'
  $r.Headers.Add('Access-Control-Allow-Origin', '*')
  $r.Headers.Add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  $r.Headers.Add('Access-Control-Allow-Headers', 'Content-Type')
  $r.Headers.Add('Access-Control-Allow-Private-Network', 'true')
  $bytes = [Text.Encoding]::UTF8.GetBytes($body)
  $r.ContentLength64 = $bytes.Length
  $r.OutputStream.Write($bytes, 0, $bytes.Length)
  $r.OutputStream.Close()
}
function Json-Texto([string]$s) { return '"' + ($s -replace '\\', '\\' -replace '"', '\"') + '"' }
function Estado-Json {
  $c = if ($script:rp) { 'true' } else { 'false' }
  $f = if ($script:rp) { $script:rp.Frames } else { 0 }
  $p = if ($script:rp) { $script:rp.Protocol } else { '' }
  return '{"ok":true,"connected":' + $c + ',"adapter":' + (Json-Texto $script:estado) + ',"protocol":' + (Json-Texto $p) + ',"frames":' + $f + ',"error":' + (Json-Texto $script:error) + '}'
}

# ---------- Atender a LIZ-DATA. Se cierra solo si LIZ-DATA deja de hablar 30 s ----------
$ultimo = (Get-Date).AddSeconds(120)  # tiempo para que abra la ventana
$seguir = $true
try {
  while ($seguir -and $http.IsListening) {
    $ar = $http.BeginGetContext($null, $null)
    while (-not $ar.AsyncWaitHandle.WaitOne(1000)) {
      if (((Get-Date) - $ultimo).TotalSeconds -gt 30) { $seguir = $false; break }
    }
    if (-not $seguir) { break }
    $ctx = $http.EndGetContext($ar)
    if (-not $script:primera) { $script:primera = $true; Log ('Primera conexion de LIZ-DATA: ' + $ctx.Request.Url.AbsolutePath) }
    $ultimo = Get-Date
    $ruta = $ctx.Request.Url.AbsolutePath
    try {
      if ($ctx.Request.HttpMethod -eq 'OPTIONS') { Responder $ctx 204 ''; continue }
      if ($ruta -eq '/' -or $ruta -eq '/index.html' -or $ruta -eq '/liz-data.ico') {
        $f = if ($ruta -eq '/liz-data.ico') { Join-Path $script:dir 'liz-data.ico' } else { Join-Path $script:dir 'LIZ-DATA.html' }
        $r = $ctx.Response
        if (Test-Path $f) {
          $b = [IO.File]::ReadAllBytes($f)
          $r.StatusCode = 200; $r.ContentType = $(if ($ruta -eq '/liz-data.ico') { 'image/x-icon' } else { 'text/html; charset=utf-8' })
          $r.Headers.Add('Cache-Control', 'no-cache')
          $r.ContentLength64 = $b.Length; $r.OutputStream.Write($b, 0, $b.Length)
        } else { $r.StatusCode = 404 }
        $r.OutputStream.Close(); continue
      }
      if ($ruta -eq '/ping')       { Responder $ctx 200 '{"ok":true}'; continue }
      if ($ruta -eq '/status')     { Responder $ctx 200 (Estado-Json); continue }
      if ($ruta -eq '/connect')    { Conectar-Nexiq ([string]$ctx.Request.QueryString['pref']); Responder $ctx 200 (Estado-Json); continue }
      if ($ruta -eq '/adapters')   { Responder $ctx 200 (Adaptadores-Json); continue }
      if ($ruta -eq '/update/check')    { Responder $ctx 200 (Info-Actualizacion); continue }
      if ($ruta -eq '/update/apply')    { Responder $ctx 200 (Aplicar-Actualizacion); continue }
      if ($ruta -eq '/update/rollback') { Responder $ctx 200 (Volver-Atras); continue }
      if ($ruta -eq '/update/online')   { Responder $ctx 200 (Online-Check ([string]$ctx.Request.QueryString['url'])); continue }
      if ($ruta -eq '/update/online/apply') { Responder $ctx 200 (Online-Apply ([string]$ctx.Request.QueryString['url'])); continue }
      if ($ruta -eq '/disconnect') { Desconectar-Nexiq; Responder $ctx 200 (Estado-Json); continue }
      # --- deteccion automatica y modulo LIZ-DATA por USB ---
      if ($ruta -eq '/detect') {
        $com = if ($script:ser -and $script:ser.IsOpen) { $script:ser.PortName } else { Buscar-Modulo }
        $nx = if ($script:rp) { $true } else { Buscar-NexiqUsb }
        Responder $ctx 200 ('{"module":' + $(if ($com) { Json-Texto $com } else { 'null' }) + ',"nexiq":' + $(if ($nx) { 'true' } else { 'false' }) + '}'); continue
      }
      if ($ruta -eq '/usb/open') {
        $com = Buscar-Modulo
        if (-not $com) { Responder $ctx 200 '{"ok":false,"error":"LIZ-DATA module not found"}'; continue }
        if (-not $script:ser) { Responder $ctx 200 ('{"ok":false,"port":' + (Json-Texto $com) + ',"error":"serial support not available (see launcher.log)"}'); continue }
        $e = $script:ser.Open($com)
        Log $(if ($e) { "No se pudo abrir $com : $e" } else { "Modulo LIZ-DATA abierto en $com" })
        if ($e) { Responder $ctx 200 ('{"ok":false,"port":' + (Json-Texto $com) + ',"error":' + (Json-Texto $e) + '}') } else { Responder $ctx 200 ('{"ok":true,"port":' + (Json-Texto $com) + '}') }
        continue
      }
      if ($ruta -eq '/usb/read') {
        if (-not $script:ser -or -not $script:ser.IsOpen) { Responder $ctx 410 '{"ok":false}'; continue }
        $r = $ctx.Response; $b = [Text.Encoding]::UTF8.GetBytes($script:ser.Read())
        $r.StatusCode = 200; $r.ContentType = 'text/plain; charset=utf-8'; $r.Headers.Add('Access-Control-Allow-Origin', '*'); $r.Headers.Add('Access-Control-Allow-Private-Network', 'true')
        $r.ContentLength64 = $b.Length; $r.OutputStream.Write($b, 0, $b.Length); $r.OutputStream.Close(); continue
      }
      if ($ruta -eq '/usb/write') {
        $line = (New-Object IO.StreamReader($ctx.Request.InputStream)).ReadToEnd().Trim()
        $e = if ($script:ser) { $script:ser.Write($line) } else { 'no serial' }
        if ($e) { Responder $ctx 200 ('{"ok":false,"error":' + (Json-Texto $e) + '}') } else { Responder $ctx 200 '{"ok":true}' }
        continue
      }
      if ($ruta -eq '/usb/close') { if ($script:ser) { $script:ser.Close() }; Responder $ctx 200 '{"ok":true}'; continue }
      $rp = $script:rp
      if (-not $rp) { Responder $ctx 409 '{"ok":false,"error":"NEXIQ not connected"}'; continue }
      switch ($ruta) {
        '/table'  { Responder $ctx 200 $rp.TableJson() }
        '/clear'  { $rp.Clear(); Responder $ctx 200 '{"ok":true}' }
        '/ids'    { Responder $ctx 200 $rp.IdsJson() }
        '/idreq'  {
          $err = ''
          foreach ($pg in @(65260, 65259, 65242, 64965)) { $e = $rp.Request($pg); if ($e) { $err = $e }; Start-Sleep -Milliseconds 30 }
          if ($err) { Responder $ctx 200 ('{"ok":false,"error":' + (Json-Texto $err) + '}') } else { Responder $ctx 200 '{"ok":true}' }
        }
        '/dm'     { Responder $ctx 200 $rp.DmJson() }
        '/tires'  { Responder $ctx 200 $rp.TiresJson() }
        '/acks'   {
          $since = 0; [int]::TryParse($ctx.Request.QueryString['since'], [ref]$since) | Out-Null
          Responder $ctx 200 $rp.AcksJson($since)
        }
        '/dmreq'  { $e = $rp.RequestTo(65227, 255); if ($e) { Responder $ctx 200 ('{"ok":false,"error":' + (Json-Texto $e) + '}') } else { Responder $ctx 200 '{"ok":true}' } }
        '/dmclear' {
          $da = 255
          if ($ctx.Request.QueryString['sa']) { [int]::TryParse($ctx.Request.QueryString['sa'], [ref]$da) | Out-Null }
          $e1 = $rp.RequestTo(65235, $da); Start-Sleep -Milliseconds 30; $e2 = $rp.RequestTo(65228, $da)
          $rp.ClearDm()
          if ($e1 -or $e2) { Responder $ctx 200 ('{"ok":false,"error":' + (Json-Texto "$e1 $e2") + '}') } else { Responder $ctx 200 '{"ok":true}' }
        }
        '/watch/start' { $rp.WatchStart(); Responder $ctx 200 '{"ok":true}' }
        '/watch/stop'  { $rp.WatchStop();  Responder $ctx 200 '{"ok":true}' }
        '/events' {
          $since = 0; [int]::TryParse($ctx.Request.QueryString['since'], [ref]$since) | Out-Null
          Responder $ctx 200 ('{"state":"' + $rp.WatchState() + '","events":' + $rp.EventsJson($since) + '}')
        }
        '/send'   {
          $cuerpo = (New-Object IO.StreamReader($ctx.Request.InputStream)).ReadToEnd().Trim()
          $partes = $cuerpo -split '\s+'
          if ($partes.Count -ne 9) { Responder $ctx 400 '{"ok":false,"error":"Format: pgn b1 .. b8"}'; break }
          $pgn = [int]$partes[0]
          $datos = [byte[]]($partes[1..8] | ForEach-Object { [Convert]::ToByte($_, 16) })
          $e = $rp.Send($pgn, $datos)
          if ($e) { Responder $ctx 200 ('{"ok":false,"error":' + (Json-Texto $e) + '}') } else { Responder $ctx 200 '{"ok":true}' }
        }
        default { Responder $ctx 404 '{"ok":false}' }
      }
    } catch { try { Responder $ctx 500 ('{"ok":false,"error":' + (Json-Texto $_.Exception.Message) + '}') } catch { } }
  }
} catch {
  Log ('Error en el enlace: ' + $_.Exception.Message + ' (linea ' + $_.InvocationInfo.ScriptLineNumber + ')')
} finally {
  try { $script:mutex.ReleaseMutex() } catch { }
  Log $(if ($seguir) { 'Enlace cerrado' } else { 'Enlace cerrado: LIZ-DATA dejo de comunicarse (ventana cerrada)' })
  $http.Stop(); Desconectar-Nexiq; if ($script:ser) { $script:ser.Close() }
}
