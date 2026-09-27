<#
    PingForge v1.3 - single-file Windows ping reducer with built-in key system.
    Key store: %ProgramData%\PingForge\keys.json
    Admin console: PingForge-Admin.ps1
    v1.3: local key auth on boot, HWID binding, cached key, admin console compatible.
#>

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- relaunch elevated -------------------------------------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $cmd = "& '" + ($PSCommandPath -replace "'","''") + "'"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    Start-Process (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-EncodedCommand',$enc) -Verb RunAs
    return
}

# =============================================================================
#  SHARED STATE
# =============================================================================
$sync = [hashtable]::Synchronized(@{})
$sync.version    = '1.3.0'
$sync.rootDir    = Join-Path $env:ProgramData 'PingForge'
$sync.backupDir  = Join-Path $sync.rootDir 'backup'
$sync.logDir     = Join-Path $env:LOCALAPPDATA 'PingForge\logs'
$sync.keysFile   = Join-Path $sync.rootDir 'keys.json'
$sync.authCache  = Join-Path $env:LOCALAPPDATA 'PingForge\.authcache'
foreach ($d in @($sync.rootDir, $sync.backupDir, $sync.logDir, (Split-Path $sync.authCache))) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
$sync.logFile    = Join-Path $sync.logDir ('PingForge_{0:yyyy-MM-dd_HH-mm-ss}.log' -f (Get-Date))
$sync.log        = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$sync.busy       = $false
$sync.closing    = $false
$sync.form       = $null
$sync.metrics    = [hashtable]::Synchronized(@{ Snapshot = $null })
$sync.lastTick   = 0
$sync.graphs     = @{}
$sync.tweakBoxes = @{}
$sync.consoleLines = 0
$sync.pingTarget = '1.1.1.1'
$sync.pingGw     = ''
$sync.stateFile  = Join-Path $sync.backupDir 'state.json'
$sync.activeKey  = ''

function Write-PFLog {
    param([string]$Message, [ValidateSet('Info','Ok','Warn','Error')][string]$Level = 'Info')
    $tag = switch ($Level) { 'Ok' { ' OK ' } 'Warn' { 'WARN' } 'Error' { 'ERR ' } default { 'INFO' } }
    $line = '[{0:HH:mm:ss}] [{1}] {2}' -f (Get-Date), $tag, $Message
    try { $sync.log.Enqueue($line) } catch {}
    try { Add-Content -LiteralPath $sync.logFile -Value $line -ErrorAction SilentlyContinue } catch {}
}

# =============================================================================
#  KEY SYSTEM
# =============================================================================
function Get-PFHWID {
    $parts = @(
        $env:COMPUTERNAME
        (Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue).SerialNumber
        (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue).ProcessorId
        (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).UUID
    ) -join '|'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($parts))
    return (($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join '').Substring(0, 32)
}

function Get-PFKeys {
    if (-not (Test-Path -LiteralPath $sync.keysFile)) {
        return @{ keys = @(); version = 1 }
    }
    try {
        return (Get-Content -LiteralPath $sync.keysFile -Raw | ConvertFrom-Json)
    } catch {
        return @{ keys = @(); version = 1 }
    }
}

function Save-PFKeys($store) {
    try {
        $store | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $sync.keysFile -Encoding UTF8 -Force
        # restrict ACL so a standard user can't edit the key store
        try {
            $acl = Get-Acl $sync.keysFile
            $acl.SetAccessRuleProtection($true, $false)
            $admin = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators','FullControl','Allow')
            $system = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM','FullControl','Allow')
            $acl.AddAccessRule($admin)
            $acl.AddAccessRule($system)
            Set-Acl -Path $sync.keysFile -AclObject $acl
        } catch {}
    } catch {
        Write-PFLog "Could not save keys file: $($_.Exception.Message)" -Level Error
    }
}

function Read-PFAuthCache {
    if (-not (Test-Path -LiteralPath $sync.authCache)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $sync.authCache -Raw
        $obj = $raw | ConvertFrom-Json
        if ($obj.key -and $obj.hwid) { return $obj }
    } catch {}
    return $null
}
function Save-PFAuthCache($key, $hwid) {
    try {
        @{ key = $key; hwid = $hwid; when = (Get-Date).ToString('s') } |
            ConvertTo-Json | Set-Content -LiteralPath $sync.authCache -Encoding UTF8 -Force
    } catch {}
}
function Clear-PFAuthCache {
    Remove-Item -LiteralPath $sync.authCache -Force -ErrorAction SilentlyContinue
}

# ----------------------------------------------------------------------------
#  Prompt for key (console window, runs before WPF)
# ----------------------------------------------------------------------------
function Invoke-PFKeyPrompt {
    $host.UI.RawUI.WindowTitle = 'PingForge - License'
    Clear-Host
    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor DarkMagenta
    Write-Host '                          P I N G F O R G E' -ForegroundColor Magenta
    Write-Host '  ================================================================' -ForegroundColor DarkMagenta
    Write-Host ''
    Write-Host '  Network optimization suite - v' -NoNewline -ForegroundColor DarkGray
    Write-Host $sync.version -ForegroundColor Gray
    Write-Host ''

    $hwid = Get-PFHWID
    $cached = Read-PFAuthCache

    if ($cached) {
        Write-Host ('  cached key: {0}...{1}' -f $cached.key.Substring(0,7), $cached.key.Substring($cached.key.Length-4)) -ForegroundColor DarkGray
        Write-Host '  verifying...' -ForegroundColor DarkGray
        $result = Test-PFKey -Key $cached.key -HWID $hwid -Silent
        if ($result.ok) {
            $sync.activeKey = $cached.key
            Write-Host '  [+] key valid' -ForegroundColor Green
            Start-Sleep -Milliseconds 400
            return $true
        }
        Write-Host ('  [!] cached key invalid: ' + $result.reason) -ForegroundColor Yellow
        Clear-PFAuthCache
        Start-Sleep -Milliseconds 800
        Write-Host ''
    }

    Write-Host '  Enter your license key below.' -ForegroundColor Cyan
    Write-Host '  (Example format: PF-XXXX-XXXX-XXXX)' -ForegroundColor DarkGray
    Write-Host ''

    $attempts = 0
    while ($attempts -lt 3) {
        $attempts++
        Write-Host ('  Attempt {0}/3  > ' -f $attempts) -NoNewline -ForegroundColor Gray
        $key = (Read-Host).Trim().ToUpper()
        if (-not $key) {
            Write-Host '  No key entered.' -ForegroundColor Yellow
            continue
        }
        $result = Test-PFKey -Key $key -HWID $hwid
        if ($result.ok) {
            $sync.activeKey = $key
            Save-PFAuthCache -key $key -hwid $hwid
            Write-Host '  [+] key accepted' -ForegroundColor Green
            Start-Sleep -Milliseconds 500
            return $true
        }
        Write-Host ('  [-] ' + $result.reason) -ForegroundColor Red
        Write-Host ''
    }

    Write-Host ''
    Write-Host '  Too many failed attempts. Exiting.' -ForegroundColor Red
    Start-Sleep -Seconds 4
    return $false
}

function Test-PFKey {
    param([string]$Key, [string]$HWID, [switch]$Silent)
    $store = Get-PFKeys
    $entry = @($store.keys | Where-Object { $_.key -eq $Key }) | Select-Object -First 1
    if (-not $entry) {
        return @{ ok = $false; reason = 'key not recognized' }
    }
    if ($entry.blacklisted) {
        return @{ ok = $false; reason = 'key has been revoked' }
    }
    if ($entry.expires) {
        try {
            $exp = [datetime]::Parse($entry.expires)
            if ((Get-Date) -gt $exp) {
                return @{ ok = $false; reason = 'key expired on ' + $exp.ToString('yyyy-MM-dd') }
            }
        } catch {}
    }
    # HWID binding
    if (-not $entry.hwid) {
        # first use — bind
        $entry.hwid = $HWID
        $entry.bound_at = (Get-Date).ToString('s')
        $entry.uses = [int]($entry.uses) + 1
        $entry.last_ip = try { (Invoke-RestMethod 'https://api.ipify.org?format=json' -TimeoutSec 4).ip } catch { 'unknown' }
        $entry.last_seen = (Get-Date).ToString('s')
        Save-PFKeys $store
        return @{ ok = $true; reason = 'bound to this PC' }
    }
    if ($entry.hwid -ne $HWID) {
        return @{ ok = $false; reason = 'key is bound to a different PC' }
    }
    # valid — update last seen
    $entry.uses = [int]($entry.uses) + 1
    $entry.last_seen = (Get-Date).ToString('s')
    try { $entry.last_ip = (Invoke-RestMethod 'https://api.ipify.org?format=json' -TimeoutSec 4).ip } catch {}
    Save-PFKeys $store
    return @{ ok = $true; reason = 'valid' }
}

# =============================================================================
#  STATE SNAPSHOT HELPERS
# =============================================================================
function Save-PFState {
    param([string]$Key, $Value)
    $state = @{}
    if (Test-Path -LiteralPath $sync.stateFile) {
        try {
            $obj = Get-Content -LiteralPath $sync.stateFile -Raw | ConvertFrom-Json
            foreach ($p in $obj.PSObject.Properties) { $state[$p.Name] = $p.Value }
        } catch {}
    }
    if (-not $state.ContainsKey($Key)) {
        $state[$Key] = if ($null -eq $Value) { '' } else { [string]$Value }
    }
    try { $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $sync.stateFile -Encoding UTF8 -Force } catch {}
}
function Get-PFState {
    param([string]$Key)
    if (-not (Test-Path -LiteralPath $sync.stateFile)) { return $null }
    try {
        $obj = Get-Content -LiteralPath $sync.stateFile -Raw | ConvertFrom-Json
        $p = $obj.PSObject.Properties[$Key]
        if ($p -and $p.Value -ne '') { return $p.Value }
    } catch {}
    return $null
}
function Get-PFStateKeys {
    param([string]$Prefix = '')
    if (-not (Test-Path -LiteralPath $sync.stateFile)) { return @() }
    try {
        $obj = Get-Content -LiteralPath $sync.stateFile -Raw | ConvertFrom-Json
        return @($obj.PSObject.Properties.Name | Where-Object { $_ -like "$Prefix*" })
    } catch { return @() }
}
function Get-PFTweakState { param([string]$Id) (Test-Path -LiteralPath (Join-Path $sync.backupDir "$Id.applied")) }
function Set-PFTweakState {
    param([string]$Id, [bool]$Applied)
    $f = Join-Path $sync.backupDir "$Id.applied"
    if ($Applied) { New-Item -ItemType File -Path $f -Force | Out-Null }
    else { Remove-Item -Path $f -Force -ErrorAction SilentlyContinue }
}

# =============================================================================
#  TWEAK FUNCTIONS
# =============================================================================
function Invoke-Tweak_Nagle {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
        $k = $_.PSChildName
        Save-PFState -Key "Nagle_${k}_ack"   -Value (Get-ItemProperty $_.PSPath -Name TcpAckFrequency -ErrorAction SilentlyContinue).TcpAckFrequency
        Save-PFState -Key "Nagle_${k}_delay" -Value (Get-ItemProperty $_.PSPath -Name TcpNoDelay -ErrorAction SilentlyContinue).TcpNoDelay
        Set-ItemProperty $_.PSPath -Name TcpAckFrequency -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty $_.PSPath -Name TcpNoDelay      -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
    }
}
function Undo-Tweak_Nagle {
    foreach ($k in @(Get-PFStateKeys -Prefix 'Nagle_')) {
        $val = Get-PFState -Key $k
        if ($k -like '*_ack') { $guid = $k -replace '^Nagle_','' -replace '_ack$','';   $prop = 'TcpAckFrequency' }
        else                  { $guid = $k -replace '^Nagle_','' -replace '_delay$',''; $prop = 'TcpNoDelay' }
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
        if (-not (Test-Path $path)) { continue }
        if ($val) { Set-ItemProperty $path -Name $prop -Type DWord -Value ([int]$val) -Force -ErrorAction SilentlyContinue }
        else      { Remove-ItemProperty $path -Name $prop -Force -ErrorAction SilentlyContinue }
    }
}
function Invoke-Tweak_NetworkThrottle {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    Save-PFState -Key 'NThrottle' -Value (Get-ItemProperty $p -Name NetworkThrottlingIndex -ErrorAction SilentlyContinue).NetworkThrottlingIndex
    Set-ItemProperty $p -Name NetworkThrottlingIndex -Type DWord -Value 0xFFFFFFFF -Force
}
function Undo-Tweak_NetworkThrottle {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    $v = Get-PFState -Key 'NThrottle'; if (-not $v) { $v = 10 }
    Set-ItemProperty $p -Name NetworkThrottlingIndex -Type DWord -Value ([int]$v) -Force -ErrorAction SilentlyContinue
}
function Invoke-Tweak_TcpAutotune { netsh int tcp set global autotuninglevel=normal | Out-Null }
function Undo-Tweak_TcpAutotune   { netsh int tcp set global autotuninglevel=normal | Out-Null }
function Invoke-Tweak_RSS { netsh int tcp set global rss=enabled | Out-Null }
function Undo-Tweak_RSS   { netsh int tcp set global rss=default | Out-Null }
function Invoke-Tweak_RSC { netsh int tcp set global rsc=disabled | Out-Null }
function Undo-Tweak_RSC   { netsh int tcp set global rsc=default | Out-Null }
function Invoke-Tweak_ECN { netsh int tcp set global ecncapability=disabled | Out-Null }
function Undo-Tweak_ECN   { netsh int tcp set global ecncapability=default | Out-Null }
function Invoke-Tweak_Timestamps { netsh int tcp set global timestamps=disabled | Out-Null }
function Undo-Tweak_Timestamps   { netsh int tcp set global timestamps=default | Out-Null }
function Invoke-Tweak_Heuristics { netsh int tcp set heuristics disabled | Out-Null }
function Undo-Tweak_Heuristics   { netsh int tcp set heuristics default | Out-Null }
function Invoke-Tweak_CTCP { netsh int tcp set supplemental template=Internet congestionprovider=ctcp | Out-Null }
function Undo-Tweak_CTCP   { netsh int tcp set supplemental template=Internet congestionprovider=default | Out-Null }
function Invoke-Tweak_NicPower {
    $names = @()
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        $n = $_.Name; $names += $n
        try { Disable-NetAdapterPowerManagement -Name $n -ErrorAction Stop } catch {}
        try {
            $null = Get-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*EEE' -ErrorAction Stop
            Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*EEE' -RegistryValue 0 -ErrorAction Stop
        } catch {}
    }
    Save-PFState -Key 'NicAdapters' -Value ($names -join '|')
}
function Undo-Tweak_NicPower {
    $saved = Get-PFState -Key 'NicAdapters'
    $names = if ($saved) { $saved -split '\|' } else { @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        if (-not $n) { continue }
        try { Enable-NetAdapterPowerManagement -Name $n -ErrorAction Stop } catch {}
        try { Reset-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*EEE' -ErrorAction Stop } catch {}
    }
}
function Invoke-Tweak_DNSCloudflare {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object @{E={[int]$_.InterfaceMetric + [int]$_.RouteMetric}} | Select-Object -First 1
    if (-not $route) { throw 'No default route' }
    $idx = [int]$route.ifIndex
    $prev = @((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
    Save-PFState -Key 'DnsPrev' -Value ($prev -join ',')
    Save-PFState -Key 'DnsIdx'  -Value $idx
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses @('1.1.1.1','1.0.0.1') -ErrorAction Stop
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}
function Undo-Tweak_DNSCloudflare {
    $idxRaw = Get-PFState -Key 'DnsIdx'
    if (-not $idxRaw) { return }
    $idx = [int]$idxRaw
    $prev = Get-PFState -Key 'DnsPrev'
    if ($prev) { Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ($prev -split ',') -ErrorAction SilentlyContinue }
    else { Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses -ErrorAction SilentlyContinue }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}
function Invoke-Tweak_DNSGoogle {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object @{E={[int]$_.InterfaceMetric + [int]$_.RouteMetric}} | Select-Object -First 1
    if (-not $route) { throw 'No default route' }
    $idx = [int]$route.ifIndex
    $prev = @((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
    Save-PFState -Key 'DnsPrev' -Value ($prev -join ',')
    Save-PFState -Key 'DnsIdx'  -Value $idx
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses @('8.8.8.8','8.8.4.4') -ErrorAction Stop
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}
function Undo-Tweak_DNSGoogle { Undo-Tweak_DNSCloudflare }
function Invoke-Tweak_FlushDns { ipconfig /flushdns | Out-Null; Clear-DnsClientCache -ErrorAction SilentlyContinue }
function Invoke-Tweak_HighPerfPower {
    $active = (powercfg /getactivescheme | Out-String)
    if ($active -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
        Save-PFState -Key 'PrevScheme' -Value $Matches[1]
    }
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
}
function Undo-Tweak_HighPerfPower {
    $prev = Get-PFState -Key 'PrevScheme'
    if (-not $prev) { $prev = 'SCHEME_BALANCED' }
    powercfg /setactive $prev | Out-Null
}

$TWEAKS = [ordered]@{
    'Nagle'           = @{ Name = "Disable Nagle's Algorithm";              Desc = "Per-interface TcpNoDelay and TcpAckFrequency. Helps apps that use TCP."; ApplyFn = 'Invoke-Tweak_Nagle';           UndoFn = 'Undo-Tweak_Nagle' }
    'NetworkThrottle' = @{ Name = "Disable Network Throttling";             Desc = "Removes the 10-packet/ms multimedia throttle during audio or video playback."; ApplyFn = 'Invoke-Tweak_NetworkThrottle'; UndoFn = 'Undo-Tweak_NetworkThrottle' }
    'TcpAutotune'     = @{ Name = "TCP Auto-Tuning (Normal)";               Desc = "Restores the Windows default for receive window scaling."; ApplyFn = 'Invoke-Tweak_TcpAutotune';     UndoFn = 'Undo-Tweak_TcpAutotune' }
    'RSS'             = @{ Name = "Receive-Side Scaling (RSS) on";          Desc = "Spreads inbound packet processing across CPU cores."; ApplyFn = 'Invoke-Tweak_RSS';             UndoFn = 'Undo-Tweak_RSS' }
    'RSC'             = @{ Name = "Receive Segment Coalescing (RSC) off";   Desc = "RSC batches packets for CPU savings at the cost of a few ms of latency."; ApplyFn = 'Invoke-Tweak_RSC';             UndoFn = 'Undo-Tweak_RSC' }
    'ECN'             = @{ Name = "ECN off";                                Desc = "Disables Explicit Congestion Notification, unstable on some ISPs."; ApplyFn = 'Invoke-Tweak_ECN';             UndoFn = 'Undo-Tweak_ECN' }
    'Timestamps'      = @{ Name = "TCP Timestamps off";                     Desc = "Removes 12 bytes per segment of optional header."; ApplyFn = 'Invoke-Tweak_Timestamps';      UndoFn = 'Undo-Tweak_Timestamps' }
    'Heuristics'      = @{ Name = "TCP Heuristics off";                     Desc = "Stops the stack from throttling window scaling on suspected lossy links."; ApplyFn = 'Invoke-Tweak_Heuristics';      UndoFn = 'Undo-Tweak_Heuristics' }
    'CTCP'            = @{ Name = "CTCP congestion provider";               Desc = "Compound TCP, better for high bandwidth-delay links."; ApplyFn = 'Invoke-Tweak_CTCP';            UndoFn = 'Undo-Tweak_CTCP' }
    'NicPower'        = @{ Name = "NIC power saving off";                   Desc = "Stops Windows putting the active adapter to sleep; disables EEE."; ApplyFn = 'Invoke-Tweak_NicPower';        UndoFn = 'Undo-Tweak_NicPower' }
    'DNSCloudflare'   = @{ Name = "DNS: Cloudflare (1.1.1.1)";              Desc = "Sets Cloudflare as resolver on the active adapter."; ApplyFn = 'Invoke-Tweak_DNSCloudflare';   UndoFn = 'Undo-Tweak_DNSCloudflare' }
    'DNSGoogle'       = @{ Name = "DNS: Google (8.8.8.8)";                  Desc = "Sets Google Public DNS on the active adapter."; ApplyFn = 'Invoke-Tweak_DNSGoogle';       UndoFn = 'Undo-Tweak_DNSGoogle' }
    'FlushDns'        = @{ Name = "Flush DNS cache (one-shot)";             Desc = "Clears the resolver cache."; ApplyFn = 'Invoke-Tweak_FlushDns';        UndoFn = $null }
    'HighPerfPower'   = @{ Name = "High Performance power plan";            Desc = "Prevents CPU downclocking between packets."; ApplyFn = 'Invoke-Tweak_HighPerfPower';   UndoFn = 'Undo-Tweak_HighPerfPower' }
}

function Invoke-PFTweak {
    param([string]$Id, [bool]$Apply)
    $t = $TWEAKS[$Id]
    if (-not $t) { Write-PFLog "Unknown tweak $Id" -Level Error; return $false }
    try {
        if ($Apply) {
            if (Get-PFTweakState -Id $Id) { Write-PFLog "$($t.Name): already applied"; return $true }
            $fn = Get-Command $t.ApplyFn -ErrorAction Stop
            & $fn
            Set-PFTweakState -Id $Id -Applied $true
            Write-PFLog "$($t.Name): applied" -Level Ok
        } else {
            if (-not (Get-PFTweakState -Id $Id)) { Write-PFLog "$($t.Name): not applied by this tool" -Level Warn; return $true }
            if ($t.UndoFn) { $fn = Get-Command $t.UndoFn -ErrorAction Stop; & $fn }
            Set-PFTweakState -Id $Id -Applied $false
            Write-PFLog "$($t.Name): reverted" -Level Ok
        }
        return $true
    } catch {
        Write-PFLog "$($t.Name) failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# =============================================================================
#  SYSTEM INFO
# =============================================================================
function Get-PFSysInfo {
    $i = @{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $i.OSName = [string]$os.Caption
        $i.Build  = [int]$os.BuildNumber
        $i.RamGB  = [math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
    } catch { $i.OSName = 'Windows'; $i.Build = 0; $i.RamGB = 0 }
    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $i.CPU     = ([string]$cpu.Name).Trim()
        $i.Cores   = [int]$cpu.NumberOfCores
        $i.Threads = [int]$cpu.NumberOfLogicalProcessors
    } catch { $i.CPU = 'unknown CPU'; $i.Cores = 0; $i.Threads = 0 }
    try { $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1; $i.GPU = ([string]$gpu.Name).Trim() }
    catch { $i.GPU = 'unknown GPU' }
    $i.Gateway = ''; $i.Adapter = ''; $i.IsWiFi = $false; $i.LinkSpeed = ''
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object @{E={[int]$_.InterfaceMetric + [int]$_.RouteMetric}} | Select-Object -First 1
        if ($route) {
            $i.Gateway = [string]$route.NextHop
            $nic = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue
            if ($nic) {
                $i.Adapter   = [string]$nic.Name
                $i.LinkSpeed = [string]$nic.LinkSpeed
                $i.IsWiFi    = ($nic.PhysicalMediaType -eq 'Native 802.11')
            }
        }
    } catch {}
    return [pscustomobject]$i
}

# =============================================================================
#  NATIVE
# =============================================================================
if (-not ('PF.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace PF {
  public static class Native {
    [StructLayout(LayoutKind.Sequential)] public struct FILETIME { public uint Low; public uint High; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetSystemTimes(out FILETIME idle, out FILETIME kernel, out FILETIME user);
    [StructLayout(LayoutKind.Sequential)]
    public class MEMORYSTATUSEX {
      public uint dwLength = 64; public uint dwMemoryLoad;
      public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GlobalMemoryStatusEx([In,Out] MEMORYSTATUSEX lpBuffer);
    static ulong ToU64(FILETIME ft) { return ((ulong)ft.High << 32) | ft.Low; }
    public class CpuTimes { public ulong Idle, Kernel, User; public bool Ok; }
    public static CpuTimes GetCpuTimes() {
      FILETIME i,k,u; CpuTimes t = new CpuTimes();
      t.Ok = GetSystemTimes(out i, out k, out u);
      if (t.Ok) { t.Idle = ToU64(i); t.Kernel = ToU64(k); t.User = ToU64(u); }
      return t;
    }
    public class MemInfo { public ulong TotalPhys, AvailPhys; public uint Load; public bool Ok; }
    public static MemInfo GetMem() {
      MEMORYSTATUSEX m = new MEMORYSTATUSEX(); MemInfo r = new MemInfo();
      r.Ok = GlobalMemoryStatusEx(m);
      if (r.Ok) { r.TotalPhys = m.ullTotalPhys; r.AvailPhys = m.ullAvailPhys; r.Load = m.dwMemoryLoad; }
      return r;
    }
    [DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int sz);
  }
}
'@ -ErrorAction SilentlyContinue
}

# =============================================================================
#  MONITOR
# =============================================================================
function Start-PFMonitor {
    $script = @'
$ErrorActionPreference = 'Continue'
$prevCpu = [PF.Native]::GetCpuTimes()
$prevNet = @{}; $prevNetTime = [DateTime]::UtcNow
$pingInet = New-Object System.Net.NetworkInformation.Ping
$pingGw   = New-Object System.Net.NetworkInformation.Ping
$inetTask = $null; $inetMs = $null; $inetStatus = 'n/a'
$gwTask   = $null; $gwMs   = $null; $gwStatus   = 'n/a'
$tick = 0
while (-not $sync.closing) {
    $tick++
    try {
        $cpu = $null
        $ct = [PF.Native]::GetCpuTimes()
        if ($ct.Ok -and $prevCpu -and $prevCpu.Ok) {
            $di = [double]($ct.Idle - $prevCpu.Idle)
            $dt = [double](($ct.Kernel + $ct.User) - ($prevCpu.Kernel + $prevCpu.User))
            if ($dt -gt 0) { $cpu = [math]::Round(100.0 * (1.0 - $di / $dt), 1) }
        }
        $prevCpu = $ct
        $mem = [PF.Native]::GetMem()
        $ramPct = $null; $ramUsed = 0; $ramTot = 0
        if ($mem.Ok -and $mem.TotalPhys -gt 0) {
            $ramTot = [int64]$mem.TotalPhys
            $ramUsed = $ramTot - [int64]$mem.AvailPhys
            $ramPct = [math]::Round(100.0 * $ramUsed / $ramTot, 1)
        }
        $netRx = 0.0; $netTx = 0.0
        $now = [DateTime]::UtcNow
        $dt2 = ($now - $prevNetTime).TotalSeconds
        foreach ($n in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($n.OperationalStatus -ne 'Up') { continue }
            if ($n.Description -match 'Virtual|VMware|Hyper-V|Loopback|Tunnel|Bluetooth') { continue }
            try {
                $st = $n.GetIPStatistics()
                $key = $n.Id
                if ($prevNet.ContainsKey($key) -and $dt2 -gt 0) {
                    $netRx += [math]::Max(0, ($st.BytesReceived - $prevNet[$key].Rx) / $dt2)
                    $netTx += [math]::Max(0, ($st.BytesSent - $prevNet[$key].Tx) / $dt2)
                }
                $prevNet[$key] = @{ Rx = $st.BytesReceived; Tx = $st.BytesSent }
            } catch {}
        }
        $prevNetTime = $now
        if ($inetTask -and $inetTask.IsCompleted) {
            try {
                if (-not $inetTask.IsFaulted) {
                    $r = $inetTask.Result
                    $inetStatus = [string]$r.Status
                    $inetMs = if ($r.Status -eq 'Success') { [int]$r.RoundtripTime } else { $null }
                } else { $inetStatus = 'error'; $inetMs = $null }
            } catch {}
            $inetTask = $null
        }
        if (-not $inetTask -and $sync.pingTarget) { try { $inetTask = $pingInet.SendPingAsync($sync.pingTarget, 1000) } catch { $inetTask = $null } }
        if ($sync.pingGw) {
            if ($gwTask -and $gwTask.IsCompleted) {
                try {
                    if (-not $gwTask.IsFaulted) {
                        $r = $gwTask.Result
                        $gwStatus = [string]$r.Status
                        $gwMs = if ($r.Status -eq 'Success') { [int]$r.RoundtripTime } else { $null }
                    } else { $gwStatus = 'error'; $gwMs = $null }
                } catch {}
                $gwTask = $null
            }
            if (-not $gwTask) { try { $gwTask = $pingGw.SendPingAsync($sync.pingGw, 800) } catch { $gwTask = $null } }
        }
        $sync.metrics.Snapshot = [pscustomobject]@{
            Tick = $tick; CpuPercent = $cpu; MemPercent = $ramPct
            MemUsedGB = [math]::Round($ramUsed / 1GB, 1); MemTotalGB = [math]::Round($ramTot / 1GB, 1)
            NetRxBps = $netRx; NetTxBps = $netTx
            InetMs = $inetMs; InetStatus = $inetStatus
            GatewayMs = $gwMs; GatewayStatus = $gwStatus
        }
    } catch { }
    Start-Sleep -Milliseconds 1000
}
'@
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync', $sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript($script)
    $handle = $ps.BeginInvoke()
    $sync.monitor = @{ PowerShell = $ps; Runspace = $rs; Handle = $handle }
}
function Stop-PFMonitor {
    $sync.closing = $true
    if (-not $sync.monitor) { return }
    try {
        if (-not $sync.monitor.Handle.AsyncWaitHandle.WaitOne(3000)) { $sync.monitor.PowerShell.Stop() }
        try { $null = $sync.monitor.PowerShell.EndInvoke($sync.monitor.Handle) } catch {}
        $sync.monitor.PowerShell.Dispose(); $sync.monitor.Runspace.Close(); $sync.monitor.Runspace.Dispose()
    } catch {}
}

# =============================================================================
#  REGION + DNS TESTS
# =============================================================================
$global:PF_Regions = @(
    @{ Name = 'NA-East';     Host = 'ping-nae.ds.on.epicgames.com';  Loc = 'Ohio / Virginia' },
    @{ Name = 'NA-Central';  Host = 'ping-nac.ds.on.epicgames.com';  Loc = 'Dallas' },
    @{ Name = 'NA-West';     Host = 'ping-naw.ds.on.epicgames.com';  Loc = 'Oregon / N. California' },
    @{ Name = 'Europe';      Host = 'ping-eu.ds.on.epicgames.com';   Loc = 'Paris / Frankfurt / London' },
    @{ Name = 'Oceania';     Host = 'ping-oce.ds.on.epicgames.com';  Loc = 'Sydney' },
    @{ Name = 'Brazil';      Host = 'ping-br.ds.on.epicgames.com';   Loc = 'Sao Paulo' },
    @{ Name = 'Asia';        Host = 'ping-asia.ds.on.epicgames.com'; Loc = 'Tokyo' },
    @{ Name = 'Middle East'; Host = 'ping-me.ds.on.epicgames.com';   Loc = 'Bahrain' },
    @{ Name = 'Cloudflare';  Host = '1.1.1.1';                       Loc = 'nearest anycast' }
)
function Invoke-RegionPing {
    param([int]$Rounds = 6)
    $lines = @()
    $lines += ('Pinging {0} hosts x {1} rounds...' -f $global:PF_Regions.Count, $Rounds)
    $lines += ''
    $lines += '{0,-12} {1,8} {2,6} {3,6} {4,8} {5,6}  {6}' -f 'REGION','AVG','MIN','MAX','JITTER','LOSS','LOCATION'
    $results = @()
    foreach ($r in $global:PF_Regions) {
        $samples = @(); $sent = 0
        for ($i = 0; $i -lt $Rounds; $i++) {
            $sent++
            try {
                $p = New-Object System.Net.NetworkInformation.Ping
                $task = $p.SendPingAsync($r.Host, 1200)
                if ($task.Wait(1500) -and -not $task.IsFaulted -and $task.Result.Status -eq 'Success') {
                    $samples += [int]$task.Result.RoundtripTime
                }
                $p.Dispose()
            } catch {}
            Start-Sleep -Milliseconds 150
        }
        $avg = $null; $min = $null; $max = $null; $jit = $null
        if ($samples.Count -gt 0) {
            $m = $samples | Measure-Object -Average -Minimum -Maximum
            $avg = [int]$m.Average; $min = [int]$m.Minimum; $max = [int]$m.Maximum
            if ($samples.Count -gt 1) {
                $d = 0.0
                for ($k = 1; $k -lt $samples.Count; $k++) { $d += [math]::Abs($samples[$k] - $samples[$k-1]) }
                $jit = [math]::Round($d / ($samples.Count - 1), 1)
            } else { $jit = 0 }
        }
        $loss = if ($sent -gt 0) { [int](100 * ($sent - $samples.Count) / $sent) } else { 100 }
        $results += [pscustomobject]@{ Name = $r.Name; Avg = $avg; Min = $min; Max = $max; Jitter = $jit; Loss = $loss; Loc = $r.Loc }
        $avgStr = if ($null -eq $avg) { 'timeout' } else { "$avg ms" }
        $minStr = if ($null -eq $min) { '-' } else { $min }
        $maxStr = if ($null -eq $max) { '-' } else { $max }
        $jitStr = if ($null -eq $jit) { '-' } else { $jit }
        $lines += '{0,-12} {1,8} {2,6} {3,6} {4,8} {5,5}%  {6}' -f $r.Name, $avgStr, $minStr, $maxStr, $jitStr, $loss, $r.Loc
    }
    $sorted = @($results | Where-Object { $null -ne $_.Avg } | Sort-Object Avg)
    if ($sorted.Count -gt 0) {
        $lines += ''
        $lines += 'Best: ' + $sorted[0].Name + ' at ' + $sorted[0].Avg + ' ms (' + $sorted[0].Loc + ')'
    }
    return ($lines -join "`r`n")
}
function Invoke-DnsBench {
    $servers = @(
        @{ Name='Cloudflare';Ip='1.1.1.1'},@{ Name='Cloudflare-2';Ip='1.0.0.1'},
        @{ Name='Google';Ip='8.8.8.8'},@{ Name='Google-2';Ip='8.8.4.4'},
        @{ Name='Quad9';Ip='9.9.9.9'},@{ Name='OpenDNS';Ip='208.67.222.222'},
        @{ Name='AdGuard';Ip='94.140.14.14'},@{ Name='ControlD';Ip='76.76.2.0'}
    )
    $lines = @('Sending 5 uncached queries to each resolver...','')
    $lines += '{0,-16} {1,-18} {2,10} {3,8} {4,8}' -f 'RESOLVER','ADDRESS','MEDIAN','BEST','OK'
    $rows = @()
    foreach ($s in $servers) {
        $times = @(); $ok = 0
        for ($i = 0; $i -lt 5; $i++) {
            $t0 = Get-Date
            try {
                $udp = New-Object System.Net.Sockets.UdpClient
                $udp.Client.ReceiveTimeout = 1500
                $udp.Connect($s.Ip, 53)
                $q = [byte[]]@(0xAB,0xCD,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x03,0x77,0x77,0x77,0x06,0x67,0x6F,0x6F,0x67,0x6C,0x65,0x03,0x63,0x6F,0x6D,0x00,
                               0x00,0x01,0x00,0x01)
                [void]$udp.Send($q, $q.Length)
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                [void]$udp.Receive([ref]$ep)
                $udp.Close()
                $times += [int]((Get-Date) - $t0).TotalMilliseconds; $ok++
            } catch { $times += $null }
        }
        $valid = @($times | Where-Object { $_ -ne $null })
        $med = $null; $best = $null
        if ($valid.Count -gt 0) {
            $st = @($valid | Sort-Object)
            $med  = $st[[int][math]::Floor($st.Count / 2)]
            $best = $st[0]
        }
        $rows += [pscustomobject]@{ Name=$s.Name; Med=$med }
        $medStr  = if ($null -eq $med)  { 'timeout' } else { "$med ms" }
        $bestStr = if ($null -eq $best) { '-' }       else { "$best ms" }
        $lines += '{0,-16} {1,-18} {2,10} {3,8} {4,8}' -f $s.Name, $s.Ip, $medStr, $bestStr, "$ok/5"
    }
    $ranked = @($rows | Where-Object { $null -ne $_.Med } | Sort-Object Med)
    if ($ranked.Count -gt 0) { $lines += ''; $lines += 'Fastest: ' + $ranked[0].Name + ' at ' + $ranked[0].Med + ' ms median' }
    return ($lines -join "`r`n")
}

# =============================================================================
#  XAML
# =============================================================================
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PingForge" Width="1240" Height="800" MinWidth="960" MinHeight="620"
        WindowStartupLocation="CenterScreen" Background="#1E1E1E" Foreground="#D4D4D4"
        FontFamily="Cascadia Mono, Consolas, Courier New" FontSize="12.5"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg0" Color="#1E1E1E"/><SolidColorBrush x:Key="Bg1" Color="#252526"/>
    <SolidColorBrush x:Key="Bg2" Color="#2D2D30"/><SolidColorBrush x:Key="Bg3" Color="#3E3E42"/>
    <SolidColorBrush x:Key="Border" Color="#3E3E42"/><SolidColorBrush x:Key="Fg" Color="#D4D4D4"/>
    <SolidColorBrush x:Key="FgDim" Color="#858585"/><SolidColorBrush x:Key="Accent" Color="#007ACC"/>
    <SolidColorBrush x:Key="Live" Color="#E8A33D"/><SolidColorBrush x:Key="Red" Color="#F14C4C"/>

    <Style TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource Bg2}"/><Setter Property="Foreground" Value="{DynamicResource Fg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,6"/><Setter Property="Margin" Value="0,0,8,0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="3" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True">
            <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Bg3}"/>
            <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
          </Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{DynamicResource FgDim}"/><Setter Property="Padding" Value="16,9"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TabItem">
        <Border x:Name="Bd" Background="Transparent" BorderThickness="0,0,0,2" BorderBrush="Transparent"
                Padding="{TemplateBinding Padding}" Cursor="Hand">
          <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter Property="Foreground" Value="{DynamicResource Fg}"/></Trigger>
          <Trigger Property="IsSelected" Value="True">
            <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
            <Setter Property="Foreground" Value="{DynamicResource Fg}"/>
          </Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{DynamicResource Fg}"/><Setter Property="Margin" Value="0,6,0,0"/>
      <Setter Property="Cursor" Value="Hand"/><Setter Property="FontSize" Value="12.5"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource Bg0}"/><Setter Property="Foreground" Value="{DynamicResource Fg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="Padding" Value="6,4"/>
      <Setter Property="FontFamily" Value="Cascadia Mono, Consolas, Courier New"/>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="{DynamicResource Bg1}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1" Padding="14,8">
      <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
        <TextBlock Text="PINGFORGE" FontSize="14" FontWeight="Bold" Foreground="{DynamicResource Fg}" VerticalAlignment="Center"/>
        <TextBlock Text="CPU" Foreground="{DynamicResource FgDim}" FontSize="11" Margin="26,0,5,0" VerticalAlignment="Center"/>
        <TextBlock Name="HudCpu" Text="--" Foreground="{DynamicResource Live}" FontSize="12" MinWidth="48" VerticalAlignment="Center"/>
        <TextBlock Text="RAM" Foreground="{DynamicResource FgDim}" FontSize="11" Margin="18,0,5,0" VerticalAlignment="Center"/>
        <TextBlock Name="HudRam" Text="--" Foreground="{DynamicResource Live}" FontSize="12" MinWidth="120" VerticalAlignment="Center"/>
        <TextBlock Text="NET" Foreground="{DynamicResource FgDim}" FontSize="11" Margin="18,0,5,0" VerticalAlignment="Center"/>
        <TextBlock Name="HudNet" Text="--" Foreground="{DynamicResource Live}" FontSize="12" MinWidth="150" VerticalAlignment="Center"/>
        <TextBlock Text="PING" Foreground="{DynamicResource FgDim}" FontSize="11" Margin="18,0,5,0" VerticalAlignment="Center"/>
        <TextBlock Name="HudPing" Text="--" Foreground="{DynamicResource Live}" FontSize="12" MinWidth="70" VerticalAlignment="Center"/>
        <TextBlock Text="GW" Foreground="{DynamicResource FgDim}" FontSize="11" Margin="18,0,5,0" VerticalAlignment="Center"/>
        <TextBlock Name="HudGw" Text="--" Foreground="{DynamicResource Live}" FontSize="12" MinWidth="70" VerticalAlignment="Center"/>
      </StackPanel>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="#0E639C" Height="24">
      <DockPanel>
        <TextBlock Name="KeyText" DockPanel.Dock="Right" Text="" Foreground="White" VerticalAlignment="Center" Margin="10,0" FontSize="11"/>
        <TextBlock Name="VersionText" DockPanel.Dock="Right" Text="v1.3" Foreground="White" VerticalAlignment="Center" Margin="10,0" FontSize="11"/>
        <TextBlock Name="StatusText" Text="ready" Foreground="White" VerticalAlignment="Center" Margin="10,0" FontSize="11"/>
      </DockPanel>
    </Border>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="340" MinWidth="260"/><ColumnDefinition Width="4"/><ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.Column="0" Background="{DynamicResource Bg1}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,1,0">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="12">
            <Border Background="{DynamicResource Bg0}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4" Padding="12" Margin="0,0,0,8">
              <StackPanel>
                <TextBlock Text="CONNECTION" Foreground="{DynamicResource FgDim}" FontSize="11"/>
                <TextBlock Name="ConnAdapter" Text="detecting..." Foreground="{DynamicResource Fg}" FontSize="12.5" Margin="0,6,0,0" TextWrapping="Wrap"/>
                <TextBlock Name="ConnDetail" Text="" Foreground="{DynamicResource FgDim}" FontSize="11" Margin="0,4,0,0" TextWrapping="Wrap"/>
                <TextBlock Name="ConnWarn" Text="" Foreground="{DynamicResource Red}" FontSize="11" Margin="0,4,0,0" TextWrapping="Wrap"/>
              </StackPanel>
            </Border>
            <Border Background="{DynamicResource Bg0}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4" Padding="12" Margin="0,0,0,8">
              <StackPanel>
                <TextBlock Text="PING TARGET" Foreground="{DynamicResource FgDim}" FontSize="11"/>
                <ComboBox Name="TargetCombo" Margin="0,6,0,0"/>
                <TextBlock Name="PingHistory" Text="waiting for first sample..." Foreground="{DynamicResource Fg}" FontSize="11" Margin="0,8,0,0" TextWrapping="Wrap"/>
              </StackPanel>
            </Border>
            <Border Background="{DynamicResource Bg1}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,0,0,8">
              <StackPanel>
                <TextBlock Text="PING (live)" Foreground="{DynamicResource FgDim}" FontSize="11"/>
                <Canvas Name="PingGraph" Height="70" Margin="0,6,0,0" ClipToBounds="True" Background="{DynamicResource Bg0}"/>
              </StackPanel>
            </Border>
            <Border Background="{DynamicResource Bg1}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,0,0,8">
              <StackPanel>
                <TextBlock Text="NETWORK (live)" Foreground="{DynamicResource FgDim}" FontSize="11"/>
                <Canvas Name="NetGraph" Height="60" Margin="0,6,0,0" ClipToBounds="True" Background="{DynamicResource Bg0}"/>
              </StackPanel>
            </Border>
            <Border Background="{DynamicResource Bg0}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4" Padding="12">
              <StackPanel>
                <TextBlock Text="QUICK ACTIONS" Foreground="{DynamicResource FgDim}" FontSize="11"/>
                <Button Name="BtnPingRegions" Content="Ping Fortnite regions" Margin="0,8,0,4" HorizontalAlignment="Stretch"/>
                <Button Name="BtnBenchmarkDns" Content="Benchmark DNS resolvers" Margin="0,0,0,4" HorizontalAlignment="Stretch"/>
                <Button Name="BtnApplyRecommended" Content="Apply recommended tweaks" Margin="0,0,0,4" HorizontalAlignment="Stretch" Background="{DynamicResource Accent}" BorderBrush="{DynamicResource Accent}" Foreground="White"/>
                <Button Name="BtnUndoAll" Content="Undo everything" Margin="0,0,0,0" HorizontalAlignment="Stretch"/>
              </StackPanel>
            </Border>
          </StackPanel>
        </ScrollViewer>
      </Border>
      <GridSplitter Grid.Column="1" HorizontalAlignment="Stretch" Background="{DynamicResource Border}"/>
      <TabControl Grid.Column="2" Background="{DynamicResource Bg0}" BorderThickness="0" Padding="0" Name="Tabs">
        <TabItem Header="TWEAKS">
          <DockPanel>
            <Border DockPanel.Dock="Top" Background="{DynamicResource Bg1}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1" Padding="12,10">
              <StackPanel Orientation="Horizontal">
                <Button Name="BtnSelectRecommended" Content="Select recommended"/>
                <Button Name="BtnClearAll" Content="Clear"/>
                <Button Name="BtnApplySelected" Content="Apply selected" Background="{DynamicResource Accent}" BorderBrush="{DynamicResource Accent}" Foreground="White"/>
                <Button Name="BtnUndoSelected" Content="Undo selected"/>
              </StackPanel>
            </Border>
            <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Name="TweaksPanel" Margin="14,10,14,20"/></ScrollViewer>
          </DockPanel>
        </TabItem>
        <TabItem Header="REGIONS">
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="14,12,14,20">
              <TextBlock Text="Fortnite datacenter ping" FontSize="13" FontWeight="Bold" Foreground="{DynamicResource Fg}"/>
              <TextBlock Text="Pings each Epic datacenter host 6 times. Pick the region with the lowest average and jitter." Foreground="{DynamicResource FgDim}" FontSize="11" Margin="0,6,0,10" TextWrapping="Wrap"/>
              <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                <Button Name="BtnRunRegions" Content="Run region ping test" Background="{DynamicResource Accent}" BorderBrush="{DynamicResource Accent}" Foreground="White"/>
                <Button Name="BtnTracert" Content="Traceroute best region"/>
              </StackPanel>
              <TextBox Name="RegionBox" Text="not run yet" IsReadOnly="True" Height="300" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
            </StackPanel>
          </ScrollViewer>
        </TabItem>
        <TabItem Header="DNS">
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="14,12,14,20">
              <TextBlock Text="DNS resolver benchmark" FontSize="13" FontW... (16 KB left)
