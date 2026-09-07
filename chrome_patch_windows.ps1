<#
.SYNOPSIS
    Force-installs a patched Google Chrome on a Windows endpoint.

.DESCRIPTION
    Bypasses Software Management entirely: installs the Chrome enterprise MSI
    directly, then optionally applies the policy that forces users to relaunch.
    Intended for the case where the third-party patch pipeline is not delivering
    and a CVE needs closing now.

    This CHANGES the endpoint. Its companion `chrome_audit_windows.ps1` is
    read-only; run that first to size the job and again afterwards to confirm.

    Safe to re-run. A machine already at or above -FixedVersion is a no-op
    unless -Force is given, so it can be scheduled across a whole group without
    reinstalling Chrome on machines that are already fine.

    Deploy in Kaseya as an agent procedure running as System, using the 64-bit
    PowerShell step where available.

.PARAMETER FixedVersion
    The Chrome build that fixes the CVE, from chromereleases.googleblog.com.
    Required. Used both to skip already-patched machines and to sanity-check
    the MSI before installing it.

.PARAMETER MsiPath
    Local path to the Chrome enterprise MSI. Stage it with a VSA writeFile step
    from Managed Files - that way the download and its hash check happen once,
    centrally, instead of on every endpoint.

.PARAMETER MsiUrl
    Optional fallback: download the MSI from here if MsiPath is absent. Get the
    URL from chromeenterprise.google/browser/download/ and pair it with
    -ExpectedSha256.

.PARAMETER ExpectedSha256
    Optional SHA256 of the MSI. Verified before installing; mismatch aborts.

.PARAMETER ClearUpdateBlockers
    Reset Google Update policy that is preventing Chrome from updating itself
    (UpdateDefault=0, per-app override, AutoUpdateCheckPeriodMinutes=0, a stale
    TargetVersionPrefix pin). Opt-in, because someone may have set these
    deliberately. Blockers are reported either way.

.PARAMETER SetRelaunchPolicy
    Apply RelaunchNotification=2, which makes Chrome force a restart after
    RelaunchPeriodMs so the new binary actually gets used.

    Opt-in on purpose: this is user-visible. Users get an escalating banner and
    then their browser restarts, with tabs restored. Without it, expect a large
    population reporting vuln_disk=0 / vuln_running=1 - patched on disk, still
    executing vulnerable code.

.PARAMETER RelaunchPeriodMs
    Grace period before the forced relaunch, in milliseconds. Default 3600000
    (1 hour), which is also the practical floor - Chrome clamps lower values.

.PARAMETER RemoveRelaunchPolicy
    Removes the relaunch policy again. For cleanup once the fleet is patched,
    if you do not want it as standing configuration.

.PARAMETER Force
    Install even when the machine already looks patched, or when the MSI's own
    version is below -FixedVersion.

.PARAMETER LogPath
    Where to write the verbose log. Defaults to chrome_patch.log beside this
    script; falls back to the working directory when the script is delivered
    inline rather than as a file, since there is then no script directory.

    Note that the log records install paths, which contain local usernames on
    machines with per-user Chrome installs. Treat a captured log as containing
    endpoint identifiers.

.PARAMETER NoLog
    Disable logging entirely.

.OUTPUTS
    One key=value line, same shape as the audit script so an existing custom
    field and View keep working:

      action=installed;before=140.0.7339.207;after=152.0.7977.83;
      vuln_disk=0;vuln_running=1;per_user=1;relaunch_policy=2;blockers=none

.NOTES
    Exit codes:  0 = patched or already compliant
                 1 = aborted before making changes (bad args, stale MSI)
                 2 = install attempted and failed
#>
[CmdletBinding()]
param(
    # Not [Mandatory]: an unattended VSA run would hang on the prompt
    [string]$FixedVersion = '',
    [string]$MsiPath = 'C:\Windows\Temp\googlechromestandaloneenterprise64.msi',
    [string]$MsiUrl = '',
    [string]$ExpectedSha256 = '',
    [switch]$ClearUpdateBlockers,
    [switch]$SetRelaunchPolicy,
    [int]$RelaunchPeriodMs = 3600000,
    [switch]$RemoveRelaunchPolicy,
    [switch]$Force,
    [string]$LogPath = '',
    [switch]$NoLog
)

$ErrorActionPreference = 'SilentlyContinue'

# Log beside the script unless told otherwise, so the artefact travels with the
# procedure instead of landing somewhere unrelated.
#
# $PSScriptRoot is empty when the script is piped into powershell.exe rather
# than invoked from a file - which is how a VSA "Execute PowerShell Command"
# step delivers an inline script - so fall back through the other ways of
# asking, ending at the working directory.
if ($NoLog) {
    $LogPath = ''
} elseif (-not $LogPath) {
    $logDir = $PSScriptRoot
    if (-not $logDir -and $PSCommandPath) { $logDir = Split-Path -Parent $PSCommandPath }
    if (-not $logDir) { $logDir = (Get-Location).Path }
    $LogPath = Join-Path $logDir 'chrome_patch.log'
}

# --- Logging ----------------------------------------------------------------
# Everything verbose goes to the log file. stdout stays exactly one key=value
# line, because that is what Kaseya captures into a custom field - printing
# anything else there would corrupt the field and any View built on it.

$script:LogFile = $null

function Initialize-Log {
    <# Best-effort. If the log cannot be opened the script still runs, since
       failing to patch because of a logging problem would be worse. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        # Rotate, so a procedure scheduled fleet-wide cannot grow this forever
        if ((Test-Path $Path) -and ((Get-Item $Path).Length -gt 1MB)) {
            Move-Item -Path $Path -Destination "$Path.old" -Force
        }
        $script:LogFile = $Path
    } catch {
        $script:LogFile = $null
    }
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    if (-not $script:LogFile) { return }
    try {
        $stamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        Add-Content -Path $script:LogFile -Value "$stamp [$Level] $Message" -ErrorAction Stop
    } catch { }
}

function Write-Result {
    <# The single line Kaseya captures, on every exit path.

       The log location is appended here rather than at the end, so that an
       abort - the case you most want to investigate - also tells you where the
       explanation is. #>
    param([string]$Text, [int]$Code = 0)
    Write-Log "RESULT $Text"
    Write-Log "=== finished, exit $Code ==="
    if ($script:LogFile) {
        Write-Output "$Text;log=$script:LogFile"
    } else {
        Write-Output "$Text;log=unavailable"
    }
    exit $Code
}

Initialize-Log -Path $LogPath
Write-Log "=== chrome_patch_windows.ps1 starting ==="
# [Environment] rather than the env vars, which can be absent depending on how
# the agent spawns the shell - and an unattributed log entry is a poor artefact
Write-Log ("host=$([Environment]::MachineName) runas=$([Environment]::UserName) " +
           "ps=$($PSVersionTable.PSVersion) is64bit=$([Environment]::Is64BitProcess)")
Write-Log ("params: FixedVersion='$FixedVersion' MsiPath='$MsiPath' " +
           "MsiUrl=$(if($MsiUrl){'set'}else{'(none)'}) " +
           "ExpectedSha256=$(if($ExpectedSha256){'set'}else{'(none)'}) " +
           "ClearUpdateBlockers=$ClearUpdateBlockers SetRelaunchPolicy=$SetRelaunchPolicy " +
           "RemoveRelaunchPolicy=$RemoveRelaunchPolicy Force=$Force")

# Stock Windows 7 ships PowerShell 2.0, which lacks [pscustomobject],
# Invoke-WebRequest and the simplified Where-Object syntax used below. Those
# machines are capped at Chrome 109 by the OS and are handled as a separate
# track, so report the version plainly rather than half-running.
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Result "action=aborted;reason=requires PowerShell 3.0 or later (found $($PSVersionTable.PSVersion))" 1
}

if ([string]::IsNullOrWhiteSpace($FixedVersion)) {
    Write-Result 'action=aborted;reason=FixedVersion not supplied' 1
}

# Re-launch in 64-bit PowerShell when started from a 32-bit host, so registry
# writes land in the real hive and MainModule works against 64-bit Chrome.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $ps64 = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if ((Test-Path $ps64) -and $PSCommandPath) {
        Write-Log "re-launching in 64-bit PowerShell: $ps64"
        # Pass the already-resolved log path so parent and child write to the
        # same file. Only when non-empty: an empty string argument can be
        # dropped in native argument passing, leaving -LogPath dangling and
        # failing the child's parameter binding.
        $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
                  '-FixedVersion', $FixedVersion, '-MsiPath', $MsiPath,
                  '-RelaunchPeriodMs', $RelaunchPeriodMs)
        if ($LogPath) { $argv += @('-LogPath', $LogPath) }
        if ($MsiUrl)               { $argv += @('-MsiUrl', $MsiUrl) }
        if ($ExpectedSha256)       { $argv += @('-ExpectedSha256', $ExpectedSha256) }
        if ($ClearUpdateBlockers)  { $argv += '-ClearUpdateBlockers' }
        if ($SetRelaunchPolicy)    { $argv += '-SetRelaunchPolicy' }
        if ($RemoveRelaunchPolicy) { $argv += '-RemoveRelaunchPolicy' }
        if ($Force)                { $argv += '-Force' }
        if ($NoLog)                { $argv += '-NoLog' }
        & $ps64 @argv
        exit $LASTEXITCODE
    }
}

# --- Helpers (duplicated from the audit script; VSA procedures are standalone
#     files and cannot dot-source a shared module) ------------------------------

function ConvertTo-Ver {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    try { return [version](($Raw -split '\s+')[0]) } catch { return $null }
}

function Get-Hklm64 {
    param([string]$Path, [string]$Name)
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.OpenSubKey($Path)
        if (-not $key) { return $null }
        return $key.GetValue($Name)
    } catch { return $null }
}

function Set-Hklm64 {
    <# Writes a DWORD to HKLM in the explicit 64-bit view.

       HKLM\SOFTWARE\Policies is on Windows' shared (non-redirected) list, so a
       32-bit host would most likely write to the right place anyway - but
       being explicit removes the doubt, and a policy silently landing in
       WOW6432Node is the kind of failure where everything reports success and
       Chrome never reads the setting. #>
    param([string]$Path, [string]$Name, [int]$Value)
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.CreateSubKey($Path)
        if (-not $key) { return $false }
        $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.Close(); $base.Close()
        return $true
    } catch { return $false }
}

function Remove-Hklm64Value {
    <# Deletes a value from HKLM in the explicit 64-bit view. #>
    param([string]$Path, [string]$Name)
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.OpenSubKey($Path, $true)
        if (-not $key) { return }
        $key.DeleteValue($Name, $false)
        $key.Close(); $base.Close()
    } catch { }
}

function Get-ServiceStartMode {
    <# Start mode of a service, or $null when it does not exist.

       Get-Service only exposes StartType from PowerShell 5.0 (.NET 4.6.1)
       onward, so on 3.0 and 4.0 it silently reads as empty and a disabled
       updater goes unreported. WMI's StartMode is available everywhere. #>
    param([string]$Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { return $null }

    if ($service.PSObject.Properties['StartType']) {
        return [string]$service.StartType
    }
    $wmi = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($wmi) { return [string]$wmi.StartMode }
    return 'Unknown'
}

function Get-Sha256 {
    <# SHA256 of a file. Get-FileHash is PowerShell 4.0+, so use .NET directly
       and keep the 3.0 floor. #>
    param([string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $bytes = $sha.ComputeHash($stream)
        } finally {
            $stream.Close()
        }
        return (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
    } catch { return $null }
}

function Get-ProfileRoots {
    $roots = @()
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $list = $base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
        foreach ($sid in $list.GetSubKeyNames()) {
            $path = $list.OpenSubKey($sid).GetValue('ProfileImagePath')
            if ($path -and (Test-Path $path)) { $roots += $path }
        }
    } catch { }
    return $roots | Select-Object -Unique
}

function Get-ChromeInstalls {
    $paths = @(
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe')
    ) | ForEach-Object { [pscustomobject]@{ Path = $_; PerUser = $false } }

    foreach ($root in Get-ProfileRoots) {
        $p = Join-Path $root 'AppData\Local\Google\Chrome\Application\chrome.exe'
        $paths += [pscustomobject]@{ Path = $p; PerUser = $true }
    }

    $seen = @{}
    foreach ($c in $paths) {
        if (-not (Test-Path $c.Path)) { continue }
        $lower = $c.Path.ToLower()
        if ($seen.ContainsKey($lower)) { continue }
        $seen[$lower] = $true
        [pscustomobject]@{
            Path    = $c.Path
            Version = ConvertTo-Ver (Get-Item $c.Path).VersionInfo.ProductVersion
            PerUser = $c.PerUser
        }
    }
}

function Get-RunningChromeVersion {
    $versions = foreach ($proc in (Get-Process -Name 'chrome')) {
        try { ConvertTo-Ver $proc.MainModule.FileVersionInfo.ProductVersion } catch { $null }
    }
    $versions = $versions | Where-Object { $_ }
    if (-not $versions) { return $null }
    ($versions | Sort-Object)[0]
}

function Get-MsiProductVersion {
    <# ProductVersion out of an MSI, so a stale staged file is caught before it
       is installed and reported as a success. #>
    param([string]$Path)
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $view = $db.GetType().InvokeMember(
            'OpenView', 'InvokeMethod', $null, $db,
            @("SELECT Value FROM Property WHERE Property='ProductVersion'"))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if (-not $record) { return $null }
        $value = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
        return ConvertTo-Ver $value
    } catch { return $null }
}

# --- Pre-flight -------------------------------------------------------------

$fixed = ConvertTo-Ver $FixedVersion
if (-not $fixed) {
    Write-Result "action=aborted;reason=unparseable FixedVersion '$FixedVersion'" 1
}

$updateKey  = 'SOFTWARE\Policies\Google\Update'
$chromeKey  = 'SOFTWARE\Policies\Google\Chrome'
$chromeGuid = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'   # Chrome Stable app ID

$installs = Get-ChromeInstalls
$before = ($installs | Where-Object Version | Sort-Object Version | Select-Object -First 1).Version
$perUserCount = ($installs | Where-Object PerUser).Count

Write-Log "fixed version target: $fixed"
Write-Log "chrome installs found: $(@($installs).Count)"
foreach ($i in $installs) {
    Write-Log ("  install: version=$($i.Version) perUser=$($i.PerUser) path='$($i.Path)'")
}
Write-Log "oldest install (judged on this): $(if($before){$before}else{'none'})"

# Report blockers regardless of whether we are clearing them
$blockers = New-Object 'System.Collections.Generic.List[string]'
if ((Get-Hklm64 $updateKey 'UpdateDefault') -eq 0)                { $blockers.Add('UpdateDefault=0') }
if ((Get-Hklm64 $updateKey "Update$chromeGuid") -eq 0)            { $blockers.Add('ChromeUpdateOff') }
if ((Get-Hklm64 $updateKey 'AutoUpdateCheckPeriodMinutes') -eq 0) { $blockers.Add('CheckPeriod=0') }
if (Get-Hklm64 $updateKey "TargetVersionPrefix$chromeGuid")       { $blockers.Add('VersionPinned') }

$hasMachineInstall = [bool]($installs | Where-Object { -not $_.PerUser })
$gupdateStartMode = Get-ServiceStartMode -Name 'gupdate'
if (-not $gupdateStartMode) {
    if ($hasMachineInstall) { $blockers.Add('GupdateMissing') }
} elseif ($gupdateStartMode -eq 'Disabled') {
    $blockers.Add('GupdateDisabled')
}
$blockerText = if ($blockers.Count) { $blockers -join '|' } else { 'none' }
Write-Log "gupdate service start mode: $(if($gupdateStartMode){$gupdateStartMode}else{'(service absent)'})"
Write-Log "update blockers: $blockerText"

# Nothing installed: this procedure patches Chrome, it does not deploy it to
# machines that never had it.
if (-not $installs) {
    Write-Result "action=skipped;reason=chrome not installed;blockers=$blockerText" 0
}

if ($before -and $before -ge $fixed -and -not $Force) {
    $running = Get-RunningChromeVersion
    $vulnRunning = if ($running) { [int]($running -lt $fixed) } else { 0 }
    Write-Result ("action=nochange;reason=already at or above fixed;before=$before" +
                  ";vuln_disk=0;vuln_running=$vulnRunning;per_user=$perUserCount" +
                  ";blockers=$blockerText") 0
}

# --- Clear update blockers (opt-in) -----------------------------------------

if ($ClearUpdateBlockers) {
    Write-Log "ClearUpdateBlockers: applying persistent policy changes" 'CHANGE'

    # Record what is about to be destroyed. TargetVersionPrefix in particular
    # may have been set deliberately to hold a client on an older Chrome for a
    # legacy web app, and removing it is not reversible from this script.
    $pinned = Get-Hklm64 $updateKey "TargetVersionPrefix$chromeGuid"
    $prevPeriod = Get-Hklm64 $updateKey 'AutoUpdateCheckPeriodMinutes'
    $prevDefault = Get-Hklm64 $updateKey 'UpdateDefault'
    $prevApp = Get-Hklm64 $updateKey "Update$chromeGuid"
    Write-Log ("  previous values: UpdateDefault=$(if($null -ne $prevDefault){$prevDefault}else{'(unset)'})" +
               " Update{Chrome}=$(if($null -ne $prevApp){$prevApp}else{'(unset)'})" +
               " TargetVersionPrefix=$(if($pinned){$pinned}else{'(unset)'})" +
               " AutoUpdateCheckPeriodMinutes=$(if($null -ne $prevPeriod){$prevPeriod}else{'(unset)'})") 'CHANGE'
    if ($pinned) {
        Write-Log "  WARNING: removing a deliberate version pin ('$pinned'); Chrome will now update past it" 'WARN'
    }

    Write-Log "  set UpdateDefault=1" 'CHANGE'
    Set-Hklm64 -Path $updateKey -Name 'UpdateDefault' -Value 1 | Out-Null
    Write-Log "  set Update$chromeGuid=1" 'CHANGE'
    Set-Hklm64 -Path $updateKey -Name "Update$chromeGuid" -Value 1 | Out-Null
    Write-Log "  removed TargetVersionPrefix$chromeGuid" 'CHANGE'
    Remove-Hklm64Value -Path $updateKey -Name "TargetVersionPrefix$chromeGuid"
    Write-Log "  removed AutoUpdateCheckPeriodMinutes" 'CHANGE'
    Remove-Hklm64Value -Path $updateKey -Name 'AutoUpdateCheckPeriodMinutes'
    if ($gupdateStartMode -eq 'Disabled') {
        Write-Log "  gupdate was Disabled; setting to Automatic" 'CHANGE'
        Set-Service -Name 'gupdate' -StartupType Automatic
    }
    Start-Service -Name 'gupdate' -ErrorAction SilentlyContinue
} else {
    Write-Log "ClearUpdateBlockers not requested; update policy left untouched"
}

# --- Acquire the MSI --------------------------------------------------------

if (-not (Test-Path $MsiPath)) {
    if (-not $MsiUrl) {
        Write-Result ("action=aborted;reason=MSI not found at $MsiPath and no MsiUrl given" +
                      ";before=$before;blockers=$blockerText") 1
    }
    try {
        # Older PowerShell defaults to TLS 1.0, which dl.google.com refuses.
        # The Tls12 enum member only exists on .NET 4.5+, so fall back to its
        # numeric value rather than throwing on an older framework.
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        } catch {
            try { [Net.ServicePointManager]::SecurityProtocol = 3072 } catch { }
        }
        Write-Log "MSI absent at '$MsiPath'; downloading from $MsiUrl"
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing -ErrorAction Stop
        Write-Log "download complete: $((Get-Item $MsiPath).Length) bytes"
    } catch {
        Write-Log "download failed: $($_.Exception.Message)" 'ERROR'
        Write-Result ("action=aborted;reason=download failed;before=$before" +
                      ";blockers=$blockerText") 1
    }
} else {
    Write-Log "using staged MSI at '$MsiPath' ($((Get-Item $MsiPath).Length) bytes)"
}

if ($ExpectedSha256) {
    $actual = Get-Sha256 -Path $MsiPath
    if (-not $actual) {
        Write-Result ("action=aborted;reason=could not hash MSI;before=$before" +
                      ";blockers=$blockerText") 1
    }
    if ($actual -ne $ExpectedSha256.ToUpper().Replace('-', '')) {
        Write-Result ("action=aborted;reason=sha256 mismatch;before=$before" +
                      ";blockers=$blockerText") 1
    }
}

# Guard against shipping a stale MSI and reporting success. This is the failure
# mode where everything looks green and the CVE is still open.
$msiVersion = Get-MsiProductVersion -Path $MsiPath
Write-Log "MSI ProductVersion: $(if($msiVersion){$msiVersion}else{'(unreadable)'})"
if ($msiVersion -and $msiVersion -lt $fixed -and -not $Force) {
    Write-Log "aborting: staged MSI $msiVersion is older than the fix $fixed" 'ERROR'
    Write-Result ("action=aborted;reason=msi $msiVersion is below fixed $fixed" +
                  ";before=$before;blockers=$blockerText") 1
}
if (-not $msiVersion) {
    Write-Log "could not read MSI version; proceeding without that check" 'WARN'
}

# --- Install ----------------------------------------------------------------

Write-Log "running: msiexec /i `"$MsiPath`" /qn /norestart REBOOT=ReallySuppress" 'CHANGE'
$proc = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -ArgumentList @(
    '/i', "`"$MsiPath`"", '/qn', '/norestart', 'REBOOT=ReallySuppress'
)
Write-Log "msiexec exit code: $(if($null -ne $proc.ExitCode){$proc.ExitCode}else{'(process did not start)'})"
# 3010 and 1641 both mean success with a reboot pending; Chrome does not need
# one. -contains rather than -in, which is PowerShell 3.0+ only.
$installOk = @(0, 3010, 1641) -contains $proc.ExitCode

# Nudge Google Update as well: it can pick up per-user installs the MSI cannot,
# provided the relevant user's updater is running.
$nudged = $false
foreach ($gu in @((Join-Path $env:ProgramFiles 'Google\Update\GoogleUpdate.exe'),
                  (Join-Path ${env:ProgramFiles(x86)} 'Google\Update\GoogleUpdate.exe'))) {
    if (Test-Path $gu) {
        Write-Log "nudging updater: $gu /ua /installsource scheduler"
        & $gu /ua /installsource scheduler | Out-Null
        $nudged = $true
    }
}
if (-not $nudged) {
    Write-Log "no machine-wide GoogleUpdate.exe found in either Program Files location" 'WARN'
}

# --- Relaunch policy --------------------------------------------------------

if ($RemoveRelaunchPolicy) {
    Write-Log "removing RelaunchNotification policy" 'CHANGE'
    Remove-Hklm64Value -Path $chromeKey -Name 'RelaunchNotification'
    Remove-Hklm64Value -Path $chromeKey -Name 'RelaunchNotificationPeriod'
} elseif ($SetRelaunchPolicy) {
    # Chrome clamps periods below an hour, so do not bother going lower
    $period = [Math]::Max($RelaunchPeriodMs, 3600000)
    if ($period -ne $RelaunchPeriodMs) {
        Write-Log "RelaunchPeriodMs $RelaunchPeriodMs raised to Chrome's 3600000 floor" 'WARN'
    }
    Write-Log ("setting RelaunchNotification=2 period=$period - this is standing config " +
               "and will force a relaunch on every future Chrome update") 'CHANGE'
    Set-Hklm64 -Path $chromeKey -Name 'RelaunchNotification' -Value 2 | Out-Null
    Set-Hklm64 -Path $chromeKey -Name 'RelaunchNotificationPeriod' -Value $period | Out-Null
} else {
    Write-Log "SetRelaunchPolicy not requested; users will keep running the old binary until they restart Chrome"
}

# --- Report -----------------------------------------------------------------

$afterInstalls = Get-ChromeInstalls
$after = ($afterInstalls | Where-Object Version | Sort-Object Version | Select-Object -First 1).Version
$running = Get-RunningChromeVersion
$relaunchPolicy = Get-Hklm64 $chromeKey 'RelaunchNotification'

Write-Log "post-install state:"
foreach ($i in $afterInstalls) {
    Write-Log ("  install: version=$($i.Version) perUser=$($i.PerUser) path='$($i.Path)'")
}
Write-Log "  oldest on disk: $(if($after){$after}else{'none'})  (was $(if($before){$before}else{'none'}))"
Write-Log "  running binary: $(if($running){$running}else{'chrome not running'})"

$vulnDisk    = if ($after)   { [int]($after -lt $fixed) } else { '' }
$vulnRunning = if ($running) { [int]($running -lt $fixed) } else { 0 }

$action = if (-not $installOk) { 'failed' }
          elseif ($after -and $before -and $after -gt $before) { 'installed' }
          else { 'installed-noversionchange' }

$summary = "action=$action;msiexec=$($proc.ExitCode)" +
           ";before=$(if($before){$before}else{'none'});after=$(if($after){$after}else{'none'})" +
           ";vuln_disk=$vulnDisk;vuln_running=$vulnRunning" +
           ";per_user=$perUserCount" +
           ";relaunch_policy=$(if($null -ne $relaunchPolicy){$relaunchPolicy}else{'unset'})" +
           ";blockers=$blockerText"

# A machine patched on disk but still running the old binary is not yet fixed
if ($installOk -and $vulnRunning -eq 1 -and -not $SetRelaunchPolicy) {
    $summary += ';note=needs_relaunch'
    Write-Log "patched on disk but still executing the old binary - needs a relaunch" 'WARN'
}
if ($perUserCount -gt 0) {
    $summary += ';note=per_user_install_not_covered_by_msi'
    Write-Log ("$perUserCount per-user install(s) present; the machine-wide MSI does not " +
               "upgrade those and the user's shortcut may still point at one") 'WARN'
}
if (-not $installOk) {
    Write-Log "msiexec did not report success" 'ERROR'
}

Write-Result $summary $(if ($installOk) { 0 } else { 2 })
