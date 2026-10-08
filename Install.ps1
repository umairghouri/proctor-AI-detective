<#
.SYNOPSIS
    Installs P-Detector for the current user. No administrator rights required.

.DESCRIPTION
    Copies the app to %LOCALAPPDATA%\Programs\PDetector, creates a Start Menu shortcut, and
    registers an uninstall entry so it appears in Settings > Apps like any normal program.

    Per-user by design: P-Detector needs no elevation to do its job, so demanding admin for
    the install would be friction for nothing.

.PARAMETER Desktop
    Also create a desktop shortcut.

.PARAMETER StartWithWindows
    Run P-Detector when the current user signs in.

.PARAMETER Machine
    Install to Program Files for all users. Requires an already-elevated session; if the
    session is not elevated this falls back to a per-user install rather than failing.

.PARAMETER Force
    Close a running P-Detector instead of refusing to overwrite it.

.EXAMPLE
    .\Install.ps1
.EXAMPLE
    .\Install.ps1 -Desktop -StartWithWindows
#>
[CmdletBinding()]
param(
    [switch] $Desktop,
    [switch] $StartWithWindows,
    [switch] $Machine,
    [switch] $Force,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$AppName   = 'P-Detector'
$ExeName   = 'PDetector.exe'
$RegKey    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PDetector'
$RunKey    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue  = 'PDetector'

function Say {
    param([string] $Text, [string] $Colour = 'Gray')
    if (-not $Quiet) { Write-Host $Text -ForegroundColor $Colour }
}

function Fail {
    param([string] $Text)
    Write-Host ''
    Write-Host "INSTALL FAILED: $Text" -ForegroundColor Red
    exit 1
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- locate payload

$Here = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Accept being run either from dist\ (next to the exe) or from the repo root (after a build).
$SourceExe = Join-Path $Here $ExeName
if (-not (Test-Path $SourceExe)) {
    $alt = Join-Path $Here 'dist\PDetector.exe'
    if (Test-Path $alt) {
        $Here = Join-Path $Here 'dist'
        $SourceExe = $alt
    }
    else {
        $alt2 = Join-Path $Here 'src\PDetector\bin\Release\net48\PDetector.exe'
        if (Test-Path $alt2) {
            $Here = Split-Path -Parent $alt2
            $SourceExe = $alt2
        }
    }
}

if (-not (Test-Path $SourceExe)) {
    Fail "Could not find $ExeName next to this script, in .\dist, or in the build output. Run .\build.ps1 first."
}

$SourceSigs = Join-Path $Here 'signatures.json'
if (-not (Test-Path $SourceSigs)) {
    Fail "signatures.json is missing from $Here. The app will not detect anything without it."
}

$version = (Get-Item $SourceExe).VersionInfo.FileVersion
if ([string]::IsNullOrWhiteSpace($version)) { $version = '1.0.0.0' }

# ---------------------------------------------------------------- choose target

$perMachine = $false
if ($Machine) {
    if (Test-Elevated) {
        $perMachine = $true
    }
    else {
        Say "-Machine needs an elevated session; this one is not elevated." 'Yellow'
        Say "Falling back to a per-user install, which works just as well." 'Yellow'
    }
}

if ($perMachine) {
    $TargetDir = Join-Path $env:ProgramFiles $AppName
    $StartMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
}
else {
    $TargetDir = Join-Path $env:LOCALAPPDATA "Programs\PDetector"
    $StartMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
}

$TargetExe = Join-Path $TargetDir $ExeName

# ---------------------------------------------------------------- running instance

$running = Get-Process -Name 'PDetector' -ErrorAction SilentlyContinue
if ($null -ne $running) {
    if ($Force) {
        Say 'Closing the running P-Detector...' 'Yellow'
        $running | Stop-Process -Force
        Start-Sleep -Milliseconds 800
    }
    else {
        Fail "P-Detector is currently running. Close it and try again, or re-run with -Force."
    }
}

# ---------------------------------------------------------------- copy

Say ''
Say "Installing $AppName $version" 'Cyan'
Say ''

if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

Copy-Item -Path $SourceExe -Destination $TargetExe -Force
Say "  app         -> $TargetExe"

# Never clobber a signature file the user has edited: back it up first.
$TargetSigs = Join-Path $TargetDir 'signatures.json'
if (Test-Path $TargetSigs) {
    $existing = Get-Content $TargetSigs -Raw
    $incoming = Get-Content $SourceSigs -Raw
    if ($existing -ne $incoming) {
        $backup = Join-Path $TargetDir ('signatures.backup.json')
        Copy-Item -Path $TargetSigs -Destination $backup -Force
        Say "  signatures  -> previous version saved as signatures.backup.json" 'Yellow'
    }
}
Copy-Item -Path $SourceSigs -Destination $TargetSigs -Force
Say "  signatures  -> $TargetSigs"

foreach ($extra in @('README.md', 'Uninstall.ps1', 'PDetector.exe.config')) {
    $src = Join-Path $Here $extra
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $TargetDir $extra) -Force
    }
}

# ---------------------------------------------------------------- shortcuts

function New-Shortcut {
    param([string] $LinkPath, [string] $Target, [string] $Description)

    $dir = Split-Path -Parent $LinkPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($LinkPath)
    $sc.TargetPath       = $Target
    $sc.WorkingDirectory = Split-Path -Parent $Target
    $sc.Description      = $Description
    $sc.Save()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
}

$startLink = Join-Path $StartMenu "$AppName.lnk"
New-Shortcut -LinkPath $startLink -Target $TargetExe -Description 'Check whether an AI meeting assistant is running on this PC'
Say "  Start Menu  -> $startLink"

if ($Desktop) {
    $desktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"
    New-Shortcut -LinkPath $desktopLink -Target $TargetExe -Description 'Check whether an AI meeting assistant is running on this PC'
    Say "  Desktop     -> $desktopLink"
}

# ---------------------------------------------------------------- run at sign-in

if ($StartWithWindows) {
    if (-not (Test-Path $RunKey)) { New-Item -Path $RunKey -Force | Out-Null }
    Set-ItemProperty -Path $RunKey -Name $RunValue -Value ('"' + $TargetExe + '"')
    Say "  sign-in     -> will start with Windows"
}
else {
    # Keep it idempotent: an install without the switch should not leave a stale Run value.
    $existingRun = Get-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
    if ($null -ne $existingRun) {
        Remove-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- Apps & features entry

$sizeKb = [int]((Get-ChildItem $TargetDir -File | Measure-Object -Property Length -Sum).Sum / 1KB)

if (-not (Test-Path $RegKey)) { New-Item -Path $RegKey -Force | Out-Null }

$uninstallScript = Join-Path $TargetDir 'Uninstall.ps1'
$uninstallCmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $uninstallScript + '"'

Set-ItemProperty -Path $RegKey -Name 'DisplayName'     -Value $AppName
Set-ItemProperty -Path $RegKey -Name 'DisplayVersion'  -Value $version
Set-ItemProperty -Path $RegKey -Name 'Publisher'       -Value 'P-Detector'
Set-ItemProperty -Path $RegKey -Name 'InstallLocation' -Value $TargetDir
Set-ItemProperty -Path $RegKey -Name 'DisplayIcon'     -Value $TargetExe
Set-ItemProperty -Path $RegKey -Name 'UninstallString' -Value $uninstallCmd
Set-ItemProperty -Path $RegKey -Name 'NoModify'        -Value 1 -Type DWord
Set-ItemProperty -Path $RegKey -Name 'NoRepair'        -Value 1 -Type DWord
Set-ItemProperty -Path $RegKey -Name 'EstimatedSize'   -Value $sizeKb -Type DWord
Say "  uninstall   -> registered in Settings > Apps"

# ---------------------------------------------------------------- done

if (-not $Quiet) {
    Write-Host ''
    Write-Host 'INSTALLED' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Location  : $TargetDir"
    Write-Host "  Launch    : Start Menu > $AppName"
    Write-Host "  Headless  : `"$TargetExe`" --json report.json"
    Write-Host "  Uninstall : Settings > Apps, or run Uninstall.ps1 in the folder above"
    Write-Host ''
    Write-Host '  First run will show a Windows SmartScreen warning because the executable is'
    Write-Host '  not code-signed. Choose More info > Run anyway.' -ForegroundColor Yellow
    Write-Host ''
}

exit 0
