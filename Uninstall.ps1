<#
.SYNOPSIS
    Removes Proctor AI Detective from this machine.

.DESCRIPTION
    Deletes the install folder, both shortcuts, the sign-in Run value and the Apps & features
    entry. Safe to run when the app was never installed.

.EXAMPLE
    .\Uninstall.ps1
.EXAMPLE
    .\Uninstall.ps1 -Quiet -Force
#>
[CmdletBinding()]
param(
    [switch] $Force,
    [switch] $Quiet,
    [switch] $KeepSignatures
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$AppName  = 'Proctor AI Detective'
$RegKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProctorAIDetective'
$RunKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'ProctorAIDetective'

function Say {
    param([string] $Text, [string] $Colour = 'Gray')
    if (-not $Quiet) { Write-Host $Text -ForegroundColor $Colour }
}

# ---------------------------------------------------------------- find the install

$TargetDir = $null

$reg = Get-ItemProperty -Path $RegKey -Name 'InstallLocation' -ErrorAction SilentlyContinue
if ($null -ne $reg) { $TargetDir = $reg.InstallLocation }

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $guess = Join-Path $env:LOCALAPPDATA 'Programs\ProctorAIDetective'
    if (Test-Path $guess) { $TargetDir = $guess }
}
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $guess2 = Join-Path $env:ProgramFiles $AppName
    if (Test-Path $guess2) { $TargetDir = $guess2 }
}

$anything = $false

Say ''
Say "Uninstalling $AppName" 'Cyan'
Say ''

# ---------------------------------------------------------------- stop a running instance

$running = Get-Process -Name 'ProctorAIDetective' -ErrorAction SilentlyContinue
if ($null -ne $running) {
    if ($Force) {
        Say '  closing the running instance' 'Yellow'
        $running | Stop-Process -Force
        Start-Sleep -Milliseconds 800
    }
    else {
        Write-Host ''
        Write-Host "Proctor AI Detective is running. Close it and try again, or re-run with -Force." -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------- shortcuts

$links = @(
    (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"),
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk")
)
foreach ($l in $links) {
    if (Test-Path $l) {
        Remove-Item $l -Force -ErrorAction SilentlyContinue
        Say "  removed shortcut  $l"
        $anything = $true
    }
}

# ---------------------------------------------------------------- run-at-sign-in

$run = Get-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
if ($null -ne $run) {
    Remove-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
    Say '  removed start-with-Windows entry'
    $anything = $true
}

# ---------------------------------------------------------------- files

if (-not [string]::IsNullOrWhiteSpace($TargetDir) -and (Test-Path $TargetDir)) {

    if ($KeepSignatures) {
        $sigs = Join-Path $TargetDir 'signatures.json'
        if (Test-Path $sigs) {
            $keep = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'ProctorAIDetective-signatures.json'
            Copy-Item $sigs $keep -Force
            Say "  kept signatures   $keep" 'Yellow'
        }
    }

    # This script may live inside the folder it is deleting, so copy it out and finish the
    # job from the temp copy rather than trying to delete a file that is currently executing.
    $selfPath = $MyInvocation.MyCommand.Definition
    $insideTarget = $selfPath.StartsWith($TargetDir, [StringComparison]::OrdinalIgnoreCase)

    if ($insideTarget) {
        $temp = Join-Path $env:TEMP ('ProctorAIDetective-Uninstall-' + [Guid]::NewGuid().ToString('N') + '.ps1')
        Copy-Item $selfPath $temp -Force

        $args = '-NoProfile -ExecutionPolicy Bypass -File "' + $temp + '"'
        if ($Quiet) { $args += ' -Quiet' }
        $args += ' -Force'

        Say '  relaunching from a temporary copy to delete the install folder'
        Start-Process -FilePath 'powershell.exe' -ArgumentList $args
        exit 0
    }

    Remove-Item -Recurse -Force $TargetDir -ErrorAction SilentlyContinue
    if (Test-Path $TargetDir) {
        Write-Host "  could not fully remove $TargetDir - delete it by hand." -ForegroundColor Yellow
    }
    else {
        Say "  removed folder    $TargetDir"
        $anything = $true
    }
}

# ---------------------------------------------------------------- registry

if (Test-Path $RegKey) {
    Remove-Item -Path $RegKey -Recurse -Force -ErrorAction SilentlyContinue
    Say '  removed Apps & features entry'
    $anything = $true
}

# ---------------------------------------------------------------- done

if (-not $Quiet) {
    Write-Host ''
    if ($anything) {
        Write-Host 'UNINSTALLED' -ForegroundColor Green
        Write-Host ''
        Write-Host '  Proctor AI Detective only ever read from this machine, so nothing else was changed.'
    }
    else {
        Write-Host 'Nothing to do - Proctor AI Detective does not appear to be installed.' -ForegroundColor Yellow
    }
    Write-Host ''
}

exit 0
