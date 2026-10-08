<#
.SYNOPSIS
    Builds P-Detector and stages a portable distribution.

.DESCRIPTION
    Produces dist\ containing PDetector.exe, signatures.json, the installer scripts and the
    README, plus a zip of the same.

    Because the project targets .NET Framework 4.8 - which is preinstalled on every
    Windows 10 1903+ and Windows 11 machine - the output is a handful of small files with
    NO .NET runtime for the end user to install. A self-contained .NET 8 equivalent would be
    68 MB and cannot be trimmed (WinForms blocks trimming: error NETSDK1175).

.EXAMPLE
    .\build.ps1
.EXAMPLE
    .\build.ps1 -Configuration Debug -SkipClean
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string] $Configuration = 'Release',
    [switch] $SkipClean,
    [switch] $NoZip,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Root       = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = Join-Path $Root 'src\PDetector'
$Project    = Join-Path $ProjectDir 'PDetector.csproj'
$DistDir    = Join-Path $Root 'dist'

function Write-Step {
    param([string] $Text)
    if (-not $Quiet) {
        Write-Host ''
        Write-Host "==> $Text" -ForegroundColor Cyan
    }
}

function Write-Info {
    param([string] $Text)
    if (-not $Quiet) { Write-Host "    $Text" -ForegroundColor Gray }
}

function Fail {
    param([string] $Text)
    Write-Host ''
    Write-Host "BUILD FAILED: $Text" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------- preflight

Write-Step 'Checking prerequisites'

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($null -eq $dotnet) {
    Fail 'The .NET SDK is not installed or not on PATH. Install it from https://dotnet.microsoft.com/download'
}
Write-Info "dotnet: $($dotnet.Source)"

if (-not (Test-Path $Project)) {
    Fail "Project not found at $Project"
}

# ---------------------------------------------------------------- clean

if (-not $SkipClean) {
    Write-Step 'Cleaning'
    foreach ($d in @((Join-Path $ProjectDir 'bin'), (Join-Path $ProjectDir 'obj'), $DistDir)) {
        if (Test-Path $d) {
            Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
            Write-Info "removed $d"
        }
    }
}

# ---------------------------------------------------------------- build

Write-Step "Building ($Configuration)"

$buildArgs = @('build', $Project, '-c', $Configuration, '-nologo')
if ($Quiet) { $buildArgs += @('-v', 'quiet') }

& dotnet $buildArgs
if ($LASTEXITCODE -ne 0) {
    Fail "dotnet build exited with code $LASTEXITCODE"
}

$OutDir = Join-Path $ProjectDir "bin\$Configuration\net48"
$Exe    = Join-Path $OutDir 'PDetector.exe'
if (-not (Test-Path $Exe)) {
    Fail "Build reported success but $Exe does not exist."
}

# ---------------------------------------------------------------- self-test

Write-Step 'Running built-in self-test'

& $Exe --selftest | Out-Null
if ($LASTEXITCODE -ne 0) {
    # Re-run visibly so the failures are on screen, then stop.
    & $Exe --selftest
    Fail "Self-test failed (exit code $LASTEXITCODE). Not packaging a build that does not pass its own checks."
}
Write-Info 'self-test passed'

# ---------------------------------------------------------------- stage

Write-Step 'Staging dist'

if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
New-Item -ItemType Directory -Path $DistDir | Out-Null

$payload = @(
    @{ From = $Exe;                                 Name = 'PDetector.exe' },
    @{ From = (Join-Path $OutDir 'signatures.json'); Name = 'signatures.json' },
    @{ From = (Join-Path $Root 'Install.ps1');       Name = 'Install.ps1' },
    @{ From = (Join-Path $Root 'Uninstall.ps1');     Name = 'Uninstall.ps1' },
    @{ From = (Join-Path $Root 'README.md');         Name = 'README.md' }
)

foreach ($p in $payload) {
    if (Test-Path $p.From) {
        Copy-Item -Path $p.From -Destination (Join-Path $DistDir $p.Name) -Force
        Write-Info "staged $($p.Name)"
    }
    else {
        Write-Host "    WARNING: missing $($p.From)" -ForegroundColor Yellow
    }
}

# PDetector.exe.config only exists if the SDK emitted one; it is optional.
$cfg = Join-Path $OutDir 'PDetector.exe.config'
if (Test-Path $cfg) {
    Copy-Item -Path $cfg -Destination (Join-Path $DistDir 'PDetector.exe.config') -Force
    Write-Info 'staged PDetector.exe.config'
}

# ---------------------------------------------------------------- zip

$version = (Get-Item $Exe).VersionInfo.FileVersion
if ([string]::IsNullOrWhiteSpace($version)) { $version = '1.0.0.0' }

if (-not $NoZip) {
    Write-Step 'Creating zip'
    $zip = Join-Path $DistDir ("PDetector-Portable-$version.zip")
    $items = Get-ChildItem -Path $DistDir -File | ForEach-Object { $_.FullName }
    Compress-Archive -Path $items -DestinationPath $zip -Force
    Write-Info "created $(Split-Path -Leaf $zip)"
}

# ---------------------------------------------------------------- report

$exeSize = [math]::Round((Get-Item (Join-Path $DistDir 'PDetector.exe')).Length / 1KB, 1)

if (-not $Quiet) {
    Write-Host ''
    Write-Host 'BUILD OK' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Version    : $version"
    Write-Host "  Executable : $exeSize KB"
    Write-Host "  Output     : $DistDir"
    Write-Host ''
    Write-Host '  Install on this machine :  .\dist\Install.ps1'
    Write-Host '  Run without installing  :  .\dist\PDetector.exe'
    Write-Host '  Headless scan           :  .\dist\PDetector.exe --json report.json'
    Write-Host ''
    Write-Host '  Targets .NET Framework 4.8, which ships with Windows 10 1903+ and Windows 11,'
    Write-Host '  so there is no runtime for the end user to install.'
    Write-Host ''
}

exit 0
