[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$PurgeData,
    [switch]$NoPathUpdate,
    [string]$InstallRoot,
    [string]$BinDir,
    [string]$DataDir
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Installer = Join-Path $RepositoryRoot "tools\install_tracequarry.py"

$PythonCommand = $null
$PythonPrefix = @()
if ($env:TRACEQUARRY_PYTHON) {
    $PythonCommand = $env:TRACEQUARRY_PYTHON
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    foreach ($Version in @("-3.12", "-3.11")) {
        & py $Version -c "import sys; raise SystemExit(sys.version_info[:2] not in {(3, 11), (3, 12)})" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PythonCommand = "py"
            $PythonPrefix = @($Version)
            break
        }
    }
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python -c "import sys; raise SystemExit(sys.version_info[:2] not in {(3, 11), (3, 12)})" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $PythonCommand = "python"
    }
}

if (-not $PythonCommand) {
    throw "TraceQuarry requires Python 3.11 or 3.12. Install Python or set TRACEQUARRY_PYTHON."
}

$InstallerArgs = @($Installer, "--platform", "windows", "--source", $RepositoryRoot)
if ($Uninstall) { $InstallerArgs += "--uninstall" }
if ($PurgeData) { $InstallerArgs += "--purge-data" }
if ($InstallRoot) { $InstallerArgs += @("--install-root", $InstallRoot) }
if ($BinDir) { $InstallerArgs += @("--bin-dir", $BinDir) }
if ($DataDir) { $InstallerArgs += @("--data-dir", $DataDir) }

& $PythonCommand @PythonPrefix @InstallerArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if (-not $NoPathUpdate) {
    $ResolvedRoot = if ($InstallRoot) { $InstallRoot } else { Join-Path $env:LOCALAPPDATA "TraceQuarry" }
    $ResolvedBin = if ($BinDir) { $BinDir } else { Join-Path $ResolvedRoot "bin" }
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = @($UserPath -split ";" | Where-Object { $_ })
    if ($Uninstall -and $PathParts -contains $ResolvedBin) {
        $UpdatedPath = @($PathParts | Where-Object { $_ -ne $ResolvedBin }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
        Write-Host "Removed $ResolvedBin from the user PATH."
    } elseif (-not $Uninstall -and $PathParts -notcontains $ResolvedBin) {
        $UpdatedPath = (@($PathParts) + $ResolvedBin) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
        Write-Host "Added $ResolvedBin to the user PATH. Open a new terminal before using the commands."
    }
}
