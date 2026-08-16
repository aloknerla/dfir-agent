[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "dfir-agent"),
    [switch]$NoPathUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    throw "-InstallRoot must not be empty."
}
if (-not [System.IO.Path]::IsPathRooted($InstallRoot)) {
    throw "-InstallRoot must be an absolute path: $InstallRoot"
}
if ($InstallRoot -match "[\p{C}]") {
    throw "-InstallRoot contains a forbidden control character."
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $projectRoot "docker-compose.yml"
$launcherSource = Join-Path $projectRoot "deploy\console\launch.ps1"

if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "docker-compose.yml is missing from the project root."
}
if (-not (Test-Path -LiteralPath $launcherSource -PathType Leaf)) {
    throw "deploy\console\launch.ps1 is missing."
}

function Assert-LocalDockerEndpoint {
    if ($env:DOCKER_CONTEXT) {
        $endpoint = (
            & docker context inspect $env:DOCKER_CONTEXT `
                --format "{{.Endpoints.docker.Host}}"
        ).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $endpoint) {
            throw "Docker context '$env:DOCKER_CONTEXT' could not be inspected."
        }
    }
    elseif ($env:DOCKER_HOST) {
        $endpoint = $env:DOCKER_HOST
    }
    else {
        $endpoint = (
            & docker context inspect --format "{{.Endpoints.docker.Host}}"
        ).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $endpoint) {
            throw "The active Docker endpoint could not be determined."
        }
    }
    if (-not $endpoint.StartsWith(
        "npipe://",
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw (
            "The active Docker endpoint is not local Docker Desktop: $endpoint. " +
            "Remote Docker contexts cannot safely mount local evidence paths."
        )
    }
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $currentPath = [System.IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $currentPath)) {
        $parent = [System.IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent) {
            break
        }
        $currentPath = $parent.FullName
    }

    while (Test-Path -LiteralPath $currentPath) {
        $item = Get-Item -LiteralPath $currentPath -Force
        if (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw (
                "$Label contains a symbolic link or junction: $($item.FullName). " +
                "Use a direct path so the evidence boundary can be verified."
            )
        }
        $parent = [System.IO.Directory]::GetParent($item.FullName)
        if ($null -eq $parent) {
            break
        }
        $currentPath = $parent.FullName
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker was not found. Install and start Docker Desktop, then run install.ps1 again."
}

Assert-LocalDockerEndpoint
& docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose is not available."
}
& docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Desktop is not running or the current user cannot access it."
}
# No --project-name: docker-compose.yml names the project, so a re-clone or a
# moved checkout reuses the one built image instead of leaving another behind.
& docker compose --project-directory $projectRoot --file $composeFile config --quiet
if ($LASTEXITCODE -ne 0) {
    throw "docker-compose.yml is invalid for the installed Docker Compose version."
}

$runtimeDirectories = @(
    (Join-Path $projectRoot "evidence"),
    (Join-Path $projectRoot "runs"),
    (Join-Path $projectRoot "config"),
    (Join-Path $projectRoot "work")
)
foreach ($directory in $runtimeDirectories) {
    Assert-NoReparsePoint $directory "Runtime directory"
}
foreach ($directory in $runtimeDirectories) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    Assert-NoReparsePoint $directory "Runtime directory"
}

if (-not $SkipBuild) {
    & docker compose --project-directory $projectRoot --file $composeFile build console
    if ($LASTEXITCODE -ne 0) {
        throw "The dfir-agent Docker image could not be built."
    }
}

$binDirectory = Join-Path $InstallRoot "bin"
New-Item -ItemType Directory -Force -Path $binDirectory | Out-Null

# Staged and renamed into place, as install.sh does: an interrupted copy must
# not leave a launcher that is half of one version and half of the next.
$stagedLauncher = Join-Path $binDirectory ".dfir-agent.ps1.new"
$stagedRootRecord = Join-Path $binDirectory ".project-root.txt.new"
Copy-Item -LiteralPath $launcherSource -Destination $stagedLauncher -Force
Set-Content -LiteralPath $stagedRootRecord -Value $projectRoot -Encoding UTF8
Move-Item -LiteralPath $stagedLauncher -Destination (Join-Path $binDirectory "dfir-agent.ps1") -Force
Move-Item -LiteralPath $stagedRootRecord -Destination (Join-Path $binDirectory "project-root.txt") -Force

$commandFile = Join-Path $binDirectory "dfir-agent.cmd"
$commandText = @'
@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0dfir-agent.ps1" %*
'@
Set-Content -LiteralPath $commandFile -Value $commandText -Encoding ASCII

if (-not $NoPathUpdate) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @($userPath -split ";" | Where-Object { $_ })
    if ($entries -notcontains $binDirectory) {
        $updatedPath = (@($binDirectory) + $entries) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
    }
}

Write-Host ""
Write-Host "dfir-agent was installed successfully." -ForegroundColor Green
Write-Host "Evidence directory: $projectRoot\evidence"
Write-Host "Runtime directory:  $projectRoot\runs"
Write-Host "Config directory:   $projectRoot\config"
Write-Host "Scratch directory:  $projectRoot\work"
Write-Host "The command remains linked to this project directory."
Write-Host "Run install.ps1 again if the project directory is moved."
Write-Host ""
Write-Host "Open a new terminal and run:"
Write-Host "  dfir-agent"
