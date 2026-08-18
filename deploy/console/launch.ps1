[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AgentArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$launcherWorkingDirectory = (Get-Location).ProviderPath

$rootFile = Join-Path $PSScriptRoot "project-root.txt"
if (-not (Test-Path -LiteralPath $rootFile)) {
    throw "The dfir-agent installation is incomplete. Run install.ps1 again."
}

$projectRoot = (Get-Content -LiteralPath $rootFile -Raw).Trim()
$composeFile = Join-Path $projectRoot "docker-compose.yml"
if (-not (Test-Path -LiteralPath $composeFile)) {
    throw "The project directory no longer contains docker-compose.yml. Run install.ps1 again."
}

# Docker's CLI prints promotional "What's next:" tips after a run, which land in
# the middle of the console's own output and read as though the forensic tool is
# suggesting them. This is the documented way off; it is set for this process
# only, so the operator's own Docker settings are left alone.
$env:DOCKER_CLI_HINTS = "false"

$privateEvidenceRoot = Join-Path `
    (Split-Path -Parent $PSScriptRoot) `
    "evidence-mount-root"
$script:EvidenceRunMountArguments = @()
$script:AuthorizedEvidencePaths = @()
$script:EvidenceSelectionKind = "directory"
$script:EvidenceSelectionSourcePath = $null

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker was not found. Install or start Docker Desktop."
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

Assert-LocalDockerEndpoint

# --rebuild belongs to the launcher and not to the console, so the token is
# taken out of the argument list here and can never reach the containerized
# CLI. The build runs through the same --project-directory and --file as the
# run at the bottom of this script, which is the only reason the image it
# produces is the image the launcher then starts. Typing "docker compose build
# console" somewhere other than the project directory names another project and
# builds an image nothing here ever runs, which costs a rebuild and leaves the
# operator looking at the old console.
$rebuildRequested = $false
if ($AgentArguments -and $AgentArguments.Count -gt 0) {
    $keptArguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in $AgentArguments) {
        if ($argument -ieq "--rebuild") {
            $rebuildRequested = $true
            continue
        }
        $keptArguments.Add($argument)
    }
    $AgentArguments = @($keptArguments.ToArray())
}

if ($rebuildRequested) {
    if ($AgentArguments -and $AgentArguments.Count -gt 0) {
        throw (
            "--rebuild rebuilds the console image and does nothing else. Run " +
            "it on its own, then start the console."
        )
    }
    Write-Host "Rebuilding the dfir-agent console image from $projectRoot."
    # PowerShell 7.3 and later turn a non-zero native exit status into a
    # terminating error while $ErrorActionPreference is Stop. A build that
    # fails has already printed why, so its status is passed on instead.
    $nativePreference = Get-Variable `
        -Name PSNativeCommandUseErrorActionPreference `
        -ErrorAction SilentlyContinue
    if ($null -ne $nativePreference) {
        $previousNativePreference = $nativePreference.Value
        Set-Variable -Name PSNativeCommandUseErrorActionPreference -Value $false
    }
    try {
        & docker compose `
            --project-directory $projectRoot `
            --file $composeFile `
            build console
        $buildStatus = $LASTEXITCODE
    }
    finally {
        if ($null -ne $nativePreference) {
            Set-Variable `
                -Name PSNativeCommandUseErrorActionPreference `
                -Value $previousNativePreference
        }
    }
    if ($buildStatus -ne 0) {
        exit $buildStatus
    }
    Write-Host "Rebuilt. Start the console with: dfir-agent"
    exit 0
}

function Clear-PrivateEvidenceRoot {
    if (-not (Test-Path -LiteralPath $privateEvidenceRoot)) {
        return
    }
    $rootItem = Get-Item -LiteralPath $privateEvidenceRoot -Force
    if (
        -not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "The private evidence mount root must be a direct directory."
    }
    foreach ($item in Get-ChildItem -LiteralPath $privateEvidenceRoot -Force) {
        if (
            $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne 0
        ) {
            throw (
                "The private evidence mount root contains an unexpected item: " +
                "$($item.FullName)."
            )
        }
        Remove-Item -LiteralPath $item.FullName -Force
    }
}

function Initialize-PrivateEvidenceRoot {
    New-Item -ItemType Directory -Force -Path $privateEvidenceRoot | Out-Null
    $rootItem = Get-Item -LiteralPath $privateEvidenceRoot -Force
    if (
        -not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "The private evidence mount root must be a direct directory."
    }
    Clear-PrivateEvidenceRoot
    return $rootItem.FullName
}

function Assert-EvidencePathIsDirect {
    param([Parameter(Mandatory = $true)][string]$Path)

    $currentPath = [System.IO.Path]::GetFullPath($Path)
    while (Test-Path -LiteralPath $currentPath) {
        $item = Get-Item -LiteralPath $currentPath -Force
        if (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw (
                "The evidence path contains a symbolic link or junction: " +
                "$($item.FullName). Use its direct path so the read-only " +
                "boundary can be verified."
            )
        }
        $parent = [System.IO.Directory]::GetParent($item.FullName)
        if ($null -eq $parent) {
            break
        }
        $currentPath = $parent.FullName
    }
}

function Get-SegmentedEvidenceSet {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$PrimaryFile)

    $name = $PrimaryFile.Name
    # Every single evidence file the launcher can mount passes through here, so
    # this is where a kind the console no longer opens has to be turned away.
    # A .plaso store is the one such kind left: mounting one would open a case
    # whose only source was then silently ignored, which reads as an empty
    # investigation rather than as an unsupported file.
    if ($name -match "\.[Pp][Ll][Aa][Ss][Oo]$") {
        throw (
            "Timeline evidence is no longer supported: $($PrimaryFile.FullName). " +
            "Open the disk image, memory image or capture it was built from."
        )
    }
    $segmentPattern = $null
    $firstSegmentName = $null
    if ($name -match "^(?<stem>.+)\.[Ee][Xx][0-9]{2}$") {
        $segmentPattern = (
            "^{0}\.[Ee][Xx][0-9]{{2}}$" -f
            [System.Text.RegularExpressions.Regex]::Escape($Matches.stem)
        )
        $firstSegmentName = "$($Matches.stem).Ex01"
    }
    elseif ($name -match "^(?<stem>.+)\.[Ee](?:[0-9]{2}|[A-Za-z]{2})$") {
        $segmentPattern = (
            "^{0}\.[Ee](?:[0-9]{{2}}|[A-Za-z]{{2}})$" -f
            [System.Text.RegularExpressions.Regex]::Escape($Matches.stem)
        )
        $firstSegmentName = "$($Matches.stem).E01"
    }
    elseif ($name -match "\.(?:7[zZ]|[zZ][iI][pP]|[rR][aA][rR]|[tT][aA][rR]|[gG][zZ]|[bB][zZ]2|[xX][zZ])\.[0-9]{3}$") {
        throw (
            "Multipart archive volumes cannot be opened as disk images: " +
            "$($PrimaryFile.FullName)"
        )
    }
    elseif ($name -match "^(?<stem>.+)\.[0-9]{3}$") {
        $segmentPattern = (
            "^{0}\.[0-9]{{3}}$" -f
            [System.Text.RegularExpressions.Regex]::Escape($Matches.stem)
        )
        $firstSegmentName = "$($Matches.stem).001"
    }

    if ($null -eq $segmentPattern) {
        return [PSCustomObject]@{
            Files = @($PrimaryFile)
            EntryFile = $PrimaryFile
        }
    }

    $segments = @(
        Get-ChildItem -LiteralPath $PrimaryFile.DirectoryName -File -Force |
            Where-Object { $_.Name -cmatch $segmentPattern } |
            Sort-Object Name
    )
    $entryFile = $segments |
        Where-Object {
            $_.Name.Equals(
                $firstSegmentName,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        } |
        Select-Object -First 1
    if ($null -eq $entryFile) {
        $expectedPath = Join-Path $PrimaryFile.DirectoryName $firstSegmentName
        throw (
            "The selected split evidence set is missing its first segment: " +
            "$expectedPath"
        )
    }
    return [PSCustomObject]@{
        Files = $segments
        EntryFile = $entryFile
    }
}

function Set-EvidenceMountSelection {
    param([Parameter(Mandatory = $true)][System.IO.FileSystemInfo]$EvidenceItem)

    if ($EvidenceItem.PSIsContainer) {
        Clear-PrivateEvidenceRoot
        $env:EVIDENCE = $EvidenceItem.FullName
        # The directory mounts at the fixed point /evidence, so its real name is
        # invisible inside the container. Forward the host directory name for the
        # console to DISPLAY; the case identity stays content-derived, so this
        # name never reaches the model.
        $env:DFA_CASE_LABEL = $EvidenceItem.Name
        $script:EvidenceRunMountArguments = @()
        $script:AuthorizedEvidencePaths = @($EvidenceItem.FullName)
        $script:EvidenceSelectionKind = "directory"
        $script:EvidenceSelectionSourcePath = $EvidenceItem.FullName
        return "/evidence"
    }

    # A single evidence file (or segment set) is mounted from its parent case
    # folder; that folder's host name is the operator-facing case name, and it
    # too is lost inside the container. Display only, never the identity.
    $env:DFA_CASE_LABEL = $EvidenceItem.Directory.Name

    $segmentSet = Get-SegmentedEvidenceSet -PrimaryFile $EvidenceItem
    return Set-EvidenceMountFileSet `
        -Files @($segmentSet.Files) `
        -EntryFile $segmentSet.EntryFile
}

function Set-EvidenceMountFileSet {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$EntryFile
    )

    $mountRoot = Initialize-PrivateEvidenceRoot
    $mountArguments = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $Files) {
        Assert-EvidencePathIsDirect -Path $file.FullName
        $placeholder = Join-Path $mountRoot $file.Name
        if (Test-Path -LiteralPath $placeholder) {
            throw "Duplicate evidence segment name: $($file.Name)"
        }
        New-Item -ItemType File -Path $placeholder | Out-Null
        $mountArguments.Add("--volume")
        $mountArguments.Add(
            "$($file.FullName):/evidence/$($file.Name):ro"
        )
    }

    $env:EVIDENCE = $mountRoot
    $script:EvidenceRunMountArguments = $mountArguments.ToArray()
    $script:AuthorizedEvidencePaths = @($Files | ForEach-Object FullName)
    $script:EvidenceSelectionKind = "files"
    $script:EvidenceSelectionSourcePath = $EntryFile.FullName
    return "/evidence/$($EntryFile.Name)"
}

function Add-EvidenceMountFileSet {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$EntryFile
    )

    $knownByName = @{}
    $knownByPath = @{}
    foreach ($knownPath in $script:AuthorizedEvidencePaths) {
        $knownItem = Get-Item -LiteralPath $knownPath -Force
        if ($knownItem.PSIsContainer) {
            continue
        }
        $knownByName[$knownItem.Name.ToLowerInvariant()] = $knownItem.FullName
        $knownByPath[$knownItem.FullName.ToLowerInvariant()] = $true
    }
    $caseRoot = $null
    if ($script:EvidenceSelectionKind -eq "directory") {
        $caseRoot = Get-Item `
            -LiteralPath $script:AuthorizedEvidencePaths[0] `
            -Force
        foreach ($caseEntry in Get-ChildItem -LiteralPath $caseRoot.FullName -Force) {
            $knownByName[$caseEntry.Name.ToLowerInvariant()] = $caseEntry.FullName
        }
    }
    $newByName = @{}
    foreach ($file in $Files) {
        Assert-EvidencePathIsDirect -Path $file.FullName
        $pathKey = $file.FullName.ToLowerInvariant()
        $nameKey = $file.Name.ToLowerInvariant()
        if (
            $null -ne $caseRoot -and
            $file.FullName.StartsWith(
                "$($caseRoot.FullName.TrimEnd('\', '/'))\",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }
        if ($knownByPath.ContainsKey($pathKey)) {
            continue
        }
        if (
            $knownByName.ContainsKey($nameKey) -or
            $newByName.ContainsKey($nameKey)
        ) {
            throw (
                "Evidence filename collision: $($file.Name). The active case " +
                "already mounts a different file with that name. Reopen one " +
                "folder containing uniquely named sources."
            )
        }
        $newByName[$nameKey] = $file.FullName
    }

    if ($script:EvidenceSelectionKind -eq "directory") {
        $authorized = [System.Collections.Generic.List[string]]::new()
        foreach ($knownPath in $script:AuthorizedEvidencePaths) {
            $authorized.Add($knownPath)
        }
        foreach ($file in $Files) {
            $pathKey = $file.FullName.ToLowerInvariant()
            if (
                $file.FullName.StartsWith(
                    "$($caseRoot.FullName.TrimEnd('\', '/'))\",
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                $knownByPath.ContainsKey($pathKey)
            ) {
                continue
            }
            $authorized.Add($file.FullName)
            $knownByPath[$pathKey] = $true
        }

        $mountArguments = [System.Collections.Generic.List[string]]::new()
        foreach ($authorizedPath in $authorized) {
            $authorizedItem = Get-Item -LiteralPath $authorizedPath -Force
            if ($authorizedItem.PSIsContainer) {
                continue
            }
            $mountArguments.Add("--volume")
            $mountArguments.Add(
                "$($authorizedItem.FullName):/evidence/$($authorizedItem.Name):ro"
            )
        }
        $env:EVIDENCE = $caseRoot.FullName
        $script:EvidenceRunMountArguments = $mountArguments.ToArray()
        $script:AuthorizedEvidencePaths = $authorized.ToArray()

        $casePrefix = "$($caseRoot.FullName.TrimEnd('\', '/'))\"
        if (
            $EntryFile.FullName.StartsWith(
                $casePrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            $relativeEntry = $EntryFile.FullName.Substring($casePrefix.Length)
            return "/evidence/$($relativeEntry.Replace('\', '/'))"
        }
        return "/evidence/$($EntryFile.Name)"
    }

    $mountRoot = Initialize-PrivateEvidenceRoot
    foreach ($knownPath in $script:AuthorizedEvidencePaths) {
        $knownItem = Get-Item -LiteralPath $knownPath -Force
        $placeholder = Join-Path $mountRoot $knownItem.Name
        New-Item -ItemType File -Path $placeholder | Out-Null
    }

    $mountArguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in $script:EvidenceRunMountArguments) {
        $mountArguments.Add($argument)
    }
    $authorized = [System.Collections.Generic.List[string]]::new()
    foreach ($knownPath in $script:AuthorizedEvidencePaths) {
        $authorized.Add($knownPath)
    }
    foreach ($file in $Files) {
        Assert-EvidencePathIsDirect -Path $file.FullName
        $pathKey = $file.FullName.ToLowerInvariant()
        $nameKey = $file.Name.ToLowerInvariant()
        if ($knownByPath.ContainsKey($pathKey)) {
            continue
        }
        $placeholder = Join-Path $mountRoot $file.Name
        New-Item -ItemType File -Path $placeholder | Out-Null
        $mountArguments.Add("--volume")
        $mountArguments.Add("$($file.FullName):/evidence/$($file.Name):ro")
        $authorized.Add($file.FullName)
        $knownByName[$nameKey] = $file.FullName
        $knownByPath[$pathKey] = $true
    }

    $env:EVIDENCE = $mountRoot
    $script:EvidenceRunMountArguments = $mountArguments.ToArray()
    $script:AuthorizedEvidencePaths = $authorized.ToArray()
    return "/evidence/$($EntryFile.Name)"
}

function ConvertTo-ContainerCasePath {
    param([Parameter(Mandatory = $true)][string]$HostPath)

    $bidiControls = @(
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069
    )
    foreach ($character in $HostPath.ToCharArray()) {
        if (
            [char]::IsControl($character) -or
            $bidiControls -contains [int]$character
        ) {
            throw "The case path contains a forbidden control character."
        }
    }

    if (-not (Test-Path -LiteralPath $HostPath)) {
        if (
            $HostPath -eq "/evidence" -or
            $HostPath.StartsWith(
                "/evidence/",
                [System.StringComparison]::Ordinal
            )
        ) {
            return $HostPath
        }
        throw "The case path does not exist: $HostPath"
    }

    $caseItem = Get-Item -LiteralPath $HostPath
    if (
        ($caseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw (
            "The case path is a symbolic link or junction: $($caseItem.FullName). " +
            "Use its direct path so the read-only boundary can be verified."
        )
    }
    return Set-EvidenceMountSelection -EvidenceItem $caseItem
}

$knownCommands = @("tui", "doctor", "ask", "models", "setup")
# "dfir-agent /case PATH" is the console's own vocabulary typed at the shell
# prompt; dropping the token lets PATH flow into the bare-case shortcut below.
if ($AgentArguments -and $AgentArguments.Count -gt 0 -and $AgentArguments[0] -ieq "/case") {
    $AgentArguments = @($AgentArguments | Select-Object -Skip 1)
}
if ($AgentArguments -and $AgentArguments.Count -gt 0) {
    $firstArgument = $AgentArguments[0]
    $isBareCaseShortcut = (
        $knownCommands -notcontains $firstArgument.ToLowerInvariant() -and
        -not $firstArgument.StartsWith("-")
    )

    if ($isBareCaseShortcut) {
        $containerPath = ConvertTo-ContainerCasePath -HostPath $firstArgument
        $remainingArguments = @($AgentArguments | Select-Object -Skip 1)
        $AgentArguments = @("tui", "--case", $containerPath) + $remainingArguments
    }
    else {
        for ($index = 0; $index -lt $AgentArguments.Count; $index++) {
            $argument = $AgentArguments[$index]
            if (
                $argument.Equals("--case", [System.StringComparison]::OrdinalIgnoreCase) -and
                ($index + 1) -lt $AgentArguments.Count
            ) {
                $containerPath = ConvertTo-ContainerCasePath `
                    -HostPath $AgentArguments[$index + 1]
                if ($null -ne $containerPath) {
                    $AgentArguments[$index + 1] = $containerPath
                }
                break
            }

            if (
                $argument.StartsWith(
                    "--case=",
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                $hostPath = $argument.Substring("--case=".Length)
                $containerPath = ConvertTo-ContainerCasePath -HostPath $hostPath
                if ($null -ne $containerPath) {
                    $AgentArguments[$index] = "--case=$containerPath"
                }
                break
            }
        }
    }
}

if (-not $env:EVIDENCE) {
    $env:EVIDENCE = Join-Path $projectRoot "evidence"
}
if (-not $env:RUNS) {
    $env:RUNS = Join-Path $projectRoot "runs"
}
if (-not $env:CONFIG) {
    $env:CONFIG = Join-Path $projectRoot "config"
}
if (-not $env:WORK) {
    $env:WORK = Join-Path $projectRoot "work"
}

if (-not (Test-Path -LiteralPath $env:EVIDENCE)) {
    throw "The evidence directory does not exist: $env:EVIDENCE"
}
$evidenceItem = Get-Item -LiteralPath $env:EVIDENCE
if (-not $evidenceItem.PSIsContainer) {
    throw "The evidence path must be a directory: $env:EVIDENCE"
}

function Test-PathsOverlap {
    param(
        [Parameter(Mandatory = $true)][string]$First,
        [Parameter(Mandatory = $true)][string]$Second
    )

    $firstPath = [System.IO.Path]::GetFullPath($First)
    $secondPath = [System.IO.Path]::GetFullPath($Second)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $separator = [System.IO.Path]::DirectorySeparatorChar

    $firstRoot = [System.IO.Path]::GetPathRoot($firstPath)
    $secondRoot = [System.IO.Path]::GetPathRoot($secondPath)
    if (-not $firstPath.Equals($firstRoot, $comparison)) {
        $firstPath = $firstPath.TrimEnd("\", "/")
    }
    if (-not $secondPath.Equals($secondRoot, $comparison)) {
        $secondPath = $secondPath.TrimEnd("\", "/")
    }

    $firstPrefix = if ($firstPath.EndsWith($separator)) {
        $firstPath
    }
    else {
        "$firstPath$separator"
    }
    $secondPrefix = if ($secondPath.EndsWith($separator)) {
        $secondPath
    }
    else {
        "$secondPath$separator"
    }

    return (
        $firstPath.Equals($secondPath, $comparison) -or
        $firstPath.StartsWith($secondPrefix, $comparison) -or
        $secondPath.StartsWith($firstPrefix, $comparison)
    )
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
                "Use a direct path so the read-only evidence boundary can be verified."
            )
        }

        $parent = [System.IO.Directory]::GetParent($item.FullName)
        if ($null -eq $parent) {
            break
        }
        $currentPath = $parent.FullName
    }
}

function Assert-SeparatePaths {
    param(
        [Parameter(Mandatory = $true)][string]$First,
        [Parameter(Mandatory = $true)][string]$FirstLabel,
        [Parameter(Mandatory = $true)][string]$Second,
        [Parameter(Mandatory = $true)][string]$SecondLabel
    )

    if (Test-PathsOverlap -First $First -Second $Second) {
        throw "$FirstLabel and $SecondLabel must not overlap or alias one another."
    }
}

function Assert-EvidenceSourcesSeparatedFromWritableRoots {
    foreach ($sourcePath in $script:AuthorizedEvidencePaths) {
        $sourceItem = Get-Item -LiteralPath $sourcePath -Force
        Assert-NoReparsePoint $sourceItem.FullName "evidence source"
        if (-not $sourceItem.PSIsContainer -and $sourceItem.LinkType -eq "HardLink") {
            throw (
                "Evidence files with multiple hard-link names cannot be mounted " +
                "safely: $($sourceItem.FullName)"
            )
        }
        Assert-SeparatePaths `
            $sourceItem.FullName "evidence source" $env:RUNS "RUNS"
        Assert-SeparatePaths `
            $sourceItem.FullName "evidence source" $env:CONFIG "CONFIG"
        Assert-SeparatePaths `
            $sourceItem.FullName "evidence source" $env:WORK "WORK"
    }
}

$resolvedEvidence = (Resolve-Path -LiteralPath $env:EVIDENCE).Path
if ([string]::IsNullOrWhiteSpace($script:EvidenceSelectionSourcePath)) {
    $script:EvidenceSelectionSourcePath = $resolvedEvidence
}
$prospectiveRuns = [System.IO.Path]::GetFullPath($env:RUNS)
$prospectiveConfig = [System.IO.Path]::GetFullPath($env:CONFIG)
$prospectiveWork = [System.IO.Path]::GetFullPath($env:WORK)

Assert-NoReparsePoint $resolvedEvidence "EVIDENCE"
Assert-NoReparsePoint $prospectiveRuns "RUNS"
Assert-NoReparsePoint $prospectiveConfig "CONFIG"
Assert-NoReparsePoint $prospectiveWork "WORK"

Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $prospectiveRuns "RUNS"
Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $prospectiveConfig "CONFIG"
Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $prospectiveWork "WORK"
Assert-SeparatePaths $prospectiveRuns "RUNS" $prospectiveConfig "CONFIG"
Assert-SeparatePaths $prospectiveRuns "RUNS" $prospectiveWork "WORK"
Assert-SeparatePaths $prospectiveConfig "CONFIG" $prospectiveWork "WORK"

New-Item -ItemType Directory -Force -Path $prospectiveRuns | Out-Null
New-Item -ItemType Directory -Force -Path $prospectiveConfig | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $prospectiveWork "home") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $prospectiveWork "cache") | Out-Null

$env:EVIDENCE = $resolvedEvidence
$env:RUNS = (Resolve-Path -LiteralPath $prospectiveRuns).Path
$env:CONFIG = (Resolve-Path -LiteralPath $prospectiveConfig).Path
$env:WORK = (Resolve-Path -LiteralPath $prospectiveWork).Path

Assert-NoReparsePoint $env:EVIDENCE "EVIDENCE"
Assert-NoReparsePoint $env:RUNS "RUNS"
Assert-NoReparsePoint $env:CONFIG "CONFIG"
Assert-NoReparsePoint $env:WORK "WORK"

Assert-SeparatePaths $env:EVIDENCE "EVIDENCE" $env:RUNS "RUNS"
Assert-SeparatePaths $env:EVIDENCE "EVIDENCE" $env:CONFIG "CONFIG"
Assert-SeparatePaths $env:EVIDENCE "EVIDENCE" $env:WORK "WORK"
Assert-SeparatePaths $env:RUNS "RUNS" $env:CONFIG "CONFIG"
Assert-SeparatePaths $env:RUNS "RUNS" $env:WORK "WORK"
Assert-SeparatePaths $env:CONFIG "CONFIG" $env:WORK "WORK"
Assert-EvidenceSourcesSeparatedFromWritableRoots

$env:DFA_UID = "10001"
$env:DFA_GID = "10001"
$env:DFA_HOST_PLATFORM = "windows"

function Invoke-NativeQuery {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    # Everything asked through here is a question the launcher can live without
    # an answer to: the image may not have been built yet, git may not be
    # installed, docker may be an older release without the subcommand. A
    # failure therefore returns $null instead of stopping a launch. PowerShell
    # 7.3 and later turn a non-zero native exit status into a terminating error
    # when $ErrorActionPreference is Stop, which is why the call is wrapped.
    try {
        $output = & $Command @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        return @($output)
    }
    catch {
        return $null
    }
}

function ConvertTo-Moment {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $value = "$Text".Trim()
    if (-not $value) {
        return $null
    }
    # Docker records nanoseconds. .NET Framework, which Windows PowerShell 5.1
    # runs on, rejects more than seven fractional digits outright, so the
    # fraction is dropped before parsing rather than after failing. The reader
    # inside the container drops it for the same reason.
    $value = [System.Text.RegularExpressions.Regex]::Replace($value, "\.[0-9]+", "")
    try {
        return [System.DateTimeOffset]::Parse(
            $value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    catch {
        return $null
    }
}

function Get-ComposeConsoleImageName {
    # docker-compose.yml pins "name: dfir-agent" and Compose tags an image it
    # builds itself <project>-<service>, so this checkout resolves to
    # dfir-agent-console:latest wherever it happens to live. Asking Compose
    # rather than assembling that string keeps a later rename of the project in
    # one file; the literal below is only the answer for a Compose release
    # without "config --images".
    $images = Invoke-NativeQuery -Command "docker" -Arguments @(
        "compose",
        "--project-directory", $projectRoot,
        "--file", $composeFile,
        "config", "--images"
    )
    if ($null -ne $images) {
        foreach ($line in $images) {
            $candidate = "$line".Trim()
            if ($candidate) {
                return $candidate
            }
        }
    }
    return "dfir-agent-console"
}

$script:ConsoleImageName = Get-ComposeConsoleImageName
$script:ConsoleImageCreated = $null

function Set-BuildIdentityVariables {
    # Nothing inside an image can name the image it is in, so the only place
    # this answer exists is out here, and the console shows whatever it is told.
    # An image that has not been built yet leaves both variables unset, which
    # docker-compose.yml renders as empty and the console reads as "unknown".
    $inspected = Invoke-NativeQuery -Command "docker" -Arguments @(
        "image", "inspect", $script:ConsoleImageName,
        "--format", "{{.Id}} {{.Created}}"
    )
    if ($null -eq $inspected) {
        return
    }
    $fields = @(
        "$($inspected -join ' ')".Trim() -split "\s+" | Where-Object { $_ }
    )
    if ($fields.Count -lt 2) {
        return
    }
    $env:DFA_BUILD_ID = $fields[0]
    $env:DFA_BUILD_TIME = $fields[1]
    $script:ConsoleImageCreated = ConvertTo-Moment -Text $fields[1]
}

function Set-HostMountVariables {
    # A container cannot see where a bind mount came from, so the console would
    # otherwise print /runtime/exports at an operator whose machine has no such
    # directory. Recomputed before every run rather than exported once: the
    # handoff loop below remounts a different host path and relaunches, and a
    # value captured before that would name the previous case.
    $env:DFA_HOST_RUNS = $env:RUNS
    if ($script:EvidenceSelectionKind -eq "directory") {
        $env:DFA_HOST_EVIDENCE = $env:EVIDENCE
        return
    }
    # A single-file case mounts each file under its own name below /evidence,
    # and $env:EVIDENCE names the private root of empty placeholders rather
    # than anything the operator owns. The directory the entry file came from
    # is what /evidence/<name> actually corresponds to.
    if (-not [string]::IsNullOrWhiteSpace($script:EvidenceSelectionSourcePath)) {
        $env:DFA_HOST_EVIDENCE = (
            Split-Path -Parent $script:EvidenceSelectionSourcePath
        )
        return
    }
    $env:DFA_HOST_EVIDENCE = ""
}

function Get-StalenessWarnings {
    # Two separate things go stale, and an operator reading a defect report
    # cannot tell which without being told. The command they type is a copy of
    # deploy\console\launch.ps1 taken at install time, and the image is a copy
    # of the source taken at build time; either can predate the checkout while
    # the other is current. Both cost whole days when they pass unnoticed,
    # because the console then behaves like a version nobody is looking at.
    $warnings = [System.Collections.Generic.List[string]]::new()

    $checkoutLauncher = Join-Path $projectRoot "deploy\console\launch.ps1"
    if (
        (Test-Path -LiteralPath $checkoutLauncher -PathType Leaf) -and
        $PSCommandPath
    ) {
        try {
            $installedHash = (
                Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256
            ).Hash
            $checkoutHash = (
                Get-FileHash -LiteralPath $checkoutLauncher -Algorithm SHA256
            ).Hash
        }
        catch {
            $installedHash = $null
            $checkoutHash = $null
        }
        # Contents, not dates: a git checkout does not preserve modification
        # times, so the tree's launcher can be older on disk than the installed
        # copy and still be the newer version.
        if (
            $null -ne $installedHash -and
            $null -ne $checkoutHash -and
            $installedHash -ne $checkoutHash
        ) {
            $warnings.Add(
                "The installed dfir-agent command is not the launcher in the " +
                "project directory."
            )
            $warnings.Add("  installed: $PSCommandPath")
            $warnings.Add("  checkout:  $checkoutLauncher")
            $warnings.Add(
                "  reinstall: powershell -File " +
                "$(Join-Path $projectRoot 'install.ps1') -SkipBuild"
            )
        }
    }

    # The image is compared against the checkout's newest commit rather than
    # against file modification times under src: a fresh clone stamps every file
    # with the moment it was cloned, which would report a correct image as
    # stale on the first launch after every clone. A commit date moves only when
    # work lands, so an image built from the current HEAD is always newer than
    # it and this cannot fire on a freshly built image. The one case it reports
    # without cause is building and then committing, where the image does hold
    # the committed code; that is a maintainer's order of work, not an
    # operator's, and it is answered by rebuilding or by DFA_ALLOW_STALE.
    $commitText = Invoke-NativeQuery -Command "git" -Arguments @(
        "-C", $projectRoot, "log", "-1", "--format=%cI"
    )
    $commitMoment = $null
    if ($null -ne $commitText) {
        $commitMoment = ConvertTo-Moment -Text ("$($commitText -join '')".Trim())
    }
    if (
        $null -ne $commitMoment -and
        $null -ne $script:ConsoleImageCreated -and
        $script:ConsoleImageCreated -lt $commitMoment
    ) {
        $imageWhen = $script:ConsoleImageCreated.ToLocalTime().ToString(
            "yyyy-MM-dd HH:mm"
        )
        $commitWhen = $commitMoment.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
        $warnings.Add(
            "The image $($script:ConsoleImageName) was built before the " +
            "project directory's newest commit."
        )
        $warnings.Add("  image built:   $imageWhen")
        $warnings.Add("  newest commit: $commitWhen")
        # The launcher's own command rather than a Compose line: it already
        # knows the compose file and the project this image belongs to, so
        # there is nothing left for the operator to get wrong.
        $warnings.Add("  rebuild: dfir-agent --rebuild")
    }
    return $warnings.ToArray()
}

function Confirm-Staleness {
    # Wrapped: an empty result unrolls to $null on the way out of a function,
    # and Set-StrictMode rejects reading .Count from that.
    $warnings = @(Get-StalenessWarnings)
    if ($warnings.Count -eq 0) {
        return
    }
    Write-Host ""
    Write-Host (
        "dfir-agent is about to run something other than the project " +
        "directory you launched it from."
    ) -ForegroundColor Yellow
    foreach ($line in $warnings) {
        Write-Host $line -ForegroundColor Yellow
    }
    Write-Host (
        "The Session panel names the build that actually starts."
    ) -ForegroundColor Yellow
    Write-Host ""
    # A warning printed here would be gone the moment the full screen console
    # draws over it, so the operator is stopped once, before the first run, and
    # never again inside the relaunch loop below. Refusing outright was the
    # other option and was rejected: reinstalling needs a running Docker and
    # rebuilding costs several gigabytes, so a refusal can strand someone whose
    # image is a day old and working. An unattended run cannot answer a prompt,
    # so it is warned and allowed to proceed rather than left hanging.
    if ($env:DFA_ALLOW_STALE -eq "1") {
        return
    }
    if ([Console]::IsInputRedirected) {
        return
    }
    Write-Host -NoNewline "Continue anyway? [y/N] "
    $answer = Read-Host
    $confirmed = (
        $null -ne $answer -and
        $answer.Trim().ToLowerInvariant() -in @("y", "yes")
    )
    if (-not $confirmed) {
        Write-Host (
            "Stopped. Set DFA_ALLOW_STALE=1 to skip this question."
        )
        exit 1
    }
}

Set-BuildIdentityVariables
Set-HostMountVariables
Confirm-Staleness

if (-not $AgentArguments -or $AgentArguments.Count -eq 0) {
    $AgentArguments = @("tui")
}

function Set-EvidenceLaunchArguments {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ContainerPath,
        [Parameter(Mandatory = $true)][string]$Action
    )

    $optionByAction = @{
        case = "--case"
        disk = "--image"
        memory = "--memory"
        network = "--pcap"
    }
    $selectedOption = $optionByAction[$Action]
    if (-not $selectedOption) {
        throw "The terminal requested an unsupported evidence action."
    }
    $result = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $argument = $Arguments[$index]
        if (
            $argument -in @("--case", "--image", "--memory", "--pcap")
        ) {
            $index++
            continue
        }
        if ($argument -eq "--resume") {
            if (($index + 1) -ge $Arguments.Count) {
                throw "--resume requires an investigation identifier."
            }
            $index++
            continue
        }
        if ($argument -eq "--continue" -or $argument -match "^--resume=") {
            continue
        }
        if (
            $argument -match "^--(?:case|image|memory|pcap)="
        ) {
            continue
        }
        $result.Add($argument)
    }
    if ($result.Count -eq 0 -or $result[0] -ne "tui") {
        $result.Insert(0, "tui")
    }
    $result.Add($selectedOption)
    $result.Add($ContainerPath)
    return $result.ToArray()
}

function Get-ExplicitEvidenceOption {
    param([Parameter(Mandatory = $true)][string]$ContainerPath)

    $extension = [System.IO.Path]::GetExtension($ContainerPath).ToLowerInvariant()
    if (
        $extension -in @(
            ".e01", ".ex01", ".dd", ".img", ".001",
            ".iso", ".vhd", ".vhdx"
        )
    ) {
        return "--image"
    }
    if ($extension -in @(".mem", ".vmem", ".dmp")) {
        return "--memory"
    }
    if ($extension -in @(".pcap", ".pcapng")) {
        return "--pcap"
    }
    throw (
        "The active single-file case type cannot be preserved while attaching " +
        "another source. Reopen one folder containing all related sources."
    )
}

function Add-EvidenceLaunchArguments {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ContainerPath,
        [Parameter(Mandatory = $true)][string]$Action
    )

    $optionByAction = @{
        "attach-disk" = "--image"
        "attach-memory" = "--memory"
        "attach-network" = "--pcap"
    }
    $selectedOption = $optionByAction[$Action]
    if (-not $selectedOption) {
        throw "The terminal requested an unsupported attachment action."
    }

    $result = [System.Collections.Generic.List[string]]::new()
    $presentOptions = @{}
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $argument = $Arguments[$index]
        if (
            $argument -in @("--case", "--image", "--memory", "--pcap")
        ) {
            if (($index + 1) -ge $Arguments.Count) {
                throw "$argument requires a path."
            }
            $value = $Arguments[++$index]
            $option = $argument.ToLowerInvariant()
            if (
                $option -eq "--case" -and
                $script:EvidenceSelectionKind -ne "directory"
            ) {
                $option = Get-ExplicitEvidenceOption -ContainerPath $value
            }
            if ($presentOptions.ContainsKey($option)) {
                throw "The active terminal contains duplicate evidence options."
            }
            $presentOptions[$option] = $true
            $result.Add($option)
            $result.Add($value)
            continue
        }
        if ($argument -eq "--resume") {
            if (($index + 1) -ge $Arguments.Count) {
                throw "--resume requires an investigation identifier."
            }
            $index++
            continue
        }
        if ($argument -eq "--continue" -or $argument -match "^--resume=") {
            continue
        }
        if ($argument -match "^(--(?:case|image|memory|pcap))=(.*)$") {
            $option = $Matches[1].ToLowerInvariant()
            $value = $Matches[2]
            if (
                $option -eq "--case" -and
                $script:EvidenceSelectionKind -ne "directory"
            ) {
                $option = Get-ExplicitEvidenceOption -ContainerPath $value
            }
            if ($presentOptions.ContainsKey($option)) {
                throw "The active terminal contains duplicate evidence options."
            }
            $presentOptions[$option] = $true
            $result.Add($option)
            $result.Add($value)
            continue
        }
        $result.Add($argument)
    }
    if ($presentOptions.ContainsKey($selectedOption)) {
        throw (
            "A source of this type is already attached. Use /case to replace " +
            "the case, or reopen a folder containing the intended source set."
        )
    }
    if ($result.Count -eq 0 -or $result[0] -ne "tui") {
        $result.Insert(0, "tui")
    }
    $result.Add($selectedOption)
    $result.Add($ContainerPath)
    return $result.ToArray()
}

function Resolve-RequestedHostPath {
    param([Parameter(Mandatory = $true)][string]$RequestedPath)

    $candidate = $RequestedPath.Trim()
    $bidiControls = @(
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069
    )
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        Write-Warning "The requested evidence path is empty."
        return $null
    }
    foreach ($character in $candidate.ToCharArray()) {
        if (
            [char]::IsControl($character) -or
            $bidiControls -contains [int]$character
        ) {
            Write-Warning "The requested evidence path contains a control character."
            return $null
        }
    }

    if ($candidate -eq "~") {
        $candidate = $HOME
    }
    elseif ($candidate.StartsWith("~/") -or $candidate.StartsWith("~\")) {
        $candidate = Join-Path $HOME $candidate.Substring(2)
    }
    elseif (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $launcherWorkingDirectory $candidate
    }

    try {
        $candidate = [System.IO.Path]::GetFullPath($candidate)
    }
    catch {
        Write-Warning "The requested evidence path is invalid: $RequestedPath"
        return $null
    }
    if (-not (Test-Path -LiteralPath $candidate)) {
        Write-Warning "Evidence path not found on the host: $candidate"
        return $null
    }
    return (Get-Item -LiteralPath $candidate -Force).FullName
}

function Set-AgentModelArgument {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Model
    )

    $bidiControls = @(
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069
    )
    if (
        [string]::IsNullOrWhiteSpace($Model) -or
        $Model -match "\s" -or
        $Model.StartsWith("-")
    ) {
        throw "The terminal produced an invalid active model identifier."
    }
    foreach ($character in $Model.ToCharArray()) {
        if (
            [char]::IsControl($character) -or
            $bidiControls -contains [int]$character
        ) {
            throw "The terminal produced an invalid active model identifier."
        }
    }

    $result = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $argument = $Arguments[$index]
        if ($argument -in @("-m", "--model")) {
            if (($index + 1) -ge $Arguments.Count) {
                throw "$argument requires a model identifier."
            }
            $index++
            continue
        }
        if (
            $argument.StartsWith(
                "--model=",
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or
            $argument.StartsWith(
                "-m=",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }
        $result.Add($argument)
    }
    $result.Add("--model")
    $result.Add($Model)
    return $result.ToArray()
}

function Set-AgentResumeArgument {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ConversationId
    )

    $bidiControls = @(
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069
    )
    if (
        [string]::IsNullOrWhiteSpace($ConversationId) -or
        $ConversationId -match "\s" -or
        $ConversationId.StartsWith("-")
    ) {
        throw "The terminal produced an invalid investigation identifier."
    }
    foreach ($character in $ConversationId.ToCharArray()) {
        if (
            [char]::IsControl($character) -or
            $bidiControls -contains [int]$character
        ) {
            throw "The terminal produced an invalid investigation identifier."
        }
    }

    $result = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $argument = $Arguments[$index]
        if ($argument -eq "--resume") {
            if (($index + 1) -ge $Arguments.Count) {
                throw "--resume requires an investigation identifier."
            }
            $index++
            continue
        }
        if ($argument -eq "--continue" -or $argument -match "^--resume=") {
            continue
        }
        $result.Add($argument)
    }
    $result.Add("--resume")
    $result.Add($ConversationId)
    return $result.ToArray()
}

function New-EvidenceLaunchSnapshot {
    return [PSCustomObject]@{
        AgentArguments = @($AgentArguments)
        Evidence = $env:EVIDENCE
        RunMountArguments = @($script:EvidenceRunMountArguments)
        AuthorizedPaths = @($script:AuthorizedEvidencePaths)
        SelectionKind = $script:EvidenceSelectionKind
        SelectionSourcePath = $script:EvidenceSelectionSourcePath
    }
}

function Restore-EvidenceLaunchSnapshot {
    param([Parameter(Mandatory = $true)][PSCustomObject]$State)

    Clear-PrivateEvidenceRoot
    if ($State.SelectionKind -eq "files") {
        $mountRoot = Initialize-PrivateEvidenceRoot
        foreach ($authorizedPath in @($State.AuthorizedPaths)) {
            $authorizedItem = Get-Item -LiteralPath $authorizedPath -Force
            if (-not $authorizedItem.PSIsContainer) {
                New-Item `
                    -ItemType File `
                    -Path (Join-Path $mountRoot $authorizedItem.Name) | Out-Null
            }
        }
    }
    $script:AgentArguments = @($State.AgentArguments)
    $env:EVIDENCE = [string]$State.Evidence
    $script:EvidenceRunMountArguments = @($State.RunMountArguments)
    $script:AuthorizedEvidencePaths = @($State.AuthorizedPaths)
    $script:EvidenceSelectionKind = [string]$State.SelectionKind
    $script:EvidenceSelectionSourcePath = [string]$State.SelectionSourcePath
}

$hostCaseHandoffExitCode = 75
$sessionStartupFailureExitCode = 78
$hostCaseHandoffSchema = "dfir-agent-host-case-v3"
$pendingEvidenceRollback = $null
$handoffDirectory = Join-Path $env:RUNS ".host-case-handoff"
New-Item -ItemType Directory -Force -Path $handoffDirectory | Out-Null
Assert-NoReparsePoint $handoffDirectory "host case handoff"
$env:DFA_SUPPRESS_BANNER = "0"

while ($true) {
    # The evidence selection changes on the handoff path below, so the host
    # roots the console displays are restated for every run rather than once.
    Set-HostMountVariables
    $handoffToken = [System.Guid]::NewGuid().ToString("N")
    $handoffFile = Join-Path $handoffDirectory "$handoffToken.request"
    Remove-Item -LiteralPath $handoffFile -Force -ErrorAction SilentlyContinue
    $env:DFA_HOST_CASE_REQUEST_TOKEN = $handoffToken
    $env:DFA_HOST_CASE_REQUEST_FILE = (
        "/runtime/.host-case-handoff/$handoffToken.request"
    )

    $nativePreference = Get-Variable `
        -Name PSNativeCommandUseErrorActionPreference `
        -ErrorAction SilentlyContinue
    if ($null -ne $nativePreference) {
        $previousNativePreference = $nativePreference.Value
        Set-Variable -Name PSNativeCommandUseErrorActionPreference -Value $false
    }
    try {
        & docker compose `
            --progress quiet `
            --project-directory $projectRoot `
            --file $composeFile `
            run --rm --remove-orphans --no-deps `
            @EvidenceRunMountArguments `
            console @AgentArguments
        $dockerStatus = $LASTEXITCODE
    }
    finally {
        if ($null -ne $nativePreference) {
            Set-Variable `
                -Name PSNativeCommandUseErrorActionPreference `
                -Value $previousNativePreference
        }
    }

    if (
        $dockerStatus -eq $sessionStartupFailureExitCode -and
        $null -ne $pendingEvidenceRollback
    ) {
        Remove-Item -LiteralPath $handoffFile -Force -ErrorAction SilentlyContinue
        Restore-EvidenceLaunchSnapshot -State $pendingEvidenceRollback
        $pendingEvidenceRollback = $null
        Write-Warning (
            "The selected evidence could not be opened. Reopening the terminal " +
            "with the previous evidence selection."
        )
        continue
    }
    if ($dockerStatus -ne $hostCaseHandoffExitCode) {
        Remove-Item -LiteralPath $handoffFile -Force -ErrorAction SilentlyContinue
        Clear-PrivateEvidenceRoot
        exit $dockerStatus
    }
    # Reaching a host-path request proves that the current session initialized.
    $pendingEvidenceRollback = $null
    $env:DFA_SUPPRESS_BANNER = "1"
    if (-not (Test-Path -LiteralPath $handoffFile -PathType Leaf)) {
        throw "The terminal requested a host path without producing a valid handoff."
    }
    $handoffItem = Get-Item -LiteralPath $handoffFile -Force
    if (
        ($handoffItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "The terminal host-path handoff must not be a symbolic link."
    }

    $requestLines = [System.IO.File]::ReadAllLines($handoffFile)
    Remove-Item -LiteralPath $handoffFile -Force
    if (
        $requestLines.Count -ne 6 -or
        $requestLines[0] -ne $hostCaseHandoffSchema -or
        $requestLines[1] -ne $handoffToken
    ) {
        throw "The terminal produced an invalid host-path handoff."
    }

    $requestedAction = $requestLines[2]
    if (
        $requestedAction -notin @(
            "case",
            "disk",
            "memory",
            "network",
            "attach-disk",
            "attach-memory",
            "attach-network"
        )
    ) {
        throw "The terminal requested an unsupported evidence action."
    }
    $AgentArguments = @(
        Set-AgentModelArgument `
            -Arguments $AgentArguments `
            -Model $requestLines[3]
    )
    if (-not [string]::IsNullOrWhiteSpace($requestLines[4])) {
        $AgentArguments = @(
            Set-AgentResumeArgument `
                -Arguments $AgentArguments `
                -ConversationId $requestLines[4]
        )
    }
    # The handoff carries the active in-container model and conversation. Keep
    # those values while treating the requested evidence change transactionally.
    $handoffRollback = New-EvidenceLaunchSnapshot
    $requestedHostPath = Resolve-RequestedHostPath -RequestedPath $requestLines[5]
    if ($null -eq $requestedHostPath) {
        Restore-EvidenceLaunchSnapshot -State $handoffRollback
        Write-Warning (
            "The terminal remains open with the previous evidence selection."
        )
        continue
    }
    if ($requestedAction.StartsWith("attach-")) {
        try {
            $attachmentItem = Get-Item -LiteralPath $requestedHostPath -Force
            if ($attachmentItem.PSIsContainer) {
                throw (
                    "/attach requires one evidence file. To open a folder and " +
                    "discover all supported sources, use /case <path>."
                )
            }
            Assert-EvidencePathIsDirect -Path $attachmentItem.FullName
            $segmentSet = Get-SegmentedEvidenceSet -PrimaryFile $attachmentItem
            $attachmentFiles = @($segmentSet.Files)
            $attachmentEntry = $segmentSet.EntryFile
            $attachmentContainerPath = "/evidence/$($attachmentEntry.Name)"
            if ($script:EvidenceSelectionKind -eq "directory") {
                $caseRoot = $script:AuthorizedEvidencePaths[0].TrimEnd("\", "/")
                $casePrefix = "$caseRoot\"
                if (
                    $attachmentEntry.FullName.StartsWith(
                        $casePrefix,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                ) {
                    $relativeEntry = $attachmentEntry.FullName.Substring(
                        $casePrefix.Length
                    )
                    $attachmentContainerPath = (
                        "/evidence/$($relativeEntry.Replace('\', '/'))"
                    )
                }
            }
        }
        catch {
            Restore-EvidenceLaunchSnapshot -State $handoffRollback
            Write-Warning $_.Exception.Message
            continue
        }
        try {
            $plannedAgentArguments = Add-EvidenceLaunchArguments `
                -Arguments $AgentArguments `
                -ContainerPath $attachmentContainerPath `
                -Action $requestedAction
        }
        catch {
            Restore-EvidenceLaunchSnapshot -State $handoffRollback
            Write-Warning $_.Exception.Message
            continue
        }

        Write-Host "The terminal requested read-only access to:"
        foreach ($file in $attachmentFiles) {
            Write-Host "  $($file.FullName)"
        }
        Write-Host -NoNewline "Allow this host access? [y/N] "
        $confirmation = Read-Host
        $confirmed = (
            $null -ne $confirmation -and
            $confirmation.Trim().ToLowerInvariant() -in @("y", "yes")
        )
        if (-not $confirmed) {
            Restore-EvidenceLaunchSnapshot -State $handoffRollback
            Write-Host (
                "Host access denied. Reopening the terminal with the previous " +
                "evidence selection."
            )
            continue
        }

        $pendingEvidenceRollback = $handoffRollback
        try {
            Add-EvidenceMountFileSet `
                -Files $attachmentFiles `
                -EntryFile $attachmentEntry | Out-Null
            Assert-EvidenceSourcesSeparatedFromWritableRoots
            $AgentArguments = @($plannedAgentArguments)
            $resolvedEvidence = (Resolve-Path -LiteralPath $env:EVIDENCE).Path
            Assert-NoReparsePoint $resolvedEvidence "EVIDENCE"
            Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $env:RUNS "RUNS"
            Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $env:CONFIG "CONFIG"
            Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $env:WORK "WORK"
            $env:EVIDENCE = $resolvedEvidence
        }
        catch {
            Restore-EvidenceLaunchSnapshot -State $pendingEvidenceRollback
            $pendingEvidenceRollback = $null
            Write-Warning $_.Exception.Message
        }
        continue
    }

    try {
        $requestedItem = Get-Item -LiteralPath $requestedHostPath -Force
        if ($requestedItem.PSIsContainer) {
            Assert-EvidencePathIsDirect -Path $requestedItem.FullName
            $requestedPaths = @($requestedItem.FullName)
        }
        else {
            Assert-EvidencePathIsDirect -Path $requestedItem.FullName
            $requestedSegmentSet = Get-SegmentedEvidenceSet `
                -PrimaryFile $requestedItem
            $requestedPaths = @($requestedSegmentSet.Files | ForEach-Object {
                $_.FullName
            })
        }
    }
    catch {
        Restore-EvidenceLaunchSnapshot -State $handoffRollback
        Write-Warning $_.Exception.Message
        continue
    }
    Write-Host "The terminal requested read-only access to:"
    foreach ($requestedPath in $requestedPaths) {
        Write-Host "  $requestedPath"
    }
    Write-Host -NoNewline "Allow this host access? [y/N] "
    $confirmation = Read-Host
    $confirmed = (
        $null -ne $confirmation -and
        $confirmation.Trim().ToLowerInvariant() -in @("y", "yes")
    )
    if (-not $confirmed) {
        Restore-EvidenceLaunchSnapshot -State $handoffRollback
        Write-Host (
            "Host access denied. Reopening the terminal with the previous " +
            "evidence selection."
        )
        continue
    }

    $pendingEvidenceRollback = $handoffRollback
    try {
        $containerPath = ConvertTo-ContainerCasePath -HostPath $requestedHostPath
        if ($null -eq $containerPath) {
            throw "The requested case path does not exist: $requestedHostPath"
        }
        $resolvedEvidence = (Resolve-Path -LiteralPath $env:EVIDENCE).Path
        Assert-NoReparsePoint $resolvedEvidence "EVIDENCE"
        Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $env:RUNS "RUNS"
        Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $env:CONFIG "CONFIG"
        Assert-SeparatePaths $resolvedEvidence "EVIDENCE" $env:WORK "WORK"
        Assert-EvidenceSourcesSeparatedFromWritableRoots
        $env:EVIDENCE = $resolvedEvidence
        $AgentArguments = Set-EvidenceLaunchArguments `
            -Arguments $AgentArguments `
            -ContainerPath $containerPath `
            -Action $requestedAction
    }
    catch {
        Restore-EvidenceLaunchSnapshot -State $pendingEvidenceRollback
        $pendingEvidenceRollback = $null
        Write-Warning $_.Exception.Message
    }
}
