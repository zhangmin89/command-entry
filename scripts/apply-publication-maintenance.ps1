<#
.SYNOPSIS
  Preview or apply the reviewed C1-C4 files and quarantine the three B records.
.DESCRIPTION
  Run manually with -Apply after stopping command-entry servers and children.
  No records are deleted. Policy bytes must remain unchanged. The existing
  update-policy.ps1 owns re-pinning; this script does not build its own binding.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Apply,
    [ValidateNotNullOrEmpty()][string]$InstallRoot = 'C:\Users\zhang\.codex\command-entry',
    [ValidateNotNullOrEmpty()][string]$SourceRoot = 'F:\Code\command-entry'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSBoundParameters.Count -gt 3) { throw 'Unexpected parameter count.' }

$install = [IO.Path]::GetFullPath($InstallRoot)
$source = [IO.Path]::GetFullPath($SourceRoot)
foreach ($root in @($install, $source)) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Directory missing: $root" }
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Reparse-point roots are not supported: $root"
    }
}
if ($install -eq $source) { throw 'InstallRoot and SourceRoot must differ.' }
$policyPath = Join-Path -Path $install -ChildPath 'policy.json'
$bindingPath = Join-Path -Path $install -ChildPath 'binding.json'
$updateScript = Join-Path -Path $source -ChildPath 'update-policy.ps1'
$serveRoot = Join-Path -Path $install -ChildPath 'serve-input'
$quarantine = Join-Path -Path $install -ChildPath 'quarantine\half-published-20260914'
$backup = Join-Path -Path $install -ChildPath 'maintenance\publication-fixes-20260914'

function Get-CheckedHash {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File missing: $Path" }
    if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Reparse-point files are not supported: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Binding {
    $binding = Get-Content -LiteralPath $bindingPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    if ($binding['schema_version'] -ne 2 -or
        [IO.Path]::GetFullPath($binding['policy']['path']) -ne $policyPath -or
        (Get-CheckedHash -Path $policyPath) -ne $binding['policy']['sha256']) {
        throw 'Installed policy does not match its reviewed binding.'
    }
    foreach ($item in $binding['runtime_files']) {
        $path = [IO.Path]::GetFullPath($item['path'])
        if ([IO.Path]::GetDirectoryName($path) -ne $install -or
            (Get-CheckedHash -Path $path) -ne $item['sha256']) {
            throw "Installed runtime does not match its reviewed binding: $path"
        }
    }
    return $binding
}

$oldBinding = Assert-Binding
$policyHash = Get-CheckedHash -Path $policyPath
$bindingHash = Get-CheckedHash -Path $bindingPath
$null = Get-CheckedHash -Path $updateScript
$copies = @(foreach ($name in @('server.py', 'entry_v2.py')) {
    $from = [IO.Path]::GetFullPath((Join-Path -Path $source -ChildPath $name))
    $to = [IO.Path]::GetFullPath((Join-Path -Path $install -ChildPath $name))
    $anchored = @($oldBinding['runtime_files'] | Where-Object -FilterScript { $_['path'] -eq $to })
    if ($anchored.Count -ne 1) { throw "Runtime missing from binding: $to" }
    [PSCustomObject]@{ source = $from; destination = $to
        old_sha256 = Get-CheckedHash -Path $to; new_sha256 = Get-CheckedHash -Path $from }
})
$identities = @(
    @{ id = '32ee416c-7ed3-532e-856c-3ff84f09a257'; fingerprint = 'da09a52adc587ee5b30ade57750bb9dcf12075e9ed7c188955db5d265705766c' }
    @{ id = 'b6e13d59-0a85-5f3b-be87-3c4d22743647'; fingerprint = 'd060a957baea03c74fec260aa905813b6a23cdede4318e4ceaf66e1ba0a28ace' }
    @{ id = '0b25593f-66dc-5deb-84f7-745e23a40692'; fingerprint = 'c0e95ed5888ac9bac76d9fc69dda3f37d3ca3f544cc4473241208d5512db19a8' }
)
$moves = @(foreach ($identity in $identities) {
    $from = [IO.Path]::GetFullPath((Join-Path -Path $serveRoot -ChildPath $identity['id']))
    $to = [IO.Path]::GetFullPath((Join-Path -Path $quarantine -ChildPath $identity['id']))
    if ([IO.Path]::GetDirectoryName($from) -ne $serveRoot -or
        [IO.Path]::GetDirectoryName($to) -ne $quarantine) { throw 'Move escaped the approved roots.' }
    if (-not (Test-Path -LiteralPath $from -PathType Container)) { throw "Orphan missing: $from" }
    if ((Get-Item -LiteralPath $from).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Orphan is a reparse point: $from"
    }
    $children = @(Get-ChildItem -LiteralPath $from -Force)
    if ($children.Count -ne 1 -or $children[0].Name -ne 'request.json' -or $children[0].PSIsContainer) {
        throw "Directory is no longer request-only: $from"
    }
    $requestPath = Join-Path -Path $from -ChildPath 'request.json'
    $request = Get-Content -LiteralPath $requestPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    if ($request['content_fingerprint'] -ne $identity['fingerprint']) { throw "Fingerprint changed: $requestPath" }
    $recordRoot = Join-Path -Path $request['business']['cwd'] -ChildPath '.codex-command-records'
    $record = Join-Path -Path $recordRoot -ChildPath $identity['id']
    $claimDirectory = Join-Path -Path (Join-Path -Path $serveRoot -ChildPath '_claims') -ChildPath $identity['fingerprint']
    $claim = Join-Path -Path $claimDirectory -ChildPath 'claim.json'
    if ((Test-Path -LiteralPath $record) -or (Test-Path -LiteralPath $claim)) {
        throw "Execution or claim now exists; re-review before moving: $from"
    }
    [PSCustomObject]@{ source = $from; destination = $to; request_sha256 = Get-CheckedHash -Path $requestPath }
})
foreach ($newPath in @($backup, $quarantine)) {
    if (Test-Path -LiteralPath $newPath) { throw "Maintenance target already exists: $newPath" }
    $parent = [IO.Path]::GetDirectoryName($newPath)
    if ((Test-Path -LiteralPath $parent) -and
        ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Maintenance parent is a reparse point: $parent"
    }
}
$active = @(Get-CimInstance -ClassName Win32_Process | Where-Object -FilterScript {
    $_.CommandLine -and $_.CommandLine.IndexOf($install, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
    $_.CommandLine -match '(server|entry_v2|worker_v2)\.py'
} | Select-Object -Property ProcessId, Name)
$backupFiles = @(foreach ($name in @('server.py', 'entry_v2.py', 'binding.json')) {
    [IO.Path]::GetFullPath((Join-Path -Path $backup -ChildPath $name))
})
$manifestPath = Join-Path -Path $backup -ChildPath 'manifest.json'
$plan = [ordered]@{ apply = [bool]$Apply; copies = $copies; moves = $moves
    backup_directory = $backup; backup_files = $backupFiles; manifest = $manifestPath
    policy_sha256 = $policyHash; active_processes = $active; binding_update = $bindingPath }
ConvertTo-Json -InputObject $plan -Depth 8
if (-not $Apply) { return }
if ($active.Count -ne 0) { throw 'Stop the listed command-entry servers and children before applying.' }

# Preflight is complete. Back up every overwritten file before the first mutation.
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($copy in $copies) {
    if ((Get-CheckedHash -Path $copy.source) -ne $copy.new_sha256 -or
        (Get-CheckedHash -Path $copy.destination) -ne $copy.old_sha256) { throw 'Runtime changed after preflight.' }
    $saved = Join-Path -Path $backup -ChildPath ([IO.Path]::GetFileName($copy.destination))
    Copy-Item -LiteralPath $copy.destination -Destination $saved
    if ((Get-CheckedHash -Path $saved) -ne $copy.old_sha256) { throw "Backup mismatch: $saved" }
}
$savedBinding = Join-Path -Path $backup -ChildPath 'binding.json'
Copy-Item -LiteralPath $bindingPath -Destination $savedBinding
if ((Get-CheckedHash -Path $savedBinding) -ne $bindingHash) { throw 'Binding changed after preflight.' }
[IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $plan -Depth 8), [Text.UTF8Encoding]::new($false))
foreach ($copy in $copies) {
    Copy-Item -LiteralPath $copy.source -Destination $copy.destination
    if ((Get-CheckedHash -Path $copy.destination) -ne $copy.new_sha256) { throw "Installed hash mismatch: $($copy.destination)" }
}
$repinParameters = @{ RepoRoot = $install; PolicyPath = $policyPath }
& $updateScript @repinParameters
$null = Assert-Binding
if ((Get-CheckedHash -Path $policyPath) -ne $policyHash) { throw 'Policy bytes changed during re-pin.' }

New-Item -ItemType Directory -Path $quarantine | Out-Null
foreach ($move in $moves) {
    $requestPath = Join-Path -Path $move.source -ChildPath 'request.json'
    if ((Get-CheckedHash -Path $requestPath) -ne $move.request_sha256 -or
        (Test-Path -LiteralPath $move.destination)) { throw 'Orphan changed after preflight.' }
    Move-Item -LiteralPath $move.source -Destination $move.destination
    $movedRequest = Join-Path -Path $move.destination -ChildPath 'request.json'
    if ((Test-Path -LiteralPath $move.source) -or
        (Get-CheckedHash -Path $movedRequest) -ne $move.request_sha256) { throw 'Quarantine verification failed.' }
}
ConvertTo-Json -InputObject @{ state = 'verified'; installed_files = $copies.Count
    quarantined_directories = $moves.Count; policy_unchanged = $true; manifest = $manifestPath }
