param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RuntimeRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$PolicyPath,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSBoundParameters.Count -ne 3) { throw 'Exactly RuntimeRoot, PolicyPath and OutputPath are required.' }
foreach ($inputPath in @($RuntimeRoot, $PolicyPath)) {
    if (-not [System.IO.Path]::IsPathFullyQualified($inputPath)) { throw "Absolute input path required: $inputPath" }
    if (-not (Test-Path -LiteralPath $inputPath)) { throw "Input path missing: $inputPath" }
}
if (-not (Test-Path -LiteralPath $RuntimeRoot -PathType Container)) { throw 'RuntimeRoot must be a directory.' }
if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) { throw 'PolicyPath must be a file.' }
if (-not [System.IO.Path]::IsPathFullyQualified($OutputPath)) { throw 'OutputPath must be absolute.' }
$runtimeDirectory = (Resolve-Path -LiteralPath $RuntimeRoot).ProviderPath
$policyFile = (Resolve-Path -LiteralPath $PolicyPath).ProviderPath
$bindingFile = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $bindingFile) { throw "Refusing to overwrite an existing binding: $bindingFile" }
if (-not (Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($bindingFile)) -PathType Container)) {
    throw 'The output parent directory must already exist.'
}

$runtimeNames = @('CommandEntry.exe', 'invoke.ps1', 'check_powershell.ps1', 'check_python.py')
$phase = 'csharp_native_aot'
if (Test-Path -LiteralPath (Join-Path -Path $runtimeDirectory -ChildPath 'CommandEntry.dll') -PathType Leaf) {
    $runtimeNames += @('CommandEntry.dll', 'CommandEntry.deps.json', 'CommandEntry.runtimeconfig.json')
    $phase = 'csharp_managed'
}
$handles = [System.Collections.Generic.List[System.IO.FileStream]]::new()
function Get-LockedDigest {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) { throw "Runtime file missing: $LiteralPath" }
    $handle = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $handles.Add($handle)
    return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($handle)).ToLowerInvariant()
}

try {
    $policyDigest = Get-LockedDigest -LiteralPath $policyFile
    $runtimeFiles = @(
        foreach ($name in $runtimeNames) {
            $runtimeFile = [System.IO.Path]::GetFullPath((Join-Path -Path $runtimeDirectory -ChildPath $name))
            @{ path = $runtimeFile; sha256 = (Get-LockedDigest -LiteralPath $runtimeFile) }
        }
    )
    $binding = @{
        schema_version = 2
        phase = $phase
        policy = @{ path = $policyFile; sha256 = $policyDigest }
        runtime_files = $runtimeFiles
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes(($binding | ConvertTo-Json -Depth 8))
    $target = [System.IO.File]::Open($bindingFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $target.Write($bytes, 0, $bytes.Length); $target.Flush($true) }
    finally { $target.Dispose() }
    $verified = [System.IO.File]::ReadAllText($bindingFile, $encoding) | ConvertFrom-Json -AsHashtable
    if ($verified.schema_version -ne 2 -or $verified.runtime_files.Count -ne $runtimeNames.Count -or $verified.policy.sha256 -ne $policyDigest) {
        throw 'Written binding did not pass artifact validation.'
    }
    @{ written = $bindingFile; files = $verified.runtime_files.Count; policy_sha256 = $policyDigest } | ConvertTo-Json -Compress
}
finally {
    foreach ($handle in $handles) { $handle.Dispose() }
}
