<#
.SYNOPSIS
  The only whitelisting entry point (pure beta, plan stage 5).

.DESCRIPTION
  Staged commit (review R4): candidate is validated BEFORE anything live is
  touched; the old policy+binding pair is backed up BEFORE commit; the
  binding rebuild's exit code is checked, and any mid-flight failure restores
  the old pair so a recovery never mixes a new policy with an old anchor.

  Either adds one program to the deployed policy (-AddProgram name path kind)
  or validates a policy file you edited under review (-PolicyPath). Direct
  hand edits of policy.json or binding.json bypassing this script are
  detected by the server startup self-check (hash mismatch) and refused.

.PARAMETER RepoRoot
  Directory containing CommandEntry.exe or server.py, scripts/, policy.json, binding.json.

.PARAMETER PolicyPath
  Path of an already-edited policy to validate and deploy.

.PARAMETER AddProgram
  Shorthand whitelist addition: -AddProgram name -ProgramPath path -Kind kind.

.PARAMETER Kind
  One of native, python, powershell, javascript.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [string]$PolicyPath,
    [string]$AddProgram,
    [string]$ProgramPath,
    [ValidateSet('native', 'python', 'powershell', 'javascript')][string]$Kind = 'native'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = [IO.Path]::GetFullPath($RepoRoot)
$livePolicy = Join-Path $repo 'policy.json'
$bindingFile = Join-Path $repo 'binding.json'
$dotnetRuntime = Test-Path -LiteralPath (Join-Path -Path $repo -ChildPath 'CommandEntry.exe') -PathType Leaf
if (-not $dotnetRuntime -and -not (Test-Path -LiteralPath (Join-Path -Path $repo -ChildPath 'server.py') -PathType Leaf)) {
    throw 'RepoRoot does not contain CommandEntry.exe or server.py.'
}
if ($dotnetRuntime -and -not (Test-Path -LiteralPath (Join-Path -Path $repo -ChildPath 'scripts\build-dotnet-binding.ps1') -PathType Leaf)) {
    throw 'The .NET runtime requires scripts\build-dotnet-binding.ps1.'
}
if (-not (Test-Path -LiteralPath $livePolicy)) { throw "Live policy not found: $livePolicy" }
$liveDefinition = Get-Content -LiteralPath $livePolicy -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
if (-not $liveDefinition.ContainsKey('python') -or $liveDefinition['python'] -isnot [string] -or
    [string]::IsNullOrWhiteSpace($liveDefinition['python'])) {
    throw 'Policy maintenance requires a non-empty python interpreter path in the live policy.'
}
$python = $liveDefinition['python']
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Policy maintenance Python interpreter not found: $python" }
$validator = Join-Path -Path $repo -ChildPath 'scripts\validate_policy.py'
if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) { throw "Policy validator not found: $validator" }

# ---------- stage 1: build the candidate (nothing live is touched) ----------
# Unique transaction id: a bare second-resolution stamp can collide across
# concurrent runs (shared TEMP candidate name, backup dir overwrite).
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
$candidate = Join-Path $env:TEMP ("policy-candidate-" + $stamp + ".json")
if ($AddProgram) {
    if (-not $ProgramPath) { throw '-ProgramPath is required with -AddProgram.' }
    $ProgramPath = [IO.Path]::GetFullPath($ProgramPath)
    if (-not (Test-Path -LiteralPath $ProgramPath -PathType Leaf)) { throw "Program path not found: $ProgramPath" }
    $policyJson = Get-Content -LiteralPath $livePolicy -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    $policyJson['programs'][$AddProgram] = @{ kind = $Kind; path = $ProgramPath }
    [IO.File]::WriteAllText($candidate, (ConvertTo-Json -InputObject $policyJson -Depth 20), [Text.UTF8Encoding]::new($false))
    Write-Output "Candidate prepared: +$AddProgram ($Kind) -> $ProgramPath"
} elseif ($PolicyPath) {
    $candidate = [IO.Path]::GetFullPath($PolicyPath)
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "PolicyPath not found: $candidate" }
} else {
    Copy-Item -LiteralPath $livePolicy -Destination $candidate
}

# ---------- stage 2: validate the candidate (failure = zero live change) ----------
$validation = & $python -X utf8 $validator $candidate
$exit = $LASTEXITCODE
Write-Output $validation
if ($exit -ne 0) { throw 'Candidate validation failed; nothing was deployed and the live policy is untouched.' }

# ---------- stage 3: back up the COMPLETE old pair before committing ----------
$backup = Join-Path $repo ("policy-backups\" + $stamp)
New-Item -ItemType Directory -Path $backup -Force | Out-Null
Copy-Item -LiteralPath $livePolicy -Destination (Join-Path $backup 'policy.json')
if (Test-Path -LiteralPath $bindingFile) {
    Copy-Item -LiteralPath $bindingFile -Destination (Join-Path $backup 'binding.json')
}
Write-Output "Old pair archived: $backup"

# ---------- stages 4+5: commit, then re-pin. ANY mid-flight failure
# (copy error, interpreter launch failure, non-zero exit) restores the old pair.
try {
    if ($candidate -ne $livePolicy) {
        Copy-Item -LiteralPath $candidate -Destination $livePolicy -ErrorAction Stop
    } else {
        Write-Output 'Candidate IS the live policy: validation + re-pin only, nothing to commit.'
    }
    if ($dotnetRuntime) {
        $candidateBinding = [IO.Path]::GetFullPath((Join-Path -Path $repo -ChildPath ("binding-candidate-" + $stamp + ".json")))
        $bindingParameters = @{ RuntimeRoot = $repo; PolicyPath = $livePolicy; OutputPath = $candidateBinding }
        $rebuilt = & (Join-Path -Path $repo -ChildPath 'scripts\build-dotnet-binding.ps1') @bindingParameters
        Move-Item -LiteralPath $candidateBinding -Destination $bindingFile -Force -ErrorAction Stop
    } else {
        $rebuilt = & $python -X utf8 (Join-Path $repo 'scripts\build_binding.py') --policy $livePolicy --out $bindingFile
        $bindingExit = $LASTEXITCODE
        if ($bindingExit -ne 0) { throw "build_binding exited $bindingExit" }
    }
} catch {
    Copy-Item -LiteralPath (Join-Path $backup 'policy.json') -Destination $livePolicy -Force
    if (Test-Path -LiteralPath (Join-Path $backup 'binding.json')) {
        Copy-Item -LiteralPath (Join-Path $backup 'binding.json') -Destination $bindingFile -Force
    }
    throw "Mid-flight failure ($($_)); the old policy+binding pair was restored from $backup."
}
Write-Output $rebuilt
Write-Output 'Restart the exec server (restart the Codex session or the server process) for the new policy to take effect.'
