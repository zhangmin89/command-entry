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
  Directory containing server.py, scripts/, policy.json, binding.json.

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
if (-not (Test-Path -LiteralPath (Join-Path $repo 'server.py'))) { throw 'RepoRoot does not contain server.py.' }
if (-not (Test-Path -LiteralPath $livePolicy)) { throw "Live policy not found: $livePolicy" }

# ---------- stage 1: build the candidate (nothing live is touched) ----------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
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
$python = (Get-Content -LiteralPath $livePolicy -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable)['python']

# ---------- stage 2: validate the candidate (failure = zero live change) ----------
$validation = & $python -X utf8 (Join-Path $repo 'scripts\validate_policy.py') $candidate
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

# ---------- stage 4: commit the candidate ----------
if ($candidate -ne $livePolicy) {
    Copy-Item -LiteralPath $candidate -Destination $livePolicy
} else {
    Write-Output 'Candidate IS the live policy: validation + re-pin only, nothing to commit.'
}

# ---------- stage 5: re-pin binding; any failure restores the old pair ----------
$rebuilt = & $python -X utf8 (Join-Path $repo 'scripts\build_binding.py') --policy $livePolicy --out $bindingFile
if ($LASTEXITCODE -ne 0) {
    Copy-Item -LiteralPath (Join-Path $backup 'policy.json') -Destination $livePolicy -Force
    if (Test-Path -LiteralPath (Join-Path $backup 'binding.json')) {
        Copy-Item -LiteralPath (Join-Path $backup 'binding.json') -Destination $bindingFile -Force
    }
    throw "Binding rebuild failed (exit $LASTEXITCODE); the old policy+binding pair was restored from $backup."
}
Write-Output $rebuilt
Write-Output 'Restart the exec server (restart the Codex session or the server process) for the new policy to take effect.'
