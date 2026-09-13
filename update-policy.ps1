<#
.SYNOPSIS
  The only whitelisting entry point (pure beta, plan stage 5).

.DESCRIPTION
  Either adds one program to the deployed policy (-AddProgram name path kind)
  or validates a policy file you edited under review (-PolicyPath). Both
  paths: structural validation -> timestamped backup -> re-pin binding.json
  -> reminder to restart the server. Direct hand edits of policy.json or
  binding.json bypassing this script are detected by the server startup
  self-check (hash mismatch) and refused.

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
$policyFile = if ($PolicyPath) { [IO.Path]::GetFullPath($PolicyPath) } else { Join-Path $repo 'policy.json' }
$bindingFile = Join-Path $repo 'binding.json'
$policyJson = Get-Content -LiteralPath $policyFile -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
$python = $policyJson['python']

if (-not (Test-Path -LiteralPath (Join-Path $repo 'server.py'))) { throw 'RepoRoot does not contain server.py.' }
if ($AddProgram) {
    if (-not $ProgramPath) { throw '-ProgramPath is required with -AddProgram.' }
    $ProgramPath = [IO.Path]::GetFullPath($ProgramPath)
    if (-not (Test-Path -LiteralPath $ProgramPath -PathType Leaf)) { throw "Program path not found: $ProgramPath" }
    $policyJson['programs'][$AddProgram] = @{ kind = $Kind; path = $ProgramPath }
    $target = if ($PolicyPath) { $policyFile } else { Join-Path $repo 'policy.json' }
    [IO.File]::WriteAllText($target, (ConvertTo-Json -InputObject $policyJson -Depth 20), [Text.UTF8Encoding]::new($false))
    $policyFile = $target
    Write-Output "Program added: $AddProgram ($Kind) -> $ProgramPath"
}

$validation = & $python -X utf8 (Join-Path $repo 'scripts\validate_policy.py') $policyFile
$exit = $LASTEXITCODE
Write-Output $validation
if ($exit -ne 0) { throw 'Policy validation failed; nothing was deployed.' }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $repo ("policy-backups\" + $stamp)
New-Item -ItemType Directory -Path $backup -Force | Out-Null
if (Test-Path -LiteralPath (Join-Path $repo 'policy.json')) {
    Copy-Item -LiteralPath (Join-Path $repo 'policy.json') -Destination (Join-Path $backup 'policy.json')
}
if (Test-Path -LiteralPath $bindingFile) {
    Copy-Item -LiteralPath $bindingFile -Destination (Join-Path $backup 'binding.json')
}
if ($policyFile -ne (Join-Path $repo 'policy.json')) {
    Copy-Item -LiteralPath $policyFile -Destination (Join-Path $repo 'policy.json')
}

$rebuilt = & $python -X utf8 (Join-Path $repo 'scripts\build_binding.py') --policy (Join-Path $repo 'policy.json') --out $bindingFile
Write-Output $rebuilt
Write-Output "Backup written: $backup"
Write-Output 'Restart the exec server (restart the Codex session or the server process) for the new policy to take effect.'
