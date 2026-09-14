# Isolated end-to-end smoke test for the C# rewrite. Everything lives under .smoke.
$ErrorActionPreference = 'Stop'
$root = 'c:\Code\command-entry\.smoke'
$work = Join-Path $root 'work'
$serve = Join-Path $root 'serve'
New-Item -ItemType Directory -Force -Path $work, $serve | Out-Null
Set-Content -Path (Join-Path $work 'hello.txt') -Value 'smoke-line-1' -Encoding utf8
Set-Content -Path (Join-Path $work 'say.ps1') -Value "Write-Output 'business-stdout-ok'" -Encoding utf8

$policy = [ordered]@{
    version = 2
    record_root = '.codex-command-records'
    serve_root = $serve
    log_root = (Join-Path $root 'logs')
    working_roots = @($work)
    read_roots = $null
    programs = @{
        pwsh = @{ kind = 'powershell'; path = 'C:\Program Files\PowerShell\7\pwsh.exe' }
        python = @{ kind = 'python'; path = 'C:\Users\zhang\AppData\Local\Python\pythoncore-3.14-64\python.exe' }
    }
    operations = @{
        native = @{ acceptable_exit_codes = @(0); run_seconds = 60; wait_category = 'long_task' }
        python_unittest = @{ acceptable_exit_codes = @(0); run_seconds = 60; wait_category = 'long_task' }
        script = @{ acceptable_exit_codes = @(0); run_seconds = 60; wait_category = 'long_task' }
    }
    output_quota_bytes = 1048576
    read_quota_bytes = 65536
    cleanup_seconds = 10
    wait_budget_seconds = 20
    wait_poll_interval_seconds = 2
    wait_stop_after_no_progress = 12
    cancel_grace_seconds = 5
    cancel_confirm_seconds = 5
    start_confirm_seconds = 15
    require_orphan_guarantee = $false
}
$policyPath = Join-Path $root 'policy.json'
$policy | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Encoding utf8

$exe = 'c:\Code\command-entry\src\CommandEntry\bin\Release\net10.0-windows\win-x64\CommandEntry.exe'
$psi = [System.Diagnostics.ProcessStartInfo]::new($exe)
$psi.ArgumentList.Add('--policy'); $psi.ArgumentList.Add($policyPath)
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)

$script:id = 0
function Send-Rpc($method, $params) {
    $script:id++
    $msg = @{ jsonrpc = '2.0'; id = $script:id; method = $method }
    if ($null -ne $params) { $msg.params = $params }
    $json = $msg | ConvertTo-Json -Depth 20 -Compress
    Write-Host ">>> $json"
    $proc.StandardInput.WriteLine($json)
    $proc.StandardInput.Flush()
    while ($true) {
        $line = $proc.StandardOutput.ReadLine()
        Write-Host "<<< $line"
        if ($null -eq $line) { throw "server stdout closed; stderr: $($proc.StandardError.ReadToEnd())" }
        $parsed = $line | ConvertFrom-Json -AsHashtable
        if ($parsed.ContainsKey('id') -and "$($parsed.id)" -eq "$($script:id)") { return $parsed }
    }
}
function Call-Tool($name, $toolArgs) { Send-Rpc 'tools/call' @{ name = $name; arguments = $toolArgs } }

$init = Send-Rpc 'initialize' @{ protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'smoke'; version = '0' } }
Write-Host "INIT: $($init.result.serverInfo | ConvertTo-Json -Compress)"
$proc.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized"}')
$proc.StandardInput.Flush()
$tools = Send-Rpc 'tools/list' $null
Write-Host "TOOLS: $(($tools.result.tools | ForEach-Object name) -join ',')"

$rt = Call-Tool 'read_text' @{ file = (Join-Path $work 'hello.txt') }
Write-Host "READ_TEXT: $($rt | ConvertTo-Json -Depth 10 -Compress)"

$start = Call-Tool 'start_operation' @{
    operation = 'script'; program = 'pwsh'; language = 'powershell'
    script = (Join-Path $work 'say.ps1')
    workdir = $work
}
$startBody = $start.result.content[0].text | ConvertFrom-Json -AsHashtable
Write-Host "START: $($start.result.content[0].text)"
$executionId = $startBody.execution_id

$wait = Call-Tool 'wait' @{ execution_id = $executionId }
Write-Host "WAIT: $($wait.result.content[0].text)"

$out = Call-Tool 'output' @{ execution_id = $executionId; stream = 'stdout' }
Write-Host "OUTPUT: $($out.result.content[0].text)"

$status = Call-Tool 'status' @{ execution_id = $executionId }
Write-Host "STATUS: $($status.result.content[0].text)"

$dedup = Call-Tool 'start_operation' @{
    operation = 'script'; program = 'pwsh'; language = 'powershell'
    script = (Join-Path $work 'say.ps1')
    workdir = $work
}
Write-Host "DEDUP: $($dedup.result.content[0].text)"

$bad = Call-Tool 'start_operation' @{ operation = 'script'; program = 'pwsh'; language = 'powershell'; script = (Join-Path $work 'say.ps1'); workdir = $work; bogus_field = 'x' }
Write-Host "UNKNOWN_FIELD isError=$($bad.result.isError): $($bad.result.content[0].text)"

$proc.StandardInput.Close()
$proc.WaitForExit(10000) | Out-Null
Write-Host "SERVER_EXIT: $($proc.ExitCode)"
Write-Host '--- server-events.jsonl ---'
Get-Content (Join-Path $root 'logs\server-events.jsonl') | ForEach-Object { Write-Host $_ }
