$ErrorActionPreference = 'Stop'
$root = 'c:\Code\command-entry\.smoke'
$exe = "$root\..\src\CommandEntry\bin\Release\net10.0-windows\win-x64\CommandEntry.exe"
$exe = 'c:\Code\command-entry\src\CommandEntry\bin\Release\net10.0-windows\win-x64\CommandEntry.exe'
$psi = [System.Diagnostics.ProcessStartInfo]::new($exe)
$psi.ArgumentList.Add('--policy'); $psi.ArgumentList.Add("$root\policy.json")
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$p.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"s","version":"0"}}}')
$p.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{"execution_id":"00000000-0000-4000-8000-000000000000"}}}')
$p.StandardInput.WriteLine('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text","arguments":{"file":"c:\\Code\\command-entry\\.smoke\\work\\hello.txt"}}}')
$p.StandardInput.Flush()
Start-Sleep -Seconds 4
$p.StandardInput.Close()
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()
$p.WaitForExit(5000) | Out-Null
"=== STDOUT ==="; $out -split "`n" | ForEach-Object { $_ }
"=== STDERR ==="; $err
"=== EXIT ==="; $p.ExitCode
