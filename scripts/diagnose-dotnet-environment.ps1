[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSBoundParameters.Count -ne 0) { throw 'This diagnostic accepts no arguments.' }

$dotnetPath = 'C:\Program Files\dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnetPath -PathType Leaf)) {
    throw 'The observed dotnet executable is missing.'
}

$variableName = 'PROCESSOR_ARCHITECTURE'
$inheritedArchitecture = [Environment]::GetEnvironmentVariable($variableName, 'Process')
$machineArchitecture = [Environment]::GetEnvironmentVariable($variableName, 'Machine')
$processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
$osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

# Restrict this experiment to the x64 installation observed in the failed run.
if ($processArchitecture -ne 'X64' -or $osArchitecture -ne 'X64' -or $machineArchitecture -ne 'AMD64') {
    throw 'The observed architecture does not match the x64 diagnostic case.'
}

function Invoke-InfoProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][bool]$SupplyArchitecture
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $dotnetPath
    $startInfo.WorkingDirectory = (Get-Location).Path
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.ArgumentList.Add('--info')
    if ($SupplyArchitecture) {
        $startInfo.Environment[$variableName] = $machineArchitecture
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'dotnet did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(20000)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) { throw 'Probe timed out; process termination is unconfirmed.' }
            throw 'Probe timed out; root process terminated.'
        }
        $exitCode = $process.ExitCode
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $installerFailure = $stderr.Contains('Microsoft.DotNet.Cli.Installer.Windows.InstallerBase') -and $stderr.Contains('NullReferenceException')
        if ($SupplyArchitecture) {
            if ($exitCode -ne 0 -or $stderr.Length -ne 0 -or -not $stdout.Contains('10.0.400')) {
                throw "Architecture probe failed: exit=$exitCode; stderr=$stderr"
            }
        } elseif ($exitCode -ne 1 -or -not $installerFailure) {
            throw "Baseline does not reproduce the recorded failure: exit=$exitCode; stderr=$stderr"
        }
        [PSCustomObject]@{
            label = $Label
            exit_code = $exitCode
            installer_null_reference = $installerFailure
            stdout_characters = $stdout.Length
            stderr_characters = $stderr.Length
            sdk_10_0_400_reported = $stdout.Contains('10.0.400')
        }
    } finally {
        $process.Dispose()
    }
}

$before = Invoke-InfoProbe -Label 'inherited_before' -SupplyArchitecture $false
$withArchitecture = Invoke-InfoProbe -Label 'child_architecture_only' -SupplyArchitecture $true
$after = Invoke-InfoProbe -Label 'inherited_after' -SupplyArchitecture $false
if ([Environment]::GetEnvironmentVariable($variableName, 'Process') -cne $inheritedArchitecture) {
    throw 'Diagnostic parent environment unexpectedly changed.'
}

[PSCustomObject]@{
    process_architecture = $processArchitecture
    os_architecture = $osArchitecture
    inherited_processor_architecture = $inheritedArchitecture
    machine_processor_architecture = $machineArchitecture
    cases = @($before, $withArchitecture, $after)
    parent_environment_unchanged = $true
    diagnosis = 'PROCESSOR_ARCHITECTURE in the child environment controls the observed InstallerBase failure.'
} | ConvertTo-Json -Depth 5
