[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('Managed', 'NativeAot')]
    [string]$Mode = 'Managed'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..'))
$testProject = Join-Path -Path $repositoryRoot -ChildPath 'tests/CommandEntry.Tests.csproj'
$entryProject = Join-Path -Path $repositoryRoot -ChildPath 'src/CommandEntry/CommandEntry.csproj'
foreach ($inputPath in @($testProject, $entryProject)) {
    if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { throw "Missing project: $inputPath" }
}
$dotnetPath = (Get-Command -Name 'dotnet' -CommandType Application -ErrorAction Stop).Source
$runRoot = [IO.Path]::GetFullPath((Join-Path -Path $repositoryRoot -ChildPath ('artifacts/test-results/' + $Mode + '-' + [Guid]::NewGuid().ToString('N'))))
if (Test-Path -LiteralPath $runRoot) { throw "Refusing to reuse a test output directory: $runRoot" }
Write-Output "Create test artifacts: $runRoot"
[IO.Directory]::CreateDirectory($runRoot) | Out-Null

function Invoke-CheckedDotnet {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$CommandArguments)
    & $dotnetPath @CommandArguments
    $commandExitCode = $LASTEXITCODE
    if ($commandExitCode -ne 0) { throw "dotnet failed (exit $commandExitCode): $($CommandArguments -join ' ')" }
}

function Invoke-TestCategory {
    param([Parameter(Mandatory)][ValidateSet('Unit', 'Integration')][string]$Category)
    $reportName = "$Category.trx"
    Invoke-CheckedDotnet -CommandArguments @('test', '--project', $testProject, '--configuration', 'Release', '--no-build', '--output', 'Detailed', '--filter-trait', "Category=$Category", '--report-trx-filename', $reportName, '--results-directory', $runRoot)
    $reportPath = Join-Path -Path $runRoot -ChildPath $reportName
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw "Missing test report: $reportPath" }
    [xml]$report = Get-Content -LiteralPath $reportPath -Raw
    $counters = $report.TestRun.ResultSummary.Counters
    if ([int]$counters.total -le 0 -or [int]$counters.passed -ne [int]$counters.total -or [int]$counters.failed -ne 0) {
        throw "Test report did not confirm every selected test passed: $reportPath"
    }
    Write-Output "$Category verified: $($counters.passed) passed; report: $reportPath"
}

$previousServer = [Environment]::GetEnvironmentVariable('COMMAND_ENTRY_TEST_SERVER')
Push-Location -LiteralPath $repositoryRoot
try {
    [Environment]::SetEnvironmentVariable('COMMAND_ENTRY_TEST_SERVER', [NullString]::Value)
    Invoke-CheckedDotnet -CommandArguments @('build', $testProject, '--configuration', 'Release', '--verbosity', 'minimal')
    if ($Mode -eq 'Managed') {
        Invoke-TestCategory -Category Unit
        Invoke-TestCategory -Category Integration
    }
    else {
        $publishRoot = Join-Path -Path $runRoot -ChildPath 'native'
        Invoke-CheckedDotnet -CommandArguments @('restore', $entryProject, '--runtime', 'win-x64', '-p:Configuration=Release', '--verbosity', 'normal')
        Write-Output "Publish native artifact: $publishRoot"
        Invoke-CheckedDotnet -CommandArguments @('publish', $entryProject, '--configuration', 'Release', '--runtime', 'win-x64', '--no-restore', '--output', $publishRoot, '--verbosity', 'minimal')
        $nativeExe = Join-Path -Path $publishRoot -ChildPath 'CommandEntry.exe'
        if (-not (Test-Path -LiteralPath $nativeExe -PathType Leaf)) { throw "Missing native executable: $nativeExe" }
        $managedAssembly = Join-Path -Path $repositoryRoot -ChildPath 'src/CommandEntry/bin/Release/net10.0-windows/win-x64/CommandEntry.dll'
        Invoke-CheckedDotnet -CommandArguments @($managedAssembly, 'inspect-aot', '--executable', $nativeExe)
        [Environment]::SetEnvironmentVariable('COMMAND_ENTRY_TEST_SERVER', $nativeExe)
        Invoke-TestCategory -Category Integration
    }
}
finally {
    if ($null -eq $previousServer) {
        [Environment]::SetEnvironmentVariable('COMMAND_ENTRY_TEST_SERVER', [NullString]::Value)
    }
    else {
        [Environment]::SetEnvironmentVariable('COMMAND_ENTRY_TEST_SERVER', $previousServer)
    }
    Pop-Location
}
