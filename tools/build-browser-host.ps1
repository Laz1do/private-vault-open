param([string]$OutputPath)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot 'dist\browser-host.exe' }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$compilerCandidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$compilerPath = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compilerPath) { throw 'Windows .NET Framework 4.x C# compiler is required.' }
New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null
$sourcePath = Join-Path $projectRoot 'windows\BrowserHost.cs'
& $compilerPath /nologo /target:exe /platform:anycpu /optimize+ /reference:System.Security.dll /reference:System.Web.Extensions.dll "/out:$OutputPath" $sourcePath
if ($LASTEXITCODE -ne 0) { throw 'Chrome native host compilation failed.' }
Write-Output "Chrome native host built: $OutputPath"
