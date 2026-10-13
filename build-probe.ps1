$ErrorActionPreference = 'Stop'
$guardCompiler = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $guardCompiler) { throw 'Windows .NET Framework C# compiler is required.' }
& $guardCompiler /nologo /target:exe ('/out:' + (Join-Path $PSScriptRoot 'network-rule-probe.exe')) (Join-Path $PSScriptRoot 'network-rule-probe.cs')
if ($LASTEXITCODE -ne 0) { throw 'Firewall probe compilation failed.' }
Write-Output 'Firewall probe built from source.'
