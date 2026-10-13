param([string]$Checker)
$ErrorActionPreference = 'Stop'
$guardCaptured = & $Checker
if (-not $guardCaptured) { throw 'Firewall JSON did not reach the installer pipeline.' }
$guardResult = $guardCaptured | ConvertFrom-Json
if ($guardResult.ok -isnot [bool]) { throw 'Firewall JSON result is invalid.' }
Write-Output ($guardResult | ConvertTo-Json -Compress)
