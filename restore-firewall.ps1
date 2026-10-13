$ErrorActionPreference = 'Stop'
$guardPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $guardPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights required' }
$guardManifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'firewall-manifest.json') -Raw | ConvertFrom-Json
foreach ($guardRuleName in $guardManifest.rules) {
    if ($guardRuleName -notmatch '^ClaudeProxyOnly-(In|Out)-[A-F0-9]{20}$') { throw 'Unexpected rule name in restore manifest' }
    Get-NetFirewallRule -Name $guardRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
$guardProfiles = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'firewall-original-profiles.json') -Raw | ConvertFrom-Json
foreach ($guardProfile in $guardProfiles) {
    if ($guardProfile.Name -notin @('Domain','Private','Public')) { throw 'Unexpected network profile in restore backup' }
    Set-NetFirewallProfile -Profile $guardProfile.Name -Enabled ($guardProfile.Enabled -eq 1)
}
