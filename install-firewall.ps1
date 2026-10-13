$ErrorActionPreference = 'Stop'
$guardInstallReport = Join-Path $PSScriptRoot 'firewall-install-result.json'
try {
    $guardIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $guardPrincipal = New-Object Security.Principal.WindowsPrincipal($guardIdentity)
    if (-not $guardPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights required' }
    . (Join-Path $PSScriptRoot 'firewall-common.ps1')
    $guardPrograms = @(Get-GuardPrograms)
    $guardBackupPath = Join-Path $PSScriptRoot 'firewall-original-profiles.json'
    if (-not (Test-Path -LiteralPath $guardBackupPath)) {
        @(Get-NetFirewallProfile | Select-Object Name,Enabled) | ConvertTo-Json | Set-Content -LiteralPath $guardBackupPath -Encoding utf8
    }
    # Only enable profiles; leave default actions and other app rules intact.
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    $guardCreated = @()
    foreach ($guardProgram in $guardPrograms) {
        foreach ($guardDirection in @('Out','In')) {
            $guardRuleName = Get-GuardRuleName $guardProgram $guardDirection
            $guardNetDirection = if ($guardDirection -eq 'Out') { 'Outbound' } else { 'Inbound' }
            $guardExisting = Get-NetFirewallRule -Name $guardRuleName -ErrorAction SilentlyContinue
            if ($guardExisting) {
                Set-NetFirewallRule -Name $guardRuleName -Enabled True -Action Block -Direction $guardNetDirection -Profile Any -Protocol Any -Program $guardProgram -RemoteAddress $GuardBlockedAddresses -LocalAddress Any -Service Any -InterfaceType Any | Out-Null
            } else {
                New-NetFirewallRule -Name $guardRuleName -DisplayName ('Claude only through local proxy: ' + $guardDirection + ' ' + [IO.Path]::GetFileName($guardProgram)) -Group $GuardFirewallGroup -Enabled True -Action Block -Direction $guardNetDirection -Profile Any -Protocol Any -Program $guardProgram -RemoteAddress $GuardBlockedAddresses -LocalAddress Any -Service Any -InterfaceType Any -PolicyStore PersistentStore | Out-Null
            }
            $guardCreated += $guardRuleName
        }
    }
    $guardManifest = [pscustomobject]@{programs=$guardPrograms;rules=$guardCreated;remote_addresses=$GuardBlockedAddresses}
    $guardManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'firewall-manifest.json') -Encoding utf8
    # An isolated test executable receives exactly the same address boundary.
    # Do not test by deliberately disabling the user's proxy or using Claude.
    $guardProbePath = Join-Path $PSScriptRoot 'network-rule-probe.exe'
    if (-not (Test-Path -LiteralPath $guardProbePath -PathType Leaf)) { throw 'Compiled firewall probe is missing' }
    $guardProbeRule = 'ClaudeNetworkGuard-IsolatedProbe'
    try {
        $guardPriorProbeRule = Get-NetFirewallRule -Name $guardProbeRule -ErrorAction SilentlyContinue
        if ($guardPriorProbeRule) { Remove-NetFirewallRule -Name $guardProbeRule }
        New-NetFirewallRule -Name $guardProbeRule -DisplayName 'Claude guard isolated firewall verification' -Direction Outbound -Profile Any -Action Block -Enabled True -Program $guardProbePath -RemoteAddress $GuardBlockedAddresses -Protocol Any | Out-Null
        $guardProbeJson = & $guardProbePath
        $guardProbeResult = $guardProbeJson | ConvertFrom-Json
        $guardProbeJson | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'firewall-network-self-test.json') -Encoding utf8
        if (-not $guardProbeResult.ok) { throw 'IPv4/IPv6 firewall enforcement self-test did not pass' }
    } finally {
        Get-NetFirewallRule -Name $guardProbeRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    $guardCheckJson = & (Join-Path $PSScriptRoot 'check-firewall.ps1')
    $guardCheck = $guardCheckJson | ConvertFrom-Json
    if (-not $guardCheck.ok) { throw 'Post-install firewall verification failed' }
    [pscustomobject]@{ok=$true;protected_programs=$guardPrograms.Count;rule_count=$guardCreated.Count;network_self_test=$guardProbeResult;completed_at=(Get-Date).ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $guardInstallReport -Encoding utf8
} catch {
    [pscustomobject]@{ok=$false;error=$_.Exception.Message;completed_at=(Get-Date).ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $guardInstallReport -Encoding utf8
    exit 1
}
