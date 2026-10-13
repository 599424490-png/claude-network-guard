$ErrorActionPreference = 'Stop'
try {
    . (Join-Path $PSScriptRoot 'firewall-common.ps1')
    $guardPolicy = New-Object -ComObject HNetCfg.FwPolicy2
    foreach ($guardProfile in @(1,2,4)) {
        if (-not $guardPolicy.FirewallEnabled($guardProfile)) { throw 'Firewall disabled on a network profile' }
    }
    if ($guardPolicy.LocalPolicyModifyState -eq 1) { throw 'Local firewall policy is overridden' }
    $guardSelfTest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'firewall-network-self-test.json') -Raw | ConvertFrom-Json
    if (-not $guardSelfTest.ok) { throw 'Firewall enforcement self-test has not passed' }
    $guardExpectedAddresses = Normalize-GuardAddresses ($GuardBlockedAddresses -join ',')
    # COM's Rules.Item indexes the friendly DisplayName, not NetSecurity's
    # internal rule Name. Match the effective grouped rules by executable and
    # direction to handle several installed versions with identical filenames.
    $guardEffectiveRules = @($guardPolicy.Rules | Where-Object { $_.Grouping -eq $GuardFirewallGroup })
    $guardPrograms = @(Get-GuardPrograms)
    foreach ($guardProgram in $guardPrograms) {
        foreach ($guardDirection in @('Out','In')) {
            $guardExpectedDirection = if ($guardDirection -eq 'Out') { 2 } else { 1 }
            $guardMatchingRules = @($guardEffectiveRules | Where-Object { $_.ApplicationName -and $_.ApplicationName.Equals($guardProgram,[StringComparison]::OrdinalIgnoreCase) -and $_.Direction -eq $guardExpectedDirection })
            if ($guardMatchingRules.Count -ne 1) { throw 'Expected exactly one protection rule per executable and direction' }
            $guardRule = $guardMatchingRules[0]
            if (-not $guardRule.Enabled -or $guardRule.Action -ne 0 -or $guardRule.Direction -ne $guardExpectedDirection -or
                ($guardRule.Profiles -band 7) -ne 7 -or $guardRule.Protocol -ne 256 -or
                -not $guardRule.ApplicationName.Equals($guardProgram,[StringComparison]::OrdinalIgnoreCase) -or
                (Normalize-GuardAddresses $guardRule.RemoteAddresses) -ne $guardExpectedAddresses -or
                $guardRule.LocalAddresses -ne '*' -or $guardRule.ServiceName -notin @($null,'','*') -or
                $guardRule.InterfaceTypes -ne 'All' -or $guardRule.Interfaces) {
                throw 'Firewall rule is missing or does not enforce the expected boundary'
            }
        }
    }
    [pscustomobject]@{ok=$true;protected_programs=$guardPrograms.Count;scope='Non-loopback IPv4 and IPv6 blocked'} | ConvertTo-Json -Compress
    exit 0
} catch {
    [pscustomobject]@{ok=$false;error='Claude firewall protection is missing, disabled, changed, or does not cover a new executable.'} | ConvertTo-Json -Compress
    exit 1
}
