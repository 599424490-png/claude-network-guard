param([switch]$Watch)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'firewall-common.ps1')
$guardPolicy = New-Object -ComObject HNetCfg.FwPolicy2

function Test-GuardFirewall {
    try {
        foreach ($guardProfile in @(1,2,4)) {
            if (-not $guardPolicy.FirewallEnabled($guardProfile)) {
                return [pscustomobject]@{ok=$false;code='profile_disabled'}
            }
        }
        if ($guardPolicy.LocalPolicyModifyState -eq 1) {
            return [pscustomobject]@{ok=$false;code='policy_overridden'}
        }
        $guardSelfTestPath = Join-Path $PSScriptRoot 'firewall-network-self-test.json'
        if (-not (Test-Path -LiteralPath $guardSelfTestPath -PathType Leaf)) {
            return [pscustomobject]@{ok=$false;code='self_test_missing'}
        }
        $guardSelfTest = Get-Content -LiteralPath $guardSelfTestPath -Raw | ConvertFrom-Json
        if ($guardSelfTest.ok -ne $true) {
            return [pscustomobject]@{ok=$false;code='self_test_failed'}
        }
        $guardExpectedAddresses = Normalize-GuardAddresses ($GuardBlockedAddresses -join ',')
        # COM's Rules.Item indexes DisplayName; match application/direction.
        $guardEffectiveRules = @($guardPolicy.Rules | Where-Object { $_.Grouping -eq $GuardFirewallGroup })
        $guardPrograms = @(Get-GuardPrograms)
        foreach ($guardProgram in $guardPrograms) {
            foreach ($guardDirection in @('Out','In')) {
                $guardExpectedDirection = if ($guardDirection -eq 'Out') { 2 } else { 1 }
                $guardMatchingRules = @($guardEffectiveRules | Where-Object { $_.ApplicationName -and $_.ApplicationName.Equals($guardProgram,[StringComparison]::OrdinalIgnoreCase) -and $_.Direction -eq $guardExpectedDirection })
                if ($guardMatchingRules.Count -ne 1) {
                    return [pscustomobject]@{ok=$false;code='rule_missing'}
                }
                $guardRule = $guardMatchingRules[0]
                if (-not $guardRule.Enabled -or $guardRule.Action -ne 0 -or $guardRule.Direction -ne $guardExpectedDirection -or
                    ($guardRule.Profiles -band 7) -ne 7 -or $guardRule.Protocol -ne 256 -or
                    -not $guardRule.ApplicationName.Equals($guardProgram,[StringComparison]::OrdinalIgnoreCase) -or
                    (Normalize-GuardAddresses $guardRule.RemoteAddresses) -ne $guardExpectedAddresses -or
                    $guardRule.LocalAddresses -ne '*' -or $guardRule.ServiceName -notin @($null,'','*') -or
                    $guardRule.InterfaceTypes -ne 'All' -or $guardRule.Interfaces) {
                    return [pscustomobject]@{ok=$false;code='rule_invalid'}
                }
            }
        }
        return [pscustomobject]@{ok=$true;protected_programs=$guardPrograms.Count;scope='Non-loopback IPv4 and IPv6 blocked'}
    } catch {
        # Query errors do not prove the policy is disabled; omit raw exceptions.
        return [pscustomobject]@{ok=$false;code='checker_exception';error_category=$_.Exception.GetType().FullName}
    }
}

do {
    $guardResult = Test-GuardFirewall
    $guardJson = $guardResult | ConvertTo-Json -Compress
    if (-not $Watch) {
        # The installer captures PowerShell pipeline output. Console.WriteLine
        # bypasses that pipeline and incorrectly reports a failed installation.
        Write-Output $guardJson
        if ($guardResult.ok) { exit 0 } else { exit 1 }
    }
    [Console]::WriteLine($guardJson)
    [Console]::Out.Flush()
    [Threading.Thread]::Sleep(1000)
} while ($true)
