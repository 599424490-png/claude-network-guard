$GuardFirewallGroup = 'Claude Network Guard'
$GuardBlockedAddresses = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
function Get-GuardPrograms {
    $guardProgramRoots = @(
        (Join-Path $env:LOCALAPPDATA 'AnthropicClaude'),
        (Join-Path $env:APPDATA 'Claude\claude-code'),
        (Join-Path $env:USERPROFILE '.local\share\claude')
    )
    $guardPrograms = @()
    foreach ($guardProgramRoot in $guardProgramRoots) {
        if (Test-Path -LiteralPath $guardProgramRoot) {
            $guardPrograms += @(Get-ChildItem -LiteralPath $guardProgramRoot -File -Filter '*.exe' -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName)
        }
    }
    if ($guardPrograms.Count -eq 0) { throw 'No Claude executables found' }
    return @($guardPrograms | Sort-Object -Unique)
}
function Get-GuardRuleName([string]$Program, [string]$Direction) {
    $guardHasher = [Security.Cryptography.SHA256]::Create()
    try { $guardHash = [BitConverter]::ToString($guardHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Program.ToLowerInvariant()))).Replace('-','').Substring(0,20) }
    finally { $guardHasher.Dispose() }
    return ('ClaudeProxyOnly-' + $Direction + '-' + $guardHash)
}
function Normalize-GuardAddresses([string]$Addresses) {
    $guardNormalized = foreach ($guardPart in $Addresses.Split(',')) {
        $guardRange = $guardPart.Trim().Split('-')
        if ($guardRange.Count -ne 2) { throw 'Unexpected firewall address filter' }
        ([Net.IPAddress]::Parse($guardRange[0]).ToString() + '-' + [Net.IPAddress]::Parse($guardRange[1]).ToString()).ToLowerInvariant()
    }
    return (@($guardNormalized | Sort-Object) -join ',')
}
