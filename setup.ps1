$ErrorActionPreference = 'Stop'
$guardPython = & py -3 -c 'import sys; assert sys.version_info >= (3, 11); print(sys.executable)'
if ($LASTEXITCODE -ne 0 -or -not $guardPython) { throw 'Install Python 3.11 or newer with the py launcher.' }
& $guardPython -c 'import yaml'
if ($LASTEXITCODE -ne 0) { throw 'First run: py -3 -m pip install -r requirements.txt' }
$guardPythonw = Join-Path (Split-Path $guardPython -Parent) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $guardPythonw)) { throw 'pythonw.exe is required.' }
$guardConfig = Join-Path $PSScriptRoot 'guard-config.json'
if (-not (Test-Path -LiteralPath $guardConfig)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guard-config.example.json') -Destination $guardConfig
}
& (Join-Path $PSScriptRoot 'build-probe.ps1')
if (-not $?) { throw 'Probe build failed.' }
$guardInstaller = Join-Path $PSScriptRoot 'install-firewall.ps1'
$guardAdmin = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $guardInstaller + '"')
if ($guardAdmin.ExitCode -ne 0) { throw 'Firewall installation failed. See firewall-install-result.json.' }
$guardReport = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'firewall-install-result.json') -Raw | ConvertFrom-Json
if (-not $guardReport.ok) { throw 'Firewall verification failed. See firewall-install-result.json.' }
$guardSettings = Get-Content -LiteralPath $guardConfig -Raw | ConvertFrom-Json
$guardShell = New-Object -ComObject WScript.Shell
$guardShortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Claude (Network Guard).lnk'
$guardShortcut = $guardShell.CreateShortcut($guardShortcutPath)
$guardShortcut.TargetPath = $guardPythonw
$guardShortcut.Arguments = '"' + (Join-Path $PSScriptRoot 'claude-guard.pyw') + '"'
$guardShortcut.WorkingDirectory = $PSScriptRoot
$guardShortcut.Description = 'Launch Claude with proxy checks and firewall protection'
$guardShortcut.IconLocation = [Environment]::ExpandEnvironmentVariables($guardSettings.claude_executable) + ',0'
$guardShortcut.Save()
Write-Output ('Installed. Launch using: ' + $guardShortcutPath)
