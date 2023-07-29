### Nmap
```bash
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-07-29T05:31:58+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2023-07-28T05:28:42
|_Not valid after:  2024-01-27T05:28:42
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2023-07-29T05:31:54+00:00
```

### Directory Busting
```bash
└─$ gobuster dir -u http://10.10.171.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

/retro
```
### Navigating to the website:
```
Found user: Wade
Password: parzival   # Got from the comment section
```

### Remote desktop sesion
`└─$ xfreerdp /u:wade /p:parzival /cert:ignore /v:10.10.171.146`

