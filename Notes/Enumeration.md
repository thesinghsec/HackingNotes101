# Initial Enumeration

### Vhost discovery

**Gobuster:**
```bash
└─$ gobuster vhost -u http://<address> -w /usr/share/seclists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt
```
**WFUZZ**
```bash
wfuzz -u <URL> -w <wordlist> -H "Host: FUZZ.example.com" --hc <status codes to hide>
```

