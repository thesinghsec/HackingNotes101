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
