### Stablize Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'

ctrl+z

stty raw -echo;fg
```
### Port Scanning with NetCat

```bash
nc -zv <IP> 1-65535
```
