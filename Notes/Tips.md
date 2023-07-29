### Stablize Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'

ctrl+z

stty raw -echo;fg
```
