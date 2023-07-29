### Stablize Shell

```
# In order to make a stable shell we need to run:

python -c 'import pty; pty.spawn("/bin/bash")'

# Background the active shell using ctrl+z and use cmds

stty raw -echo
fg

www-data@40ad97ed7351:/var/www/admin$ whoami
whoami
www-data
```
