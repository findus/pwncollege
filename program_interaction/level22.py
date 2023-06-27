#!/usr/bin/env python3
from pwn import *
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run("/challenge/embryoio_level22")')
p = s.process(['python3', '/tmp/my_script.py'])
r = p.recvall(timeout=10)
result=repr(r)
print(result)

