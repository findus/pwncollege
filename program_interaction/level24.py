#!/usr/bin/env python3
from pwn import *
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
#f.touch()
f.write_text('import subprocess; subprocess.run(["/challenge/embryoio_level24", "wtqojprjjr"])')
p = s.process(['python3', '/tmp/my_script.py'])
p.sendline('dremewyh')
r = p.clean(timeout=2)
result=repr(r)
print(result)

