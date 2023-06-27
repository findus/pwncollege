#!/usr/bin/env python3
from pwn import *
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run(["/challenge/embryoio_level26", "lgwuuobv"])')

f2 = SSHPath('/tmp/nrzqjx', ssh=s)
f2.touch()
f2.write_text('lgwuuobv')
p = s.process(['/usr/bin/python3', '/tmp/my_script.py'], env={'dllbhc': 'kmafnbxpyo'}, stdin="/tmp/nrzqjx")
#p.sendline('dremewyh')
r = p.clean(timeout=2)
result=repr(r)
print(result)

