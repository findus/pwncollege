#!/usr/bin/env python3
from pwn import *
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run(["/challenge/embryoio_level28"])')

f2 = SSHPath('/tmp/nrzqjx', ssh=s)
f2.touch()
f2.write_text('lgwuuobv')
p = s.process(['/usr/bin/python3', '/tmp/my_script.py'], env={}, stdout="/tmp/fnnofu", stdin="/tmp/nrzqjx")
#p.sendline('dremewyh')
r = p.clean(timeout=2)
result=repr(r)
print(result)

