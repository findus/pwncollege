#!/usr/bin/env python3
from pwn import *
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
#f.touch()
f.write_text('import subprocess; subprocess.run(["/challenge/embryoio_level25", "wtqojprjjr"])')
p = s.process(['/usr/bin/python3', '/tmp/my_script.py'], env={'dllbhc': 'kmafnbxpyo'})
#p.sendline('dremewyh')
r = p.clean(timeout=2)
result=repr(r)
print(result)

