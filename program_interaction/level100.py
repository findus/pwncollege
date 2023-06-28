#!/usr/bin/env python3
from pwn import *
import re
    
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run("/challenge/embryoio_level100")')
p = s.process(['python', '/tmp/my_script.py'])
r = p.recvlines(18)

def solveChallenge(r):
    number=re.search(r'\[TEST\] CHALLENGE! Please send the solution for: (.*)', repr(r))
    if(number is None):
        print(r)
        if("pwn.college{" in repr(r)):
           exit(0)
        solveChallenge(p.readline())
    number=number.group(1)
    number=number[:-1]
    print(number)
    print(eval(number.replace("\\n",'')))
    p.sendline(str(eval(number.replace("\\n",''))))
    print(p.readline())
    r=p.readline()
    print(r)
    solveChallenge(r)

print(r[-1])
print(repr(r[-1]))
solveChallenge(r[-1])

