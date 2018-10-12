#!/usr/bin/python2

from hashlib import sha512
import sys

def verify(x, chalbox):
    length, gates, check = chalbox
    b = [(x >> i) & 1 for i in range(length)]
    for name, args in gates:
        if name == 'true':
            b.append(1)
        else:
            u1 = b[args[0][0]] ^ args[0][1]
            u2 = b[args[1][0]] ^ args[1][1]
            if name == 'or':
                b.append(u1 | u2)
                print("s.add(Or(Xor(b[" + str(args[0][0]) + "] , " + str(args[0][1]) + ") , Xor(b[" + str(args[1][0]) + "] , " + str(args[1][1]) + ")) ==b[" + str(len(b)-1) + "])" )
            elif name == 'xor':
                b.append(u1 ^ u2)
                print("s.add(Xor(Xor(b[" + str(args[0][0]) + "] , " + str(args[0][1]) + ") , Xor(b[" + str(args[1][0]) + "] , " + str(args[1][1]) + ")) ==b[" + str(len(b)-1) + "])" )
    print("s.add(Xor(b[" + str(check[0]) + "] , " + str(check[1]) + ") == True)" )
    return b[check[0]] ^ check[1]


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage: ' + sys.argv[0] + ' <key> <map.txt>'
        print 'Example: Try Running ' + sys.argv[0] + ' 11443513758266689915 map1.txt'
        exit(1)
    with open(sys.argv[2], 'r') as f:
        cipher, chalbox = eval(f.read())

    key = int(sys.argv[1]) % (1 << chalbox[0])
    print(cipher)
    print 'Attempting to decrypt ' + sys.argv[2] + '...'
    if verify(key, chalbox):
        print("oh nice!")
    else:
        print("try again!")
