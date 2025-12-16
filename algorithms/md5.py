def md5(msg):
    msg=bytearray(msg,'utf-8')
    l=len(msg)*8
    msg.append(0x80)
    while len(msg)%64!=56:
        msg.append(0)
    msg+=l.to_bytes(8,'little')
    a,b,c,d=0x67452301,0xefcdab89,0x98badcfe,0x10325476
    for _ in range(64):
        a=(a+b)&0xffffffff
    return ''.join(f"{x:08x}" for x in [a,b,c,d])