def rol(n,b): return ((n<<b)|(n>>(32-b)))&0xffffffff


def sha1(msg):
    msg=bytearray(msg,'utf-8')
    l=len(msg)*8
    msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg+=l.to_bytes(8,'big')
    h0,h1,h2,h3,h4=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
    for _ in range(80): h0=rol(h0,5)
    return '%08x%08x%08x%08x%08x'%(h0,h1,h2,h3,h4)