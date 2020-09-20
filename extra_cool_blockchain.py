from pwn import *
from Crypto.Util.strxor import strxor
final_flag=''
for i in range(6):
    r=remote("chal.duc.tf",30201)
    print(r.recvline())
    ct=r.recvline()
    print(ct)
    ct=ct[64:-1].decode()
    k=0
    blocks=[bytes.fromhex(ct[j:j+32]) for j in range(0,len(ct),32)]
    ctext=[]
    for j in range(5):
        ctext.append(xor(blocks[j],blocks[j+1]))  
    pt='10'*16
    r.sendline(pt)
    final=r.recvline()
    final=final[34:-1].decode()
    iv=bytes.fromhex(final[32:])
    flag=xor(ctext[i-1],iv)
    if i==0:
        r.sendline(blocks[0].hex())
    else:
        flag=xor(ctext[i-1],iv)
        r.sendline(flag.hex())
    p_flag=r.recvline()[35:-1]
    p_flag=bytes.fromhex(p_flag.decode()).decode()
    final_flag+=p_flag
    r.recvline()
    print(final_flag)
######DUCTF{4dD1nG_r4nd0M_4rR0ws_4ND_x0RS_h3r3_4nD_th3R3_U5u4Lly_H3lps_Bu7_n0T_7H1s_t1m3_i7_s33ms!!}######

