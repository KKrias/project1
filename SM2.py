import random

from SM3 import SM3

def gcd(a,b):
    while a!=0:
        a,b=b%a,a
    return b
def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1,u2,u3 = 1, 0, a
    v1,v2,v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m
def chr_xor(a,b):
    return hex(int(a,16)^int(b,16))[2:]
def zero_fill(a,n):
    if len(a)<n:
        a="0"*(n-len(a))+a
    return a
def KDF(Z,klen,v):
    ct=1
    k=''
    flenth = klen // v
    for i in range(flenth):
        k+=SM3(Z+zero_fill(hex(ct)[2:],8))   #32位bit ct,,十六进制下为8位
        ct+=1
    if flenth<klen / v:
        k+=SM3(Z+zero_fill(hex(ct)[2:],8))[:int((klen-(v*flenth))/4)]
    return k
def chr_to_int(chr):
    return int(chr,16)
def ecc_same_add(ecc,G):#自身加自身
    x1=chr_to_int(G[0])
    y1 = chr_to_int(G[1])
    a=chr_to_int(ecc[0])
    b=chr_to_int(ecc[1])
    p=chr_to_int(ecc[2])
    tmp1 = 3 * x1 * x1 + a
    tmp2 = findModInverse(2 * y1,p)
    k = (tmp1 * tmp2) % p
    x3 = (k * k - x1 - x1) % p
    y3 = (k * (x1 - x3) - y1) % p
    return [hex(x3)[2:], hex(y3)[2:]]
def ecc_diff_add(ecc, G1, G2):#不同坐标点相加
    x1 = chr_to_int(G1[0])
    y1 = chr_to_int(G1[1])
    x2 = chr_to_int(G2[0])
    y2 = chr_to_int(G2[1])
    p=chr_to_int(ecc[-1])
    tmp1 = y2 - y1
    tmp2 = findModInverse((x2 - x1) % p, p)
    k = tmp1 * tmp2 % p
    x3 = (k * k - x1 - x2) % p
    y3 = (k * (x1 - x3) - y1) % p
    return [hex(x3)[2:], hex(y3)[2:]]
def ecc_diff_add_near(ecc, pointbase, G1):#和比自己大1的点相加
    return ecc_diff_add(ecc,pointbase, ecc_same_add(ecc,G1))
def ecc_multiply(ecc, k, G):#椭圆曲线乘法
    k1=chr_to_int(k)
    if k1 == 2:
        return ecc_same_add(ecc,G)
    if k1 == 3:
        return ecc_diff_add(ecc,G,ecc_same_add(ecc,G))
    if k1 % 2 == 0:
        return ecc_same_add( ecc,ecc_multiply(ecc,hex(k1 // 2)[2:], G))
    if k1 % 2 == 1:
        return ecc_diff_add_near(ecc,G,ecc_multiply(ecc,hex(k1 // 2)[2:], G))

def SM2_encrypt(ecc,G,n,plaintext):
    klen=len(plaintext)*4
    # k=random.randint(1,n-1)
    k = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"  #该k值为官方文档给出的实例,应用时取上面的随机数
    pB=ecc_multiply(ecc,dB,G)
    C1=ecc_multiply(ecc,k,G)
    temp=ecc_multiply(ecc,k,pB)
          #使用的SM3  hash,输出为256bit
    t=KDF(temp[0]+temp[1],klen,v)
    C2=chr_xor(plaintext,t)
    C3=SM3(temp[0]+plaintext+temp[1])
    C1="04"+C1[0]+C1[1]
    C=C1+C2+C3
    return C
def ecc_point_true(ecc,point):
    a=chr_to_int(ecc[0])
    b=chr_to_int(ecc[1])
    p=chr_to_int(ecc[2])
    x = chr_to_int(point[0])
    y = chr_to_int(point[1])
    if (y*y)%p == (x*x*x +a*x +b )%p:
        return True
    else:
        return False
def SM2_decrypt(ecc,cipher,privatrkey,klen):
    clen=len(cipher)
    C1=cipher[:130]
    C1=[C1[2:66],C1[66:]]
    if not ecc_point_true(ecc,C1):
        print("c1不对")
        return False
    temp=ecc_multiply(ecc,privatrkey,C1)
    t=KDF(temp[0]+temp[1],klen,v)
    #print("t:",t)
    if chr_to_int(t)==0:
        print("全0串")
        return False
    C2=cipher[130:clen-v//4]
    #print("C2",C2)
    C3=cipher[-v//4:]
    M=chr_xor(C2,t)
    #print(temp)
    u=SM3(temp[0]+M+temp[1])
    if u==C3:
        return M

Gx="421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
Gy="0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
n="8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
k="4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
a="787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
b="63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
p="8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"     #模数
dB="1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"    #私钥
pB=['435b39cca8f3b508c1488afc67be491a0f7ba07e581a0e4849a5cf70628a7e0a','75ddba78f15feecb4c7895e2c1cdf5fe01debb2cdbadf45399ccf77bba076a42']
v=256
ecc=[a,b,p]
G=[Gx,Gy]

plaintext="656E6372797074696F6E207374616E64617264"
cipher="04245c26fb68b1ddddb12c4b6bf9f2b6d5fe60a383b0d18d1c4144abf17f6252e776cb9264c2a7e88e52b19903fdc47378f605e36811f5c07423a24b84400f01b8650053a89b41c418b0c3aad00d886c002864679c3d7360c30156fab7c80a0276712da9d8094a634b766d3a285e07480653426d"

klen=len(plaintext)*4
if SM2_decrypt(ecc, cipher, dB, klen).upper()==plaintext.upper():
    print(SM2_decrypt(ecc, cipher, dB, klen).upper())
    print("解密成功")
else:
    print("失败")





