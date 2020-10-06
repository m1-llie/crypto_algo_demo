import random
import math
import sys, getopt


# 生成十进制密钥值（包括公钥和私钥，n、e、d）
def create_keys():
    p = create_prime_num()
    q = create_prime_num()
    n = p * q
    fn = (p - 1)*(q - 1)  # 欧拉函数值
    e = selectE(fn)
    d = match_d(e, fn)

    # 转成十六进制形式后写入文件
    open("p.txt", "w+").write(dec2hex(p))
    open("q.txt", "w+").write(dec2hex(q))
    open("n.txt", "w+").write(dec2hex(n))
    open("e.txt", "w+").write(dec2hex(e))
    open("d.txt", "w+").write(dec2hex(d))

    print("p："+str(p))
    print("q：" + str(q))
    print("n：" + str(n))
    print("e：" + str(e))
    print("d：" + str(d))
    return n, e, d


# 生成一个大素数
def create_prime_num():
    while True:
        n = random.randint(10**10, 10**11)
        if n % 2 != 0:
            found = True
            # 如果经过10次素性检测，那么很大概率上，这个数就是素数
            for i in range(0, 10):
                if miller_rabin_test(n):
                    pass
                else:
                    found = False
                    break
            if found:
                return n


# 针对随机取得的p，q两个数的素性检测
def miller_rabin_test(n):  # p为要检验的数
    p = n - 1
    r = 0
    # Miller-Rabin素性检验原理见PPT
    # 寻找满足n-1 = 2^s  * m 的s,m两个数
    #  n -1 = 2^r * p
    while p % 2 == 0:  # 最后得到为奇数的p(即m)
        r += 1
        p /= 2
    b = random.randint(2, n - 2)  # 随机取b=（0.n）
    # 如果情况1    b得p次方  与1  同余  mod n
    if fastExpMod(b, int(p), n) == 1:
        return True  # 通过测试,可能为素数
    # 情况2  b得（2^r  *p）次方  与-1 (n-1) 同余  mod n
    for i in range(0, 7):  # 检验六次
        if fastExpMod(b, (2 ** i) * p, n) == n - 1:
            return True  # 该数很大可能为素数
    return False  # 不可能是素数


# 选择e，要求e<fn且(e,fn)=1
def selectE(fn):
    while True:
        e = random.randint(0, fn)
        if math.gcd(e, fn) == 1:
            return e


# # 根据选择的e，匹配出唯一的d
# def match_d(e, fn):
#     d = 0
#     while True:
#         if (e * d) % fn == 1:
#             return d
#         d += 1

# 根据选择的e，匹配出唯一的d
def match_d(e, fn):
    if gcd(e, fn) != 1:
        return None
    u1, u2, u3 = 1, 0, e
    v1, v2, v3 = 0, 1, fn
    while v3 != 0:
        x = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - x * v1), (u2 - x * v2), (u3 - x * v3), v1, v2, v3
    return u1 % m


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


# 模N大数的幂乘的快速算法，result = b^e(mod m)
def fastExpMod(b, e, m):  # 底数，幂，大数N
    result = 1
    e = int(e)
    while e != 0:
        if e % 2 != 0:  # 按位与
            e -= 1
            result = (result * b) % m
            continue
        e >>= 1
        b = (b * b) % m
    return result


# 十进制数值转对应十六进制字符串形式
def dec2hex(num):
    base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]
    l = []
    if num < 0:
        return '-' + dec2hex(abs(num))
    while True:
        num, rem = divmod(num, 16)
        l.append(base[rem])
        if num == 0:
            return ''.join(l[::-1])


# 十六进制字符串形式转十进制数值
def hex2dec(str):
    return int(str, 16)


# 主功能函数
def main(argv):
    # 得到命令行中给定的rsa_plain.txt和rsa_cipher.txt
    plainfile = ""
    cfile = ""
    try:
        opts, args = getopt.getopt(argv, "p:c:", ["filep=", "filec="])
    except getopt.GetoptError:
        print("RSA.py -p plainfile -c cipherfile")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-p", "--filep"):
            plainfile = arg
        elif opt in ("-c", "--filec"):
            cfile = arg
    # print(plainfile)
    # print(cfile)

    # 准备好加密运算用到的各个十进制数
    plaintext = open(plainfile, 'r+').read()
    print("原明文（十六进制）："+plaintext)
    plain = hex2dec(plaintext)  # 明文的十进制
    # 生成随机公钥和私钥，新建了p/q/n/e/d.txt五个文件
    n, e, d = create_keys()
    # 现在plain,n,e,d都在内存中了

    # 数据加密
    resultDec_E = fastExpMod(plain, e, n)  # 数据加密的十进制
    print("数据加密后（十进制）：" + str(resultDec_E))
    resultHex_E = dec2hex(resultDec_E)  # 数据加密的十六进制字符串
    print("数据加密后（十六进制）：" + str(resultHex_E))
    open(cfile, 'r+').write(resultHex_E)  # 写入文件
    print("Already written to " + cfile)

    # 数据解密
    resultDec_D = fastExpMod(resultDec_E, d, n)  # 解密得原明文的十进制
    resultHex_D = dec2hex(resultDec_D)  # 得原明文的十六进制字符串
    print("反向解密（十六进制）：" + str(resultHex_D))


if __name__ == "__main__":
   main(sys.argv[1:])







