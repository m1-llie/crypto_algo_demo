import random
import math
import sys, getopt


# 模N大数的幂乘的快速算法
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
    # 得到命令行中给定的五个文件名
    plainfile = ""
    #efile = ""
    dfile = ""
    nfile = ""
    cfile = ""
    try:
        opts, args = getopt.getopt(argv, "p:n:d:c:", ["filep=", "filen=", "filed=", "filec="])
    except getopt.GetoptError:
        print("test1.py -p plainfile -n nfile -d dfile -c cipherfile")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-p", "--filep"):
            plainfile = arg
        elif opt in ("-n", "--filen"):
            nfile = arg
        # elif opt in ("-e", "--filee"):
        #     efile = arg
        elif opt in ("-d", "--filed"):
            dfile = arg
        elif opt in ("-c", "--filec"):
            cfile = arg
    # print(plainfile)
    # print(nfile)
    # print(efile)
    # print(dfile)
    # print(cfile)

    # 准备好加密运算用到的各个十进制数
    plaintext = open(plainfile, 'r+').read()
    #etext = open(efile, 'r+').read()
    dtext = open(dfile, 'r+').read()
    ntext = open(nfile, 'r+').read()
    plain = hex2dec(plaintext)  # 明文的十进制
    #e = hex2dec(etext)  # 幂指数，取e则数据加密
    d = hex2dec(dtext)  # 幂指数，取d则数字签名
    n = hex2dec(ntext)  # n=pq

    # # 数据加密
    # resultDec_e = fastExpMod(plain, e, n)  # 数据加密的十进制
    # resultHex_e = dec2hex(resultDec_e)  # 数据加密的十六进制字符串
    # open(cfile, 'r+').write(resultHex_e)  # 写入文件
    # print("数据加密：" + str(resultHex_e))
    # print("Already written to " + cfile)

    # 数字签名
    resultDec_d = fastExpMod(plain, d, n)  # 数字签名的十进制
    resultHex_d = dec2hex(resultDec_d)  # 数字签名的十六进制字符串
    open(cfile, 'r+').write(resultHex_d)  # 写入文件
    print("数字签名：" + str(resultHex_d))
    print("Already written to " + cfile)


if __name__ == "__main__":
   main(sys.argv[1:])







