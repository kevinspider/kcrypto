"""
rc4
类别: 对称加密算法
密钥长度: 可变, 一般是 40bit 到 2048bit
加密方式: 流加密 (逐位加密)

rc4 的加密和解密是同一个函数, 输入是明文得到的就是密文, 输入是密文, 得到的就是解密后的内容
"""


def krc4(message: bytes, key: bytes):
    # 初始化S盒 0-255 [0x0,0x1,...0xff]
    S: list[int] = list(range(256))

    # debug 打乱S盒
    # debug 这里打乱S盒只和输入的key的长度以及内容有关系, 相同的key生成的S相同
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    # print("S first value", [(hex(each)) for each in S])

    # 计算结果
    rc4_result = bytes()
    i = 0
    j = 0
    for each in message:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        # debug 循环中会再次打乱S盒
        S[i], S[j] = S[j], S[i]
        # debug 最终计算出和长度相关的k值, 这个值只和输入的key长度和内容相关, 相同的key得到的k相同
        k = S[(S[i] + S[j]) % 256]
        # print("k=", hex(k))
        # 输入明文的每个字节和 k 进行异或操作
        rc4_result += (each ^ k).to_bytes(1, "big")
    return rc4_result.hex()


if __name__ == "__main__":
    # 加密
    message = "kevinSpider".encode("utf-8")
    key = bytes.fromhex("aabbccddeeff")
    result = krc4(message, key)
    print(result)

    # 解密
    message = bytes.fromhex("d167aac3d6e3428a989b05")
    key = bytes.fromhex("aabbccddeeff")
    result = krc4(message, key)
    print(result, bytes.fromhex(result).decode("utf-8"))
