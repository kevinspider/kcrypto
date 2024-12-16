import struct

# debug T 表
# 生成规则很简单
"""
Tj = {
        0x79cc4519 0 ≤ j ≤ 15
        0x7a879d8a 16 ≤ j ≤ 63
    } 
"""
T = [
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
]


# debug 计算部分

def rol32(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def ff(x, y, z, index):
    if 0 <= index <= 15:
        return x ^ y ^ z
    elif 16 <= index <= 63:
        return (x & y) | (x & z) | (y & z)


def gg(x, y, z, index):
    if 0 <= index <= 15:
        return x ^ y ^ z
    elif 16 <= index <= 63:
        return (x & y) | (~x & z)


def p0(x):
    return x ^ rol32(x, 9) ^ rol32(x, 17)


def p1(x):
    # P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)
    return x ^ rol32(x, 15) ^ rol32(x, 23)


def pad_message(message: bytes) -> bytes:
    original_bit_len = len(message) * 8
    message += b'\x80'
    while (len(message) + 8) % 64:
        message += b'\x00'
    message += struct.pack(">Q", original_bit_len)
    return message


def ksm3(message: bytes) -> str:
    # 初始化IV
    h0 = 0x7380166F
    h1 = 0x4914B2B9
    h2 = 0x172442D7
    h3 = 0xDA8A0600
    h4 = 0xA96F30BC
    h5 = 0x163138AA
    h6 = 0xE38DEE4D
    h7 = 0xB0FB0E4E

    # 填充
    message = pad_message(message)

    # 拆分, 64个字节一组
    chunks = [message[i: i + 64] for i in range(0, len(message), 64)]

    # 运算部分
    for chunk in chunks:
        # 扩展
        # debug W 和 W' 生成
        W = [0] * 68
        W_ = [0] * 64

        # W[0:16] 明文4个字节16个 并使用大端排序
        W[0:16] = struct.unpack(">16I", chunk)
        # W[16:68]
        for i in range(16, 68):
            W[i] = p1(W[i - 16] ^ W[i - 9] ^ rol32(W[i - 3], 15)) ^ rol32(W[i - 13], 7) ^ W[i - 6]

        # W_[0:64]
        for i in range(64):
            W_[i] = W[i] ^ W[i + 4]

        # a-h 为4字节寄存器
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # debug 主循环 64轮
        for j in range(64):
            # debug 中间变量ss1,ss2,tt1,tt2
            # SS1 ← ((A ≪ 12) + E + (Tj ≪ j)) ≪ 7 debug 这里的j会超过32bit 算法文档中没有 %32 实际需要
            ss1 = rol32(rol32(a, 12) + e + rol32(T[j], j % 32) & 0xFFFFFFFF, 7)
            # SS2 ← SS1 ⊕ (A ≪ 12)
            ss2 = ss1 ^ rol32(a, 12)
            # TT1 ← FF(A, B, C, j) + D + SS2 + W′[j]
            tt1 = ff(a, b, c, j) + d + ss2 + W_[j] & 0xFFFFFFFF
            # TT2 ← GG(E, F, G, j) + H + SS1 + Wj
            tt2 = gg(e, f, g, j) + h + ss1 + W[j] & 0xFFFFFFFF
            # D ← C
            d = c
            # C ← B ≪ 9
            c = rol32(b, 9)
            # B ← A
            b = a
            # A ← TT1
            a = tt1
            # H ← G
            h = g
            # G ← F ≪ 19
            g = rol32(f, 19)
            # F ← E
            f = e
            # E ← P0(TT2)
            e = p0(tt2)

        # debug 一个分组长度计算完成后, 更新结果 作为下一次循环的入参
        h0 = (a ^ h0) & 0xFFFFFFFF
        h1 = (b ^ h1) & 0xFFFFFFFF
        h2 = (c ^ h2) & 0xFFFFFFFF
        h3 = (d ^ h3) & 0xFFFFFFFF
        h4 = (e ^ h4) & 0xFFFFFFFF
        h5 = (f ^ h5) & 0xFFFFFFFF
        h6 = (g ^ h6) & 0xFFFFFFFF
        h7 = (h ^ h7) & 0xFFFFFFFF

    sm3_result = struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)
    return sm3_result.hex()


if __name__ == '__main__':
    inputValue = "kevinSpider"
    result = ksm3(inputValue.encode("utf-8"))
    print(result)
