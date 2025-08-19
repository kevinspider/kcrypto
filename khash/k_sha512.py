import struct

# 80 个常量值
K = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
]


# debug 8 字节 64bit 的循环右移
# 旋转与移位操作
def right_rotate(value, shift, size=64):
    return ((value>> shift) | (value << (size - shift))) & ((1 << size) - 1)


# 消息填充
def pad_message(message: bytes):
    original_bit_len = len(message) * 8
    message += b"\x80"  # add 0x80
    # debug sha512 分组长度 128 字节, 末尾 16 字节填充长度
    while (len(message) + 16) % 128 != 0:
        message += b"\x00"
    # debug sha512 尾端填充的 bit 长度使用大端排序, 而且是 16 个字节
    # message += struct.pack(">Q", 0) + struct.pack(">Q", original_bit_len)
    message += original_bit_len.to_bytes(16, "big")
    return message


# 主函数
def ksha512(message: bytes):
    # sha512 IV
    # 初始哈希值（SHA-512）
    h0 = 0x6A09E667F3BCC908
    h1 = 0xBB67AE8584CAA73B
    h2 = 0x3C6EF372FE94F82B
    h3 = 0xA54FF53A5F1D36F1
    h4 = 0x510E527FADE682D1
    h5 = 0x9B05688C2B3E6C1F
    h6 = 0x1F83D9ABFB41BD6B
    h7 = 0x5BE0CD19137E2179

    # 第一步, 填充
    message = pad_message(message)

    # debug 分组, 分组长度 128 字节
    blocks = [message[i : i + 128] for i in range(0, len(message), 128)]

    for block in blocks:
        # 扩展
        W = [0] * 80

        # W[0:16] 16 个 8 字节大端排序一组数组 block
        W[0:16] = struct.unpack(">16Q", block)

        # W[16:80] 计算得到的扩展
        for i in range(16, 80):
            s0 = (
                right_rotate(W[i - 15], 1)
                ^ right_rotate(W[i - 15], 8)
                ^ (W[i - 15] >> 7)
            )
            s1 = (
                right_rotate(W[i - 2], 19)
                ^ right_rotate(W[i - 2], 61)
                ^ (W[i - 2] >> 6)
            )
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF

        # 缓存
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(80):
            S1 = right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41)
            ch = (e & f) ^ (~e & g)
            # debug 作为定位点; 可以通过 K[0] 定位找到 sha512 的输入参数;
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFFFFFFFFFF

            S0 = right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFFFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

        # debug 保留 8 个字节
        h0 = (h0 + a) & 0xFFFFFFFFFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFFFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFFFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFFFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFFFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFFFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFFFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFFFFFFFFFF

    sha512_result = struct.pack(">8Q", h0, h1, h2, h3, h4, h5, h6, h7)
    return sha512_result.hex()


if __name__ == "__main__":

    print(ksha512("kevinSpider1".encode("utf-8")))
