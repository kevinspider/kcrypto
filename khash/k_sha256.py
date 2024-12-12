import struct

# K 表 64 个
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


# 计算部分
# 循环右移
def ror32(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def pad_message(message: bytes) -> bytes:
    original_bit_len = len(message) * 8
    message += b"\x80"
    while (len(message) + 8) % 64 != 0:
        message += b"\x00"
    # 添加8个字节,大端排序,填充输入明文的bit长度
    message += struct.pack(">Q", original_bit_len)
    return message


def ksha256(message: bytes) -> str:
    # sha1 魔数部分
    h0 = 0x6A09E667
    h1 = 0xBB67AE85
    h2 = 0x3C6EF372
    h3 = 0xA54FF53A
    h4 = 0x510E527F
    h5 = 0x9B05688C
    h6 = 0x1F83D9AB
    h7 = 0x5BE0CD19

    # 第一步, 进行填充
    message = pad_message(message)

    # 分组长度为 64 字节 每个chunk; chunks = [chunk0, chunk2...]
    chunks = [message[i: i + 64] for i in range(0, len(message), 64)]

    # 第二步, 处理每个分组
    for chunk in chunks:
        # 待扩展的表, 64个 W表
        W = [0] * 64
        # debug w[0:16] chunk 64字节转为16个4字节, 大端排序
        W[0:16] = struct.unpack(">16I", chunk)
        # debug w[16:64] 需要计算
        for i in range(16, 64):
            s0 = ror32(W[i - 15], 7) ^ ror32(W[i - 15], 18) ^ (W[i - 15] >> 3)
            s1 = ror32(W[i - 2], 17) ^ ror32(W[i - 2], 19) ^ (W[i - 2] >> 10)
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF
        # 到这里W表也是64个

        # 初始化缓冲区
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # 64轮主循环
        for i in range(64):
            # debug sha256 64 轮一样的计算
            # use e
            s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)
            # use e f g
            ch = (e & f) ^ (~e & g)
            # use h and K table
            temp1 = (h + s1 + ch + K[i] + W[i]) & 0xFFFFFFFF
            # use a
            s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)
            # use a b c
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

        # h中保存了每次计算每个分组的结果 缓冲区
        print("sha256 update", struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7).hex())

    sha256_result = struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)
    return sha256_result.hex()

if __name__ == "__main__":
    inputValue = "kevinSpider"
    result = ksha256(inputValue.encode("utf-8"))
    print(result)
