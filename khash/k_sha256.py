import struct

# K 表 64 个
K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
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
    # 添加 8 个字节, 大端排序, 填充输入明文的 bit 长度
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

    # 分组长度为 64 字节 每个 chunk; chunks = [chunk0, chunk2...]
    chunks = [message[i : i + 64] for i in range(0, len(message), 64)]

    print("填充后, message:", message.hex())

    # 第二步, 处理每个分组
    for chunk in chunks:
        # 待扩展的表, 64 个 W 表
        W = [0] * 64
        # debug w[0:16] chunk 64 字节转为 16 个 4 字节, 大端排序
        # debug 这里的 W 头部 64 个字节是输入明文
        W[0:16] = struct.unpack(">16I", chunk)
        # debug w[16:64] 需要计算
        for i in range(16, 64):
            s0 = ror32(W[i - 15], 7) ^ ror32(W[i - 15], 18) ^ (W[i - 15] >> 3)
            s1 = ror32(W[i - 2], 17) ^ ror32(W[i - 2], 19) ^ (W[i - 2] >> 10)
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF
        # 到这里 W 表也是 64 个

        # 初始化缓冲区
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # 64 轮主循环
        for i in range(64):
            # debug sha256 64 轮一样的计算
            # use e
            s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)
            # use e f g
            ch = (e & f) ^ (~e & g)
            # use h and K table
            # 定位 sha256 入参的算法点; 通过 K[0] 找到参与运算的参数, 因为当 K[0] 使用的时候, 必定是循环的第一次, 所以此时都是定值, 排除法就可以找到明文入参;
            if i == 0:
                print(
                    f"debug sha256 start loop:{i} h:{hex(h)} s1:{hex(s1)} ch:{hex(ch)} K[{i}]={hex(K[i])} h + s1 + ch + K[{i}] = {hex(h + s1 + ch + K[i])}"
                )
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

        # h 中保存了每次计算每个分组的结果 缓冲区
        print("sha256 update", struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7).hex())

    sha256_result = struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)
    return sha256_result.hex()


if __name__ == "__main__":
    """
    0000:
    2F 72 65 73
    74 2F 6E 2F
    66 65 65 64
    2F 73 65 6C    /rest/n/feed/sel
    0010:
    65 63 74 69
    6F 6E 61 32
    64 39 63 66
    33 34 35 64    ectiona2d9cf345d
    0020:
    36 37 34 62
    37 66 38 38
    66 34 61 38
    35 33 33 66    674b7f88f4a8533f
    0030:
    32 36 31 61
    36 30 00 00
    00 00 00 00
    00 00 00 00    261a60
    """
    inputValue = bytes.fromhex(
        "406147520250646E4E6E73405F00604F59785D527C406440475C5D66005F52437B50056C65025E4264434043506E5501715B4E787553645F424E62016041547D2F726573742F6E2F666565642F73656C656374696F6E6132643963663334356436373462376638386634613835333366323631613630"
    )
    result = ksha256(inputValue)
    print(result)
    # 459ddcf09a7b3c6c0685c0feedd3e9030e35e3fbb2a06e31c4e3e0da2045e5e6

    inputValue = bytes.fromhex(
        "2A0B2D38683A0E042404192A356A0A2533123738162A0E2A2D36370C6A353829113A6F060F6834280E292A293A043F6B1B3124121F390E352824086B0A2B3E17459DDCF09A7B3C6C0685C0FEEDD3E9030E35E3FBB2A06E31C4E3E0DA2045E5E6"
    )
    result = ksha256(inputValue)
    print(result)
