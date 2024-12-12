import struct


# 计算部分
def rol32(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def pad_message(message: bytes) -> bytes:
    # 计算 bit 长度; bytes len * 8
    original_bit_len = len(message) * 8
    message += b"\x80"
    # 判断是否满足增加8字节长度后是64字节的整数倍
    while (len(message) + 8) % 64 != 0:
        message += b"\x00"
    # debug 填充完成后, 尾部也要填充长度, sha1 长度填充采用的是大端序;
    # message += struct.pack(">Q", original_bit_len)
    message += original_bit_len.to_bytes(8, "big")
    return message


def ksha1(message: bytes) -> str:
    # sha1 魔数部分
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0  # debug 这个是sha1独有的, 其他的和md5一样

    # 第一步, 进行填充
    message = pad_message(message)

    # sha1 分组长度64字节, 将填充后的进行64字节分组
    chunks = [message[i: i + 64] for i in range(0, len(message), 64)]

    # 第二步, 处理每个 64字节分组
    for chunk in chunks:
        # 待扩展的表w 80个, 每个元素4字节
        w = [0] * 80
        # 将64字节转为16个4字节, 并使用大端序排列

        # debug w[0:16] 赋值 这里的 w[0:16] 是将一个chunk 64字节打包进去
        w[0:16] = struct.unpack(">16I", chunk)
        # for i in range(16):
        #     w[i] = int.from_bytes(chunk[4 * i: 4 * i + 4], "big")

        # w[16:80] 扩展
        for i in range(16, 80):
            w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        # 初始化缓冲区
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # 80轮主循环
        for i in range(80):
            # debug sha1 每20轮是一样的计算
            if 0 <= i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            else:
                raise

            temp = (rol32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = rol32(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

        print("sha1 update", struct.pack(">5I", h0, h1, h2, h3, h4).hex())

    sha1_result = struct.pack(">5I", h0, h1, h2, h3, h4)
    return sha1_result.hex()

if __name__ == "__main__":
    result = ksha1("kevinSpider".encode("utf-8"))
    print("debug", result)
