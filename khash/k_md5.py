import struct


# 计算函数
# 循环左移
def rol32(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def F(x, y, z):
    return (x & y) | (~x & z)


def G(x, y, z):
    return (x & z) | (y & ~z)


def H(x, y, z):
    return x ^ y ^ z


def I(x, y, z):
    return y ^ (x | ~z)


def FF(a, b, c, d, x, s, ac):
    a = (a + F(b, c, d) + x + ac) & 0xFFFFFFFF
    a = rol32(a, s)
    a = (a + b) & 0xFFFFFFFF
    return a


def GG(a, b, c, d, x, s, ac):
    a = (a + G(b, c, d) + x + ac) & 0xFFFFFFFF
    a = rol32(a, s)
    a = (a + b) & 0xFFFFFFFF
    return a


def HH(a, b, c, d, x, s, ac):
    a = (a + H(b, c, d) + x + ac) & 0xFFFFFFFF
    a = rol32(a, s)
    a = (a + b) & 0xFFFFFFFF
    return a


def II(a, b, c, d, x, s, ac):
    a = (a + I(b, c, d) + x + ac) & 0xFFFFFFFF
    a = rol32(a, s)
    a = (a + b) & 0xFFFFFFFF
    return a


# 填充
def pad_message(message: bytes) -> bytes:
    # 计算 bytes -> bit 长度
    original_bit_len = len(message) * 8
    message += b"\x80"
    # 因为尾部要增加8字节的message长度,所以计算的时候先+8
    # 64字节 * 8bit = 512bit
    while (len(message) + 8) % 64 != 0:
        message += b"\x00"
    # debug 填充完成后, 尾部增加长度, 将长度使用小端序<, Q是8字节打包, 插入message尾部
    message += original_bit_len.to_bytes(8, "little")
    # message += struct.pack("<Q", original_bit_len)
    return message


# md5 主体
def kmd5(message: bytes) -> str:

    # 魔数部分
    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    # 第一步, 进行填充
    message = pad_message(message)

    # 每次计算512bit 64字节, 每64字节一个元素
    chunks = [message[i : i + 64] for i in range(0, len(message), 64)]

    # 每次计算512bit 64字节
    for chunk in chunks:
        # 将64字节分成16份,每一份I就是四字节, 小端序
        words = struct.unpack("<16I", chunk)

        a, b, c, d = a0, b0, c0, d0

        # debug md5 64轮都是不一样的计算
        # Round1 使用的都是原始的魔数
        a = FF(a, b, c, d, words[0], 7, 0xD76AA478)
        d = FF(d, a, b, c, words[1], 12, 0xE8C7B756)
        c = FF(c, d, a, b, words[2], 17, 0x242070DB)
        b = FF(b, c, d, a, words[3], 22, 0xC1BDCEEE)
        a = FF(a, b, c, d, words[4], 7, 0xF57C0FAF)
        d = FF(d, a, b, c, words[5], 12, 0x4787C62A)
        c = FF(c, d, a, b, words[6], 17, 0xA8304613)
        b = FF(b, c, d, a, words[7], 22, 0xFD469501)
        a = FF(a, b, c, d, words[8], 7, 0x698098D8)
        d = FF(d, a, b, c, words[9], 12, 0x8B44F7AF)
        c = FF(c, d, a, b, words[10], 17, 0xFFFF5BB1)
        b = FF(b, c, d, a, words[11], 22, 0x895CD7BE)
        a = FF(a, b, c, d, words[12], 7, 0x6B901122)
        d = FF(d, a, b, c, words[13], 12, 0xFD987193)
        c = FF(c, d, a, b, words[14], 17, 0xA679438E)
        b = FF(b, c, d, a, words[15], 22, 0x49B40821)

        # Round2
        a = GG(a, b, c, d, words[1], 5, 0xF61E2562)
        d = GG(d, a, b, c, words[6], 9, 0xC040B340)
        c = GG(c, d, a, b, words[11], 14, 0x265E5A51)
        b = GG(b, c, d, a, words[0], 20, 0xE9B6C7AA)
        a = GG(a, b, c, d, words[5], 5, 0xD62F105D)
        d = GG(d, a, b, c, words[10], 9, 0x02441453)
        c = GG(c, d, a, b, words[15], 14, 0xD8A1E681)
        b = GG(b, c, d, a, words[4], 20, 0xE7D3FBC8)
        a = GG(a, b, c, d, words[9], 5, 0x21E1CDE6)
        d = GG(d, a, b, c, words[14], 9, 0xC33707D6)
        c = GG(c, d, a, b, words[3], 14, 0xF4D50D87)
        b = GG(b, c, d, a, words[8], 20, 0x455A14ED)
        a = GG(a, b, c, d, words[13], 5, 0xA9E3E905)
        d = GG(d, a, b, c, words[2], 9, 0xFCEFA3F8)
        c = GG(c, d, a, b, words[7], 14, 0x676F02D9)
        b = GG(b, c, d, a, words[12], 20, 0x8D2A4C8A)

        # Round3
        a = HH(a, b, c, d, words[5], 4, 0xFFFA3942)
        d = HH(d, a, b, c, words[8], 11, 0x8771F681)
        c = HH(c, d, a, b, words[11], 16, 0x6D9D6122)
        b = HH(b, c, d, a, words[14], 23, 0xFDE5380C)
        a = HH(a, b, c, d, words[1], 4, 0xA4BEEA44)
        d = HH(d, a, b, c, words[4], 11, 0x4BDECFA9)
        c = HH(c, d, a, b, words[7], 16, 0xF6BB4B60)
        b = HH(b, c, d, a, words[10], 23, 0xBEBFBC70)
        a = HH(a, b, c, d, words[13], 4, 0x289B7EC6)
        d = HH(d, a, b, c, words[0], 11, 0xEAA127FA)
        c = HH(c, d, a, b, words[3], 16, 0xD4EF3085)
        b = HH(b, c, d, a, words[6], 23, 0x04881D05)
        a = HH(a, b, c, d, words[9], 4, 0xD9D4D039)
        d = HH(d, a, b, c, words[12], 11, 0xE6DB99E5)
        c = HH(c, d, a, b, words[15], 16, 0x1FA27CF8)
        b = HH(b, c, d, a, words[2], 23, 0xC4AC5665)

        # Round4
        a = II(a, b, c, d, words[0], 6, 0xF4292244)
        d = II(d, a, b, c, words[7], 10, 0x432AFF97)
        c = II(c, d, a, b, words[14], 15, 0xAB9423A7)
        b = II(b, c, d, a, words[5], 21, 0xFC93A039)
        a = II(a, b, c, d, words[12], 6, 0x655B59C3)
        d = II(d, a, b, c, words[3], 10, 0x8F0CCC92)
        c = II(c, d, a, b, words[10], 15, 0xFFEFF47D)
        b = II(b, c, d, a, words[1], 21, 0x85845DD1)
        a = II(a, b, c, d, words[8], 6, 0x6FA87E4F)
        d = II(d, a, b, c, words[15], 10, 0xFE2CE6E0)
        c = II(c, d, a, b, words[6], 15, 0xA3014314)
        b = II(b, c, d, a, words[13], 21, 0x4E0811A1)
        a = II(a, b, c, d, words[4], 6, 0xF7537E82)
        d = II(d, a, b, c, words[11], 10, 0xBD3AF235)
        c = II(c, d, a, b, words[2], 15, 0x2AD7D2BB)
        b = II(b, c, d, a, words[9], 21, 0xEB86D391)

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

        print("md5 update: ", struct.pack("<4I", a0, b0, c0, d0).hex())

    md5_result = struct.pack("<4I", a0, b0, c0, d0)
    return md5_result.hex()


if __name__ == "__main__":
    input_str = "kevinSpider"
    result = kmd5(input_str.encode("utf-8"))
    print("md5 final: ", result)
