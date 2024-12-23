# base64 编码表
base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def kbase64_encode(message: bytes) -> str:
    # 原始 的编码是8bit来表示一个字节, 2**8 = 256 个字符
    # base64 使用6bit来表示一个字节, 2**6 = 64 个字符
    """
    :param message: 待编码的字节数据
    :return: 编码后的 Base64 字符串
    """

    # 初始化变量
    counts = 0
    buffer = []
    cipher = []

    # 遍历输入字节流
    for byte in message:
        buffer.append(byte)  # 将字节加入缓冲区
        counts += 1
        if counts == 3:
            # 编码 3 字节为 4 个 Base64 字符
            cipher.append(base64_table[buffer[0] >> 2])
            cipher.append(base64_table[((buffer[0] & 0x03) << 4) | (buffer[1] >> 4)])
            cipher.append(base64_table[((buffer[1] & 0x0F) << 2) | (buffer[2] >> 6)])
            cipher.append(base64_table[buffer[2] & 0x3F])
            buffer = []  # 清空缓冲区
            counts = 0

    # 处理剩余的字节
    if counts > 0:
        cipher.append(base64_table[buffer[0] >> 2])  # 第一部分
        if counts == 1:
            # 剩余 1 字节时，填充 2 个 '='
            cipher.append(base64_table[(buffer[0] & 0x03) << 4])
            cipher.append('=')
            cipher.append('=')
        elif counts == 2:
            # 剩余 2 字节时，填充 1 个 '='
            cipher.append(base64_table[((buffer[0] & 0x03) << 4) | (buffer[1] >> 4)])
            cipher.append(base64_table[(buffer[1] & 0x0F) << 2])
            cipher.append('=')

    return ''.join(cipher)


def kbase64_decode(cipher: str) -> bytes:
    """
    :param cipher: Base64 编码的字符串
    :return: 解码后的字节数据
    """

    base64_reverse_map = {char: idx for idx, char in enumerate(base64_table)}
    base64_reverse_map['='] = 64  # '=' 表示填充字符

    # 初始化变量
    counts = 0
    buffer = []
    plain = bytearray()  # 使用可变字节数组存储解码结果

    # 遍历 Base64 字符串
    for char in cipher:
        if char not in base64_reverse_map:
            raise ValueError(f"Invalid character '{char}' in Base64 string")

        # 查找当前字符对应的值
        buffer.append(base64_reverse_map[char])
        counts += 1

        # 如果缓冲区满 4 字节，则解码为 3 字节
        if counts == 4:
            # 解码缓冲区的 4 个 Base64 字符
            plain.append(((buffer[0] << 2) | (buffer[1] >> 4)) & 0xFF)  # 前 8 位
            if buffer[2] != 64:  # 如果第 3 个字符不是填充
                plain.append(((buffer[1] << 4) | (buffer[2] >> 2)) & 0xFF)  # 中间 8 位
            if buffer[3] != 64:  # 如果第 4 个字符不是填充
                plain.append(((buffer[2] << 6) | buffer[3]) & 0xFF)  # 后 8 位

            # 清空缓冲区
            buffer = []
            counts = 0

    return bytes(plain)


# 测试用例
if __name__ == "__main__":

    test_cases = [
        b"A",  # 单字节输入
        b"AB",  # 两字节输入
        b"ABC",  # 三字节输入
        b"Hello",  # 普通字符串
        b"Base64",  # 偶数字符
        b"",  # 空输入
    ]

    for test in test_cases:
        print(f"Input: {test} -> Encoded: {kbase64_encode(test)} -> Decode: {kbase64_decode(kbase64_encode(test))}")
