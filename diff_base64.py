import struct
from karm.arm64 import bfi


base64_table = "abcdefghijklmnopqrstuvwxyz!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ+/"

# for i in range(0, len(input_bytes), 3):
#     x10 = input_bytes[i]
#     x8 = input_bytes[i + 1]
#     try:
#         x9 = input_bytes[i + 2]
#     except Exception as e:
#         x9 = 0x0

#     x27 = x8 >> 4
#     x27 = bfi(x27, x10, 4, 2)
#     result0 = base_64_table[x27 & 0xFF]
#     print(result0)

#     x11 = x9 >> 6
#     x11 = bfi(x11, x8, 2, 4)
#     result1 = base_64_table[x11 & 0xFF]
#     print(result1)

#     x12 = x10 >> 2
#     result2 = base_64_table[x12 & 0xFF]
#     print(result2)

#     x11 = x9 & 0x3F
#     result3 = base_64_table[x11 & 0xFF]
#     print(result3)


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
            cipher.append("=")
            cipher.append("=")
        elif counts == 2:
            # 剩余 2 字节时，填充 1 个 '='
            cipher.append(base64_table[((buffer[0] & 0x03) << 4) | (buffer[1] >> 4)])
            cipher.append(base64_table[(buffer[1] & 0x0F) << 2])
            cipher.append("=")

    return "".join(cipher)


def swap(message: str) -> str:
    tmp = []
    for i in range(0, len(message), 4):
        tmp.append(message[i : i + 4])
    result = ""
    for i in range(0, len(tmp)):
        result += tmp[i][1] + tmp[i][2] + tmp[i][0] + tmp[i][3]
    print(result)


DELTA = 0x9E3779B9
NUM_ROUNDS = 32


def custom_encrypt(data: bytes, key: bytes) -> bytes:
    """实现类似 TEA 变种的加密算法"""
    assert len(key) == 16, "Key must be 16 bytes (128 bits)"

    # 解析密钥为 4 个 32 位整数
    k0, k1, k2, k3 = struct.unpack(">4I", key)

    # 确保数据长度是 8 的倍数，不足则填充 0x00
    pad_len = (8 - len(data) % 8) % 8
    data += b"\x00" * pad_len

    # 处理 8 字节块
    encrypted = bytearray()
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack(">2I", data[i : i + 8])
        sum_ = 0x9E3779B9 * NUM_ROUNDS  # sum 先初始化为 32 轮 * delta

        for _ in range(NUM_ROUNDS):
            v1 -= (k2 + (v0 << 4)) ^ (v0 + sum_) ^ (k3 + (v0 >> 5))
            v1 &= 0xFFFFFFFF  # 保持 32 位
            v0 -= (k0 + (v1 << 4)) ^ (v1 + sum_) ^ (k1 + (v1 >> 5))
            v0 &= 0xFFFFFFFF  # 保持 32 位
            sum_ -= DELTA

        encrypted.extend(struct.pack(">2I", v0, v1))

    return bytes(encrypted)


if __name__ == "__main__":
    input_value = "5654f83cbc71c4a9291cf2a28eaa1f73cade640b8e57fceb8d144dfe2e55880d"
    input_bytes = bytes.fromhex(input_value)
    result = kbase64_encode(input_bytes)
    print(result)
    swap(result)

    # 示例
    data = b"1234567890abcdedfaaaaaaaaaaaaaaa"
    key = bytes.fromhex("0000000c00000022000000380000004e")
    print(key.hex())
    encrypted_data = custom_encrypt(data, key)

    # # 转换为 HEX 格式输出
    hex_output = " ".join(f"{b:02x}" for b in encrypted_data)
    print("Encrypted:", hex_output)
