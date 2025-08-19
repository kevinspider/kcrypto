"""
aes
- 类别: 对称加密算法
- 密钥长度: 128bit, 192bit, 256bit 即 16字节, 24字节, 32字节
- 加密方式: 分组加密 (分组大小 16字节 128bit)

填充模式:
1. pkcs7 填充
2. pad_zero 0填充
3. unpad 无填充

加密模式
1. ecb 无iv
2. cbc 有iv 16字节

aes
1. 128 -> 10轮
2. 192 -> 12轮
3. 256 -> 14轮

分组长度
    16字节, 密文长度都是16字节的整数倍

填充方式
    - PKCS7 (使用的最多)
        填充字节数和填充内容都是: 分组大小 - 数据长度对分组大小的余数
            kevinSpider 是密文, 一共11个字节 -> 6b 65 76 69 6e 53 70 69 64 65 72
            填充字节数: 16 - (11 % 16) = 0x5
            填充内容: 16 - (11 % 16) = 0x5
        填充后的数据: 16个字节                  6b 65 76 69 6e 53 70 69 64 65 72 05 05 05 05 05

    - zero 填充
        填充字节数: 分组大小 - 数据长度对分组大小的余数;
        填充内容: 0x0

    ps: 如果输入的密文本身就是一个分组长度 16 字节; 那么也需要进行填充
        输入 16 字节 6b 65 76 69 6e 53 70 69 64 65 72 05 05 05 05 05
        那么填充以后的结果, 就是填充 16 - (16 % 16) = 0x10
                    6b 65 76 69 6e 53 70 69 64 65 72 05 05 05 05 05
                    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
    ps: 无论输入是多少, 都是需要进行填充的!!!

加密模式
    - CBC
        - 需要一个16字节的IV
        - 明文的前16字节首先和IV异或, 得到result1
        - 然后使用 ECB 模式加密这 16 字节 result1 的数据, 得到的结果作为第一组密文; 同时作为下一轮的 iv 与下一组明文进行异或
        - 如果只知道密钥而不知道 IV, 解出来就是明文和iv 异或的结果
    - ECB

算法部分:
    密钥长度
        16字节 对应 aes-128
        24字节 对应 aes-192
        32字节 对应 aes-256
    iv 长度, 如果存在iv, 则iv长度恒定为16字节
    算法循环
        密钥长度每增加8字节, 算法循环次数就增加两轮;
        aes-128 循环 10轮
        aes-192 循环 12轮
        aes-256 循环 14轮
"""

import struct
from enum import Enum

from kutils.utils import array_hex_dump


class AesMode(Enum):
    ECB = 1
    CBC = 2


class PadMode(Enum):
    pkcs7_pad = 1
    zero_pad = 2
    unpad = 3


# important aes 密钥长度和循环次数对应表
key_len_loop_num = {
    16: 10,  # aes 128; key is 16 bytes, loop is 10
    24: 12,  # aes 192; key is 24 bytes, loop is 12
    32: 14,  # aes 256; key is 32 bytes, loop is 14
}

SBOX = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)

RCON = (
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
)  # 11个; 所以为 0 的 0x0 用不到占位; C中常用0x8d来占位 反正都用不到


# debug 填充模式
def pad_pkcs7(message: bytes, bytes_len: int) -> bytes:
    # debug 输入刚好为一个分组长度, 则也需要填充
    pad = bytes_len - (len(message) % bytes_len)
    message += bytes([pad] * pad)
    return message


def pad_zero(message: bytes, bytes_len: int) -> bytes:
    # debug 输入刚好为一个分组长度, 则也需要填充
    if len(message) % bytes_len == 0:
        message += bytes([0x0] * bytes_len)
        return message
    else:
        pad = bytes_len - (len(message) % bytes_len)
        message += bytes([0x0] * pad)
        return message


def pad_unpad(message: bytes, bytes_len: int) -> bytes:
    # debug 不填充
    assert len(message) % bytes_len == 0
    return message


# debug 密钥扩展计算部分


def shift_left(array, num):
    """
    :param array: 需要循环左移的数组
    :param num: 循环左移的位数
    :return: 返回循环左移之后的 array
    """
    return array[num:] + array[:num]


def g(array, index):
    # 1. 循环左移1字节
    array = shift_left(array, 1)
    # 2. 字节替换 将array中的每个字节都使用SBOX值替换
    array = [SBOX[i] for i in array]
    # 3. 首字节和 rcon 对应索引进行异或
    array = [RCON[index] ^ array[0]] + array[1:]
    return array


def xor_array(array1, arrary2):
    assert len(arrary2) == len(array1)
    return [array1[i] ^ arrary2[i] for i in range(len(array1))]


def show_round_keys(round_kyes: list[list], loop_num: int):
    kList = [[] for _i in range(loop_num + 1)]
    for i in range(len(round_kyes)):
        kList[i // 4] += round_kyes[i]
    for i in range(len(kList)):
        print("K%02d: " % i + "".join("%02X" % k for k in kList[i]))


# debug 加密计算部分
def add_round_keys(state: list[list[int]], round_keys: list[list[int]]):
    result = [[] for _i in range(4)]
    for i in range(4):
        result[i] = xor_array(state[i], round_keys[i])
    return result


def sub_bytes(state: list[list[int]]):
    result = [[] for _i in range(4)]
    for i in range(4):
        result[i] = [SBOX[i] for i in state[i]]
    return result


def shift_rows(state: list[list[int]]):
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1],
        state[2][1],
        state[3][1],
        state[0][1],
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2],
        state[3][2],
        state[0][2],
        state[1][2],
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[3][3],
        state[0][3],
        state[1][3],
        state[2][3],
    )
    return state


def mix_columns(state: list[list[int]]):
    def mul02(value):
        if value < 0x80:
            res = value << 1
        else:
            res = (value << 1) ^ 0x1B
        res = res % 0x100
        return res

    def mul03(value):
        res = mul02(value) ^ value
        return res

    for i in range(4):
        s0 = mul02(state[i][0]) ^ mul03(state[i][1]) ^ state[i][2] ^ state[i][3]
        s1 = state[i][0] ^ mul02(state[i][1]) ^ mul03(state[i][2]) ^ state[i][3]
        s2 = state[i][0] ^ state[i][1] ^ mul02(state[i][2]) ^ mul03(state[i][3])
        s3 = mul03(state[i][0]) ^ state[i][1] ^ state[i][2] ^ mul02(state[i][3])
        state[i][0] = s0
        state[i][1] = s1
        state[i][2] = s2
        state[i][3] = s3
    return state


def state_to_text(state: list[list[int]]):
    text = sum(state, [])
    return "".join("%02x" % k for k in text)


# debug 密钥编排 aes_key_schedule
def aes_key_schedule(master_key: bytes, nk: int) -> list:
    """
    :param master_key: 输入的主密钥
    :param nk: nk = len(master_key) // 4
    :return: list: 子密钥字节数组;
    :descript:
        生成
            生成子密钥的时候, 是逐4字节生成的;
            例如, aes128 是 44 *4
        返回
            aes128-> 11 * 16 字节 对应 K0 - K10 一共11个, k0 是主密钥; 一共 176 字节
            aes192-> 13 * 16字节 对应 K0 - K12 一共13个, k0-k1的一半 是主密钥; 一共 208 字节
            aes256-> 15 * 16字节 K0 - K14 一共15个, k0-k1 是主密钥; 一共 240 字节
    """
    # 初始化计算子密钥W 二维数组的形式, round_keys 44 个元素, 每个元素 4个字节[]
    # round_keys = [[x, x, x, x], ...]

    assert len(master_key) in key_len_loop_num

    loop_num = key_len_loop_num[len(master_key)]  # 10 or 12 or 14
    round_keys_len = (loop_num + 1) * 4  # debug aes128 是 (10 + 1) *4 = 44个
    round_keys = [
        [0] * 4 for _i in range(round_keys_len)
    ]  # debug [ [x,x,x,x] * 44 ] 二维数组
    # nk = len(master_key) // 4  # debug aes128->4 , aes192->6, aes256->8
    """
    nk 的作用
    密钥扩展逻辑: 在密钥扩展过程中，nk 决定了何时需要调用 g 函数进行字节替换和 RCON 异或操作。具体来说，每 nk 个字会触发一次 g 函数的调用。
    特殊处理: 对于 AES-256，nk 的值为 8，这意味着在密钥扩展中，每 8 个字会进行一次 g 函数调用，而在第 4 个字时会进行 SBOX 替换操作。
    """
    for i in range(0, round_keys_len):
        if 0 <= i < nk:
            tmp_key = struct.unpack(f">{nk}I", master_key)[i].to_bytes(4, "big")
            round_keys[i] = list(struct.unpack(">4B", tmp_key))
        elif i % nk == 0:
            index = i // nk
            round_keys[i] = xor_array(g(round_keys[i - 1], index), round_keys[i - nk])
        # debug 处理 AES-256 的额外步骤; AES-256 在每个 4 个字节的时候, 需要额外的 SBOX 替换操作
        elif nk > 6 and i % nk == 4:
            round_keys[i] = xor_array(
                [SBOX[b] for b in round_keys[i - 1]], round_keys[i - nk]
            )
        else:
            round_keys[i] = xor_array(round_keys[i - 1], round_keys[i - nk])

    show_round_keys(round_keys, loop_num)
    return round_keys


# debug aes ecb 模式
def aes_encrypt_ecb(message: bytes, master_key: bytes, pad: PadMode) -> str:
    """
    :param message: 输入明文 bytes
    :param master_key: 密钥 bytes
    :param pad: PadMode.pkcs7_pad or PadMode.zero_pad or PadMode.unpad
    :return: hexString
    """
    # nk 初始化 4 or 6 or 8 控制了密钥编排中g函数的使用
    nk = len(master_key) // 4
    # 根据key长度确定循环次数
    # aes 128; key is 16 bytes, loop is 10
    # aes 192; key is 24 bytes, loop is 12
    # aes 256; key is 32 bytes, loop is 14
    loop_num = key_len_loop_num[len(master_key)]
    # 生成子密钥 round_keys 4个元素组成了一个子密钥K, 第一次使用K00, 一次类推
    round_keys = aes_key_schedule(master_key, nk)

    # 填充
    if pad == PadMode.pkcs7_pad:
        message = pad_pkcs7(message, 16)
    elif pad == PadMode.zero_pad:
        message = pad_zero(message, 16)
    elif pad == PadMode.unpad:
        message = pad_unpad(message, 16)
    else:
        raise ValueError("未定义的Pad模式")

    # 初始化结果
    aes_result = ""
    # 每16个字节加密一次
    chunks = [message[i : i + 16] for i in range(0, len(message), 16)]
    for chunk in chunks:
        # debug 生成state, 存储的是进来的分组16个字节
        # 先切割成4字节的 list[bytes]
        state = [chunk[i : i + 4] for i in range(0, len(chunk), 4)]
        # 再将list[bytes] 转为 list[list[int]]
        state = [list(struct.unpack(">4B", each)) for each in state]
        # print(f"state {len(state)}", state)
        print("加密明文:")
        for each in state:
            array_hex_dump(each, (1, 4))
        # debug 轮密钥加 state和 master_key输入部分
        # debug 初始化密钥轮相加
        state = add_round_keys(state, round_keys[0:4])
        # debug 主体循环 [1,n]次 最后一次单独
        for i in range(1, loop_num):
            # 字节替
            state = sub_bytes(state)
            # 行移位
            state = shift_rows(state)
            # important dfa 攻击点, 最后两次列混淆之间, 随机修改state的一个字节
            # if i == (loop_num - 1): # i == 9
            #     z = random.randint(0, 3)
            #     y = random.randint(0, 3)
            #     value = 0x3
            #     state[z][y] = value
            # 列混淆
            state = mix_columns(state)
            # 轮密钥加
            state = add_round_keys(state, round_keys[4 * i : 4 * (i + 1)])

        # debug 最后一次循环, 缺少一个列混淆
        # 字节替
        state = sub_bytes(state)
        # 行移位
        state = shift_rows(state)
        # 轮密钥加 最后一次使用最后的一个轮密钥
        state = add_round_keys(state, round_keys[-4:])
        aes_result += state_to_text(state)
    return aes_result


# debug aes cbc 模式
def aes_encrypt_cbc(
    message: bytes, master_key: bytes, master_iv: bytes, pad: PadMode
) -> str:
    """
    :param message: 输入明文 bytes
    :param master_key: 密钥 bytes
    :param master_iv: iv bytes
    :param pad: PadMode.pkcs7_pad or PadMode.zero_pad or PadMode.unpad
    :return: hexString
    """
    # nk 初始化 4 or 6 or 8 控制了密钥编排中g函数的使用
    # aes 128; nk = 4
    # aes 192; nk = 6
    # aes 256; nk = 8
    nk = len(master_key) // 4
    # 根据key长度确定循环次数
    # aes 128; key is 16 bytes, loop is 10
    # aes 192; key is 24 bytes, loop is 12
    # aes 256; key is 32 bytes, loop is 14
    loop_num = key_len_loop_num[len(master_key)]
    # 生成子密钥 round_keys 4个元素组成了一个子密钥K, 第一次使用K00, 一次类推
    round_keys = aes_key_schedule(master_key, nk)

    # 填充
    if pad == PadMode.pkcs7_pad:
        message = pad_pkcs7(message, 16)
    elif pad == PadMode.zero_pad:
        message = pad_zero(message, 16)
    elif pad == PadMode.unpad:
        message = pad_unpad(message, 16)
    else:
        raise ValueError("未定义的Pad模式")

    # 初始化结果
    aes_result = ""
    # 初始化iv
    iv = [master_iv[i : i + 4] for i in range(0, len(master_iv), 4)]
    iv = [list(struct.unpack(">4B", each)) for each in iv]

    # 每16个字节加密一次
    chunks = [message[i : i + 16] for i in range(0, len(message), 16)]
    for chunk in chunks:
        # debug 生成state, 存储的是进来的分组16个字节
        # 先切割成4字节的 list[bytes]
        state = [chunk[i : i + 4] for i in range(0, len(chunk), 4)]
        # 再将list[bytes] 转为 list[list[int]]
        state = [list(struct.unpack(">4B", each)) for each in state]
        # print(f"state {len(state)}", state)
        print("加密明文:")
        for each in state:
            array_hex_dump(each, (1, 4))
        # important cbc模式, 第一次的时候明文16字节和初始iv进行异或
        for i in range(4):
            state[i] = xor_array(state[i], iv[i])

        # debug 轮密钥加 state和 master_key输入部分
        # debug 初始化密钥轮相加
        state = add_round_keys(state, round_keys[0:4])
        # debug 主体循环 [1,n]次 最后一次单独
        for i in range(1, loop_num):
            # 字节替
            state = sub_bytes(state)
            # 行移位
            state = shift_rows(state)
            # important dfa 攻击点, 最后两次列混淆之间, 随机修改state的一个字节
            # if i == (loop_num - 1): # i == 9
            #     z = random.randint(0, 3)
            #     y = random.randint(0, 3)
            #     value = 0x3
            #     state[z][y] = value
            # 列混淆
            state = mix_columns(state)
            # 轮密钥加
            state = add_round_keys(state, round_keys[4 * i : 4 * (i + 1)])

        # debug 最后一次循环, 缺少一个列混淆
        # 字节替
        state = sub_bytes(state)
        # 行移位
        state = shift_rows(state)
        # 轮密钥加 最后一次使用最后的一个轮密钥
        state = add_round_keys(state, round_keys[-4:])

        # important 结果作为下一轮的IV 参与计算, 下一轮的IV会和下一轮输入明文进行异或操作
        iv = state
        aes_result += state_to_text(state)
    return aes_result


# debug 入口函数
def aes_encrypt(
    message: bytes,
    master_key: bytes,
    master_iv: bytes | None = None,
    mode: AesMode = AesMode.ECB,
    pad: PadMode = PadMode.pkcs7_pad,
):
    """
    :param message: 输入明文 bytes
    :param master_key: 密钥 bytes
    :param master_iv: iv bytes
    :param mode: 加密模式, AesMode.ECB or AesMode.CBC
    :param pad: PadMode.pkcs7_pad or PadMode.zero_pad or PadMode.unpad
    :return: hexString
    """
    if mode == AesMode.ECB:
        return aes_encrypt_ecb(message, master_key, pad)
    elif mode == AesMode.CBC:
        assert master_iv is not None
        return aes_encrypt_cbc(message, master_key, master_iv, pad)
    else:
        raise ValueError("unsupport AesMode, just AesMode.CBC or AesMode.EBC")


if __name__ == "__main__":
    message = bytes.fromhex("21d214c2c080fdec3d4263c0a6d7807797ef71d4b5ba6cafa5e6c9fa4f9cde44")
    key = bytes.fromhex("6845594D5977705579484A764B5A5476")

    result = aes_encrypt_ecb(message, key, PadMode.pkcs7_pad)
    print(result)
