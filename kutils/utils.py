from typing import List, Literal

import numpy as np

np.set_printoptions(linewidth=1000000)


def array_hex_dump(
    table: List, shape: (int, int), bytes_len: int | None = None
) -> None:
    """
    :param table: 一维数组, 如果是二维数组, 需要自己遍历再打印
    :param shape: (行, 列) (16,16) 就是16 * 16 = 256 个元素
    :param bytes_len: 数组每个元素的长度, 如果为None, 则使用默认的hex打印
    :return:
    """
    total = shape[0] * shape[1]
    if len(table) < total:
        table += [None] * (total - len(table))

    def khex(x, bytes_len):
        # debug 每个字节用两位十六进制表示
        if x is None:
            return "IGNORE"
        else:
            return f"0x{x:0{bytes_len * 2}x}"

    array_reshape = np.array(table).reshape(shape)
    if bytes_len is None:
        array_hex = np.vectorize(hex)(array_reshape)
    else:
        array_hex = np.vectorize(khex)(array_reshape, bytes_len)
    for element in array_hex:
        print(",".join([str(e) for e in element if e != "IGNORE"]) + ",")


def number2hex(
    number: int, len: int, byteorder: Literal["little", "big"] = "little"
) -> str:
    if byteorder == "little":
        value = number.to_bytes(len, byteorder)
        return value.hex()
    else:
        value = number.to_bytes(len, byteorder)
        return value.hex()


if __name__ == "__main__":
    input = 0x2D6B64F4
    result = number2hex(input, 4, "big")
    print(result)
