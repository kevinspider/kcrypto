def bfi(destination, source, lsb, width):
    # 模拟 32 位行为，确保所有位操作都在 32 位内
    destination &= 0xFFFFFFFF
    source &= 0xFFFFFFFF
    # 构建 width 宽度的掩码
    mask = ((1 << width) - 1) << lsb
    # 清除 destination 的目标区域
    destination &= ~mask & 0xFFFFFFFF
    # 提取 source 的低 width 位，并移到 lsb 位置
    insert_bits = (source & ((1 << width) - 1)) << lsb
    # 插入进 destination
    result = (destination | insert_bits) & 0xFFFFFFFF
    return result


def ubfx(rn, lsb, width):
    mask = (1 << width) - 1
    result = (rn >> lsb) & mask
    return result


def bfxil(dst: int, src: int, lsb: int, width: int) -> int:
    # 构造 mask，比如 width = 2 -> mask = 0b11
    mask = (1 << width) - 1

    # 提取 src 中的目标位域
    extracted_bits = (src >> lsb) & mask

    # 清除 dst 中相应位域
    dst_cleared = dst & ~(mask << lsb)

    # 插入位域
    result = dst_cleared | (extracted_bits << lsb)

    # 保证返回值在 32-bit 范围内
    return result & 0xFFFFFFFF


def ror(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & 0xFFFFFFFFFFFFFFFF
