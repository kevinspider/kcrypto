def bfi(dst: int, src: int, lsb: int, width: int) -> int:
    mask = (1 << width) - 1  # 计算用于提取 src 的掩码
    src_bits = (src & mask) << lsb  # 提取 src 指定宽度的位并左移到 lsb 位置
    dst_mask = ~(mask << lsb)  # 生成清除 dst 目标位置的掩码
    return (dst & dst_mask) | src_bits  # 清除目标位置并插入新值


if __name__ == "__main__":
    x27 = 0x5
    x10 = 0x56
    result = bfi(x27, x10, 4, 2)
    print(hex(result))
    print(hex(bfi(0x3, 0x54, 2, 4)))
