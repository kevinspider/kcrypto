# 结果是 013a0b18

# 01 18 这两个可以看做定值

from kutils.utils import number2hex

"""
输入的请求头中 "x-ss-stub" 的内容, 4A615C6ED77874BFEEB266FEFEE9547D 进行 sm3 的结果 取第一个字节
得到的 0x7a
输入的 url 进行 sm3 的结果取第一个字节
得到的 0xec
"""

protobuf_1bytes = 0xec
protobuf_2bytes = 0x7a

padding1 = 0x18000000
padding2 = 0x00000001
result1 = (protobuf_1bytes & 0x3f) << 0xe
result2 = (protobuf_2bytes & 0x3f) << 0x8
result = (padding1 | result1 | result2 | padding2)
result = bytes.fromhex(number2hex(result, 4, "little"))
print(result.hex())
