# hmac 总结起来就是 2次哈希, 2次加盐

# 使用 hmac md5 为例

# 1.密钥填充
# 如果密钥长度小于hash函数分组长度
# 首先填充0x00到对应的hash函数的分组长度, 例如md5分组长度为64字节 -> 512bit
# 如果密钥长度超过hash函数分组长度
# 使用hash先对密钥进行计算, 将hash的结果作为密钥, 再进行填充

# 2.异或0x36
# 填充后密钥逐字节异或 0x36 得到扩展密钥1

# 3.异或0x5c
# 填充的密钥逐字节异或 0x5c 得到扩展密钥2

# 4.第一次加盐hash
# 扩展密钥1+输入 作为入参, 进行hash算法得到结果1

# 5.第二次加盐hash
# 扩展密钥2+第一次hash结果1, 再次进行hash算法得到最终结果

from khash.k_md5 import kmd5
from khash.k_sha1 import ksha1
from khash.k_sha256 import ksha256
from khash.k_sha512 import ksha512


def hmac_key_extend(key: bytes, group_len: int):
    # 判断当前密钥长度是否大于分组长度, 如果小于,则填充
    if len(key) < group_len:
        key = key + b"\x00" * (group_len - len(key))
    else:
        # todo 如果大于则使用密钥hash之后的结果作为密钥, 再进行填充
        raise

    # 0x36 和 0x5c 是hmac的特征
    # 将密钥和0x36,0x5c 进行逐字节异或
    extend_key1 = bytes(b ^ 0x36 for b in key)
    extend_key2 = bytes(b ^ 0x5C for b in key)

    # 返回最终的扩展密钥
    return extend_key1, extend_key2


def khmac(message: bytes, key: bytes, digest_mod: str):
    group_len = 0
    hash_func = None

    if digest_mod.upper() == "MD5":
        hash_func = kmd5
        group_len = 64
    if digest_mod.upper() == "SHA1":
        hash_func = ksha1
        group_len = 64
    if digest_mod.upper() == "SHA256":
        hash_func = ksha256
        group_len = 64
    if digest_mod.upper() == "SHA512":
        hash_func = ksha512
        group_len = 128

    assert group_len != 0
    assert hash_func is not None

    # hmac 扩展密钥
    extend_key1, extend_kye2 = hmac_key_extend(key, group_len)
    # debug 第一次加盐hash, (扩展密钥1 + 输入) 进行 hash, 得到hash_result1
    hash_result1 = hash_func(extend_key1 + message)
    # debug 第二次加盐hash, (扩展密钥2 + hash_result1) 进行hash,得到最终结果
    hash_result2 = hash_func(extend_kye2 + bytes.fromhex(hash_result1))
    return hash_result2


if __name__ == '__main__':
    result = khmac("hello".encode("utf-8"), "kevinSpider".encode("utf-8"), "md5")
    print("debug", result)

    result = khmac("hello".encode("utf-8"), "kevinSpider".encode("utf-8"), "sha1")
    print("debug", result)

    result = khmac("hello".encode("utf-8"), "kevinSpider".encode("utf-8"), "sha256")
    print("debug", result)

    result = khmac("hello".encode("utf-8"), "kevinSpider".encode("utf-8"), "sha512")
    print("debug hmac_sha512", result)
