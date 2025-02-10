import struct
from kutils.utils import array_hex_dump


def pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if not 1 <= pad_len <= 8:
        raise ValueError("Invalid padding length")
    return data[:-pad_len]


def encrypt_block(v0: int, v1: int, key: tuple) -> tuple:
    delta = 0x9E3779B9
    sum_ = 0
    k0, k1, k2, k3 = key
    for _ in range(32):
        sum_ = (sum_ + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
    return v0, v1


def decrypt_block(v0: int, v1: int, key: tuple) -> tuple:
    delta = 0x9E3779B9
    sum_ = (delta * 32) & 0xFFFFFFFF
    k0, k1, k2, k3 = key
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF
    return v0, v1


def tea_encrypt(message: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long")
    padded = pad(message)
    encrypted = []
    key_parts = struct.unpack(">4I", key)
    for i in range(0, len(padded), 8):
        block = padded[i : i + 8]
        v0, v1 = struct.unpack(">2I", block)
        ev0, ev1 = encrypt_block(v0, v1, key_parts)
        encrypted.append(struct.pack(">2I", ev0, ev1))
    return b"".join(encrypted)


def tea_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long")
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be a multiple of 8 bytes")
    decrypted = []
    key_parts = struct.unpack(">4I", key)
    array_hex_dump(list(key_parts),[1,4])
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i : i + 8]
        v0, v1 = struct.unpack(">2I", block)
        dv0, dv1 = decrypt_block(v0, v1, key_parts)
        decrypted.append(struct.pack(">2I", dv0, dv1))
    decrypted_data = b"".join(decrypted)
    return unpad(decrypted_data)


if __name__ == "__main__":
    key = bytes.fromhex("00000042000000370000002c00000021")  # 16字节的0
    message = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    # 加密
    ciphertext = tea_encrypt(message, key)
    print(f"Ciphertext: {ciphertext.hex()}")

    # 解密
    decrypted = tea_decrypt(ciphertext, key)
    print(f"Decrypted: {decrypted.decode()}")
