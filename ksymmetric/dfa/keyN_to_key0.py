# =====================================================================
# This file is a little helper to compute AES key scheduling
# from any round key
# Original author:   Philippe Teuwen <phil@teuwen.org> 2016
#
# Usage:
# aes_keyschedule AES_key_in_hex
# aes_keyschedule Round_key_in_hex Round_key_number_between_0_and_10
#
# Examples:
# aes_keyschedule 11223344556677881122334455667788
# aes_keyschedule 23D7F7B876B180306793B37432F5C4FC 1
# aes_keyschedule 43EDA420DD033E7627347DC2CC6E0B4E 9
# aes_keyschedule EAC68B6B37C5B51D10F1C8DFDC9FC391 10
#
# Based on the Tiny AES128 in C https://github.com/kokke/tiny-AES128-C
# and released under the same licensing terms:
#
# This is free and unencumbered software released into the public domain
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>
# =====================================================================

Nb = 4

RoundKey = [0] * 240
Key = [0] * 32

sbox = [
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
]

Rcon = [0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def key_expansion(start, aes_size):
    Nk = aes_size // 32
    Nr = Nk + 6
    start *= 4
    for i in range(start, Nk + start):
        RoundKey[(i * 4) + 0] = Key[((i - start) * 4) + 0]
        RoundKey[(i * 4) + 1] = Key[((i - start) * 4) + 1]
        RoundKey[(i * 4) + 2] = Key[((i - start) * 4) + 2]
        RoundKey[(i * 4) + 3] = Key[((i - start) * 4) + 3]
    for i in range(Nk + start, Nb * (Nr + 1)):
        tempa = [RoundKey[(i - 1) * 4 + j] for j in range(4)]
        if i % Nk == 0:
            tempa = tempa[1:] + tempa[:1]
            tempa = [sbox[b] for b in tempa]
            tempa[0] ^= Rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            tempa = [sbox[b] for b in tempa]
        for j in range(4):
            RoundKey[i * 4 + j] = RoundKey[(i - Nk) * 4 + j] ^ tempa[j]
    for i in range(Nk + start - 1, Nk - 1, -1):
        tempa = [RoundKey[(i - 1) * 4 + j] for j in range(4)]
        if i % Nk == 0:
            tempa = tempa[1:] + tempa[:1]
            tempa = [sbox[b] for b in tempa]
            tempa[0] ^= Rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            tempa = [sbox[b] for b in tempa]
        for j in range(4):
            RoundKey[(i - Nk) * 4 + j] = RoundKey[i * 4 + j] ^ tempa[j]
    for j in range(16 * (Nr + 1)):
        if j % 16 == 0:
            print(f"K{j // 16:02}: ", end="")
        print(f"{RoundKey[j]:02X}", end="")
        if j % 16 == 15:
            print()


def is_hex_char(c):
    return ("0" <= c <= "9") or ("a" <= c <= "f") or ("A" <= c <= "F")


def aes_key_revese(roundkey, round_key_index=0):
    arglen = len(roundkey)
    if arglen not in [32, 48, 64]:
        print("Error: AES_key must be 16, 24 or 32-byte long")
        return

    AesSize = arglen * 4
    for i in range(0, arglen, 2):
        if not is_hex_char(roundkey[i]) or not is_hex_char(roundkey[i + 1]):
            return
        Key[i // 2] = int(roundkey[i : i + 2], 16)

    key_expansion(round_key_index, AesSize)


if __name__ == "__main__":
    """
    AES-128: provide 1 round key
    key: B1BA2737C83233FE7F7A7DF0FBB01D4A
    aes_keyschedule("97F926D5677B324AC439D77C8B03FDF8", 5)
    output:
        K00: *B1BA2737C83233FE7F7A7DF0FBB01D4A*          ** is key
        K01: 571EF1389F2CC2C6E056BF361BE6A27C
        K02: DB24E19744082351A45E9C67BFB83E1B
        K03: B3964E9FF79E6DCE53C0F1A9EC78CFB2
        K04: 071C7951F082149FA342E5364F3A2A84
        K05: 97F926D5677B324AC439D77C8B03FDF8
        K06: CCAD67E8ABD655A26FEF82DEE4EC7F26
        K07: 427F9081E9A9C523864647FD62AA38DB
        K08: 6E78292B87D1EC080197ABF5633D932E
        K09: 52A418D0D575F4D8D4E25F2DB7DFCC03
        K10: FAEF63792F9A97A1FB78C88C4CA7048F

    AES-192: provide 1.5 round key
    key: B1BA2737C83233FE7F7A7DF0FBB01D4A7835FA62BE9726A1
    aes_keyschedule("D42AAFEB1510F368D8AA1354A707697696D6CC20F7737995", 5)
    output:
        K00: *B1BA2737C83233FE7F7A7DF0FBB01D4A*             ** is key
        K01: *7835FA62BE9726A1* 384D1599F07F2667
        K02: 8F055B9774B546DD0C80BCBFB2179A1E
        K03: CAF567AE3A8A41C9B58F1A5EC13A5C83
        K04: CDBAE03C7FAD7A225B2FF47C61A5B5B5
        K05: D42AAFEB1510F368D8AA1354A7076976
        K06: 96D6CC20F77379952359D67E36492516
        K07: EEE3364249E45F34EF19D41B186AAD8E
        K08: 3B337BF00D7A5EE6E39968A4AA7D3790
        K09: 3083B4B728E9193913DA62C91EA03C2F
        K10: FD39548B5744631B6B781BEC439102D5
        K11: 504B601C4EEB5C33B3D208B8E4966BA3
        K12: 7B0711853896135068DD734C26362F7F

    AES-256: provide 2 round keys
    key: B1BA2737C83233FE7F7A7DF0FBB01D4A7835FA62BE9726A1BB39F261BAC4729C
    aes_keyschedule("F2E96B6FD53C1BBB49D0990E6FF86927DF8F909C21310695C43D2751C133AC12", 5)
    output:
        K00: *B1BA2737C83233FE7F7A7DF0FBB01D4A*             ** is key
        K01: *7835FA62BE9726A1BB39F261BAC4729C*
        K02: ACFAF9C364C8CA3D1BB2B7CDE002AA87
        K03: 9942567527D570D49CEC82B52628F029
        K04: 9A765C34FEBE9609E50C21C4050E8B43
        K05: F2E96B6FD53C1BBB49D0990E6FF86927
        K06: DF8F909C21310695C43D2751C133AC12
        K07: 8A2AFAA65F16E11D16C67813793E1134
        K08: 650D882A443C8EBF8001A9EE413205FC
        K09: 09099116561F700B40D9081839E7192C
        K10: E1D9F938A5E5778725E4DE6964D6DB95
        K11: 4AFF283C1CE058375C39502F65DE4903
        K12: DCE282757907F5F25CE32B9B3835F00E
        K13: 4D69A4975189FCA00DB0AC8F686EE58C
        K14: 033BE6307A3C13C226DF38591EEAC857
    """
    # debug aes128 需要提供1轮子密钥
    aes_key_revese("AE7A911AA47EBC689C96DCFEB6E9B5AF", 10)

    # debug aes192 需要提供1.5轮子密钥
    aes_key_revese("504B601C4EEB5C33B3D208B8E4966BA37B07118538961350", 11)

    # debug aes256
    aes_key_revese(
        "4D69A4975189FCA00DB0AC8F686EE58C033BE6307A3C13C226DF38591EEAC857", 13
    )
