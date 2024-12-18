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
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


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
    return (
            ('0' <= c <= '9') or
            ('a' <= c <= 'f') or
            ('A' <= c <= 'F')
    )


def aes_key_revese(roundkey, round_key_index=0):
    arglen = len(roundkey)
    if arglen not in [32, 48, 64]:
        print("Error: AES_key must be 16, 24 or 32-byte long")
        return

    AesSize = arglen * 4
    for i in range(0, arglen, 2):
        if not is_hex_char(roundkey[i]) or not is_hex_char(roundkey[i + 1]):
            return
        Key[i // 2] = int(roundkey[i:i + 2], 16)

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
    aes_key_revese("D014F9A8C9EE2589E13F0CC8B6630CA6", 10)

    # debug aes192 需要提供1.5轮子密钥
    aes_key_revese("504B601C4EEB5C33B3D208B8E4966BA37B07118538961350", 11)

    # debug aes256
    aes_key_revese("4D69A4975189FCA00DB0AC8F686EE58C033BE6307A3C13C226DF38591EEAC857", 13)
