# 目录结构

```bash
tree | grep -vE "__pycache__|*.pyc"
```

```log
kcrypto
├── demo.py
├── khash
│   ├── k_crc32.py
│   ├── k_md5.py
│   ├── k_sha1.py
│   ├── k_sha256.py
│   ├── k_sha512.py
│   └── k_sm3.py
├── khmac
│   └── k_hmac.py
├── ksymmetric
│   ├── dfa
│   │   ├── dfa_attack.py
│   │   └── keyN_to_key0.py
│   ├── k_aes.py
│   ├── k_rc4.py
│   └── tracefile
├── kutils
│   └── utils.py
└── README.md


```
