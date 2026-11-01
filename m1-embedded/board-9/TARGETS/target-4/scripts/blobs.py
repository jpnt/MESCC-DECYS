#!/usr/bin/env python3

import base64

ROOT_DIR = "../"

d = open("PROGMEM.bin", "rb").read()

i = d.find(b"MIIEpAIBAAKCAQEA")
if i != -1:
    j = d.find(b"\"", i)
    blob = d[i:j].decode('utf-8')

    pem_key = "-----BEGIN RSA PRIVATE KEY-----\n"
    # break the long string into clean 64-character lines for standard PEM formatting
    pem_key += "\n".join([blob[k:k+64] for k in range(0, len(blob), 64)])
    pem_key += "\n-----END RSA PRIVATE KEY-----\n"

    with open(ROOT_DIR + "rsa_private_key.pem", "w", encoding="utf-8") as f:
        f.write(pem_key)


i = d.find(b"b+gJJKG56gAz")
if i != -1:
    j = d.find(b"\"", i)
    blob = d[i:j].decode('utf-8')

    pem_sig = "-----BEGIN SIGNATURE-----\n"
    # break the long string into clean 64-character lines for standard PEM formatting
    pem_sig += "\n".join([blob[k:k+64] for k in range(0, len(blob), 64)])
    pem_sig += "\n-----END SIGNATURE-----\n"

    with open(ROOT_DIR + "signature.pem", "w", encoding="utf-8") as f:
        f.write(pem_sig)
