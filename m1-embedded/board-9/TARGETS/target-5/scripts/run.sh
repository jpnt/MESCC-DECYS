#!/bin/sh

set -e

# signature.pem is pem-wrapped base64; pkeyutl -in wants raw bytes.
# strip the header/footer and base64-decode to the raw 256-byte signature first.
sed '1d;$d' signature.pem | base64 -d > signature.raw

openssl pkeyutl -decrypt -inkey rsa_private_key.pem -in signature.raw > ../decrypted-hash.bin

cat ../decrypted-hash.bin
