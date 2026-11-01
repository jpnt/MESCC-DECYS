#!/bin/sh

openssl asn1parse -in ../rsa_private_key.pem > ../asn1parse.txt

openssl rsa -text -in ../rsa_private_key.pem > ../rsa-text.txt
