#!/bin/sh

binwalk -E PROGMEM.bin
mv PROGMEM.bin.png ../progmem-entropy.png
