#!/usr/bin/env python3

import serial
import time
import re
from pathlib import Path

ALAN_PASSWORD = "alanzvnswtxmjxjcikzpmemegrjqaugjmidnmxiynjghxmdnlffbmw"
CC_PASSWORD = "cncgijucsnrdyfwsatpqxiodhlnqrfxutzzygjtmnkmofphuhzzaj"
PORT = "/dev/cu.usbserial-10"
BAUD_RATE = 115200
OTP_FIRST_PROBE = 42
PARAMS_FILE = "otp-params.conf"


def load_params(path=PARAMS_FILE):
    params = {}
    with open(path) as f:
        for line in f:
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            params[key.strip().upper()] = int(value.strip())
    return params["A"], params["M"]

def w(stream, data):
    stream.write((data + "\n").encode('utf-8'))
    time.sleep(1)


def r(stream, num_bytes=None, until=None):
    buffer = b''

    while True:
        if num_bytes is not None:
            remaining = num_bytes - len(buffer)

            if remaining <= 0:
                break

            if stream.in_waiting > 0:
                bytes_to_read = min(stream.in_waiting, remaining)
                buffer += stream.read(bytes_to_read)
            else:
                time.sleep(0.01)

        elif until is not None:
            if stream.in_waiting > 0:
                buffer += stream.read(stream.in_waiting)
                if until in buffer:
                    break
            else:
                time.sleep(0.01)

        else:
            if stream.in_waiting > 0:
                buffer += stream.read(stream.in_waiting)
            else:
                time.sleep(0.1)
                if stream.in_waiting == 0:
                    break

    return buffer


def init(stream):
    time.sleep(2)

    res = r(stream).decode('utf-8').strip()
    print(res)

    # 1. log in as alan
    w(stream, ALAN_PASSWORD)
    print(ALAN_PASSWORD)
    res = r(stream).decode('utf-8').strip()
    print(res)

    # 2. authenticate to the C&C with the password recovered in target 5
    w(stream, CC_PASSWORD)
    print(CC_PASSWORD)
    res = r(stream).decode('utf-8').strip()
    print(res)


def next_otp(x, a, m):
    return (a * x) % m


def main():
    with serial.Serial(PORT, BAUD_RATE, timeout=2) as stream:

        init(stream)

        otp_a, otp_m = load_params()

        guess = OTP_FIRST_PROBE

        while True:
            w(stream, str(guess))
            print(guess)

            text = r(stream).decode('utf-8').strip()

            if re.search("Incorrect", text) is None:
                print(text)
                trailing = r(stream).decode('utf-8').strip()
                if trailing:
                    print(trailing)
                return

            print(text)

            revealed = re.search(r"expecting (\d+)", text)
            if revealed:
                guess = next_otp(int(revealed.group(1)), otp_a, otp_m)
            else:
                guess = next_otp(guess, otp_a, otp_m)


if __name__ == "__main__":
    raise SystemExit(main())
