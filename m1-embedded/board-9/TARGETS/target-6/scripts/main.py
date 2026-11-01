#!/usr/bin/env python3

import serial
import time
import re

ALAN_PASSWORD = "alanzvnswtxmjxjcikzpmemegrjqaugjmidnmxiynjghxmdnlffbmw"
CC_PASSWORD = "cncgijucsnrdyfwsatpqxiodhlnqrfxutzzygjtmnkmofphuhzzaj"
PORT = "/dev/cu.usbserial-10"
BAUD_RATE = 115200


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
                # Read chunks dynamically to check for delimiter alignment
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
    # initial wait for arduino setup
    time.sleep(2)

    # read the initial prompt
    res = r(stream).decode('utf-8').strip()
    print(res)

    # 1. log in as alan
    w(stream, ALAN_PASSWORD)
    print(ALAN_PASSWORD)
    res = r(stream).decode('utf-8').strip()
    print(res)

    # 2. authenticate as cc
    w(stream, CC_PASSWORD)
    print(CC_PASSWORD)
    res = r(stream).decode('utf-8').strip()
    print(res)


def main():
    with serial.Serial(PORT, BAUD_RATE, timeout=2) as stream:

        init(stream)

        # the idea is:

        # loop
        #  send guess to the device
        #  read response from the device

        #  if response is correct
        #  then print the secret output and stop program
        #  else extract the expected_number from the error response

        #  if we are seeing expected_number for the second time and haven't updated our guess yet
        #  then set guess to expected_number
        #  else save expected_number to seen_numbers

        filler = "42"
        count = 1
        matched = False
        seen = {}
        while True:
            w(stream, filler)
            print(filler)

            text = r(stream).decode('utf-8').strip()

            if re.search("Incorrect", text) is None:
                print(text)
                text = stream.read_until("Dan").decode('utf-8').strip()
                print(text)
                return

            number = re.findall(r'\d+', text)[-1]

            if number in seen and not matched:
                filler = number
                matched = True
                count = 0
                continue
            else:
                seen[number] = True

            print(text)
            count = count + 1


if __name__ == "__main__":
    raise SystemExit(main())
