#!/usr/bin/env python3

import serial
import time
import re
import hashlib

PORT = "/dev/cu.usbserial-10"
BAUD_RATE = 115200

PASSWORD = "danrgwygtrkvk"
LIST_CMD = "0"
DUMP_CMD = "1"
ROOT_DIR = "../"

def init(stream):
    time.sleep(2)
    raw_data = stream.readline()
    print(raw_data.decode('utf-8'))

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


def main():
    with serial.Serial(PORT, BAUD_RATE, timeout=2) as stream:
        init(stream)

        # 1. insert Dan's password
        w(stream, PASSWORD)
        print(PASSWORD)

        res = r(stream).decode('utf-8').strip()
        print(res)

        # 2. list memory locations
        w(stream, LIST_CMD)
        res = r(stream).decode('utf-8').strip()
        print(res)

        # 3. extract memory locations via regex
        #    captures cmd, start, end, name
        pattern = re.compile(r"\{(\d+)\}\s*\((\d+),\s*(\d+)\)\s*([\w-]+):?\s*")
        matches = pattern.findall(res)
        for match in matches:
            cmd, start, end, location = match

            # 4. dump location
            print(DUMP_CMD)
            w(stream, DUMP_CMD)
            res = r(stream).decode('utf-8').strip()
            print(res)

            print(cmd)
            w(stream, cmd)
            res = stream.read_until(b'stop' + b'\r\n').decode('utf-8').strip()
            print(res)
            bin = r(stream, num_bytes=int(end)+1)
            # print(bin)
            res = r(stream).decode('utf-8').strip()
            print(res)

            # 5. save location bin and digest
            digest = hashlib.sha256(bin).hexdigest()
            with open(ROOT_DIR + location + ".bin", "wb") as f:
                f.write(bin)
            with open(ROOT_DIR + location + "_SHA256", "w") as f:
                f.write(digest)



if __name__ == "__main__":
    raise SystemExit(main())
