#!/usr/local/bin/python
import os
import random

try:
    flag = open("/flag.txt", "rb").read()
except FileNotFoundError:
    flag = b"FLAG{******** REDACTED ********}"

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

message = input("msg> ").encode()
used = False
for _ in range(20000):
    noise = random.randbytes(len(message))
    # print("noise:", noise.hex()) # You don't need to hear the noise :)
    if input("use? ") == "y":
        message = xor(message, noise)
        used = True
if used and message == b"give me the flag!":
    print(flag)
else:
    print("What I heard:", message.hex())
