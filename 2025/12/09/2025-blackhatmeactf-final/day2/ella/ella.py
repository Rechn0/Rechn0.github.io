#!/usr/bin/env python3
#
# BlackHat MEA 2025 Finals :: Ella
#
#

#------------------------------------------------------------------------------------------------------------------------------#
#   IMPORTS                                                                                                                    #
#------------------------------------------------------------------------------------------------------------------------------#
# Documentation imports
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union

# Native imports
import os
import base64
from hashlib import sha256
from secrets import randbelow

# External dependencies
from Crypto.Util.number import getPrime   # pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{D3BUGG1NG_1S_FUN}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()

#------------------------------------------------------------------------------------------------------------------------------#
#   UTILITY FUNCTIONS                                                                                                          #
#------------------------------------------------------------------------------------------------------------------------------#
def B64Encode(x: bytes) -> str:
    """ Encodes a bytestring into url-safe base64. """
    return base64.urlsafe_b64encode(x).decode().strip('=')

def B64Decode(x: str) -> bytes:
    """ Decodes a url-safe base64 string into bytes. """
    return base64.urlsafe_b64decode(x.encode() + b'===')

def FlagCryptor(flag: bytes, secret: bytes) -> bytes:
    """ Encrypts a flag using a given secret. """
    return AES.new(sha256(secret).digest(), AES.MODE_ECB).encrypt(pad(flag, 16))

#------------------------------------------------------------------------------------------------------------------------------#
#   CHALLENGE CLASS                                                                                                            #
#------------------------------------------------------------------------------------------------------------------------------#
class Ella:
    """ Let Ella save your secrets statelessly! """
    def __init__(self, bits: int, size: int, x: int = None) -> None:
        self.bits = bits
        self.size = size
        self.p = getPrime(self.bits)
        if x is None:
            x = randbelow(self.p)
        self.s = [randbelow(self.p) for _ in range(self.size - 1)]
        self.s.append((secret - sum(self.s)) % self.p)
        assert sum(self.s) % self.p == x

    def Update(self) -> None:
        """ Updates inner states. """
        nonces = [0] + [randbelow(self.p) for _ in range(self.size - 1)] + [0]
        for i in range(self.size):
            self.s[i] = (self.s[i] + nonces[i] - nonces[i+1]) % self.p

    def Leak(self, idx: int) -> list:
        """ Leaks inner sta... wait who put this here??? """
        return [(self.s[i] >> idx) & 1 for i in range(self.size)]

#------------------------------------------------------------------------------------------------------------------------------#
#   MAIN LOOP                                                                                                                  #
#------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":

    # Challenge parameters
    ellaBits = 256
    ellaSize = 8

    # Challenge setup
    i = 0
    while True:
        secret = int.from_bytes(sha256(FLAG + i.to_bytes(2, 'big')).digest(), 'big')
        if not secret >> (ellaBits - 1):
            break
        i += 1
    encFlag = FlagCryptor(FLAG, secret.to_bytes(-(-secret.bit_length() // 8), 'big'))

    ella = Ella(
        bits = ellaBits,
        size = ellaSize,
        x = secret
    )

    HDR = """|
|      ,ggggggg,                           
|    ,dP""\""\""Y8b ,dPYb, ,dPYb,            
|    d8'    a  Y8 IP'`Yb IP'`Yb            
|    88     "Y8P' I8  8I I8  8I            
|    `8baaaa      I8  8' I8  8'            
|   ,d8P"\"""      I8 dP  I8 dP    ,gggg,gg 
|   d8"           I8dP   I8dP    dP"  "Y8I 
|   Y8,           I8P    I8P    i8'    ,8I 
|   `Yba,,_______,d8b,_ ,d8b,_ ,d8,   ,d8b,
|     `"Y888888888P'"Y888P'"Y88P"Y8888P"`Y8
|
|    flag = {}
|    p = {}"""
    print(HDR.format(B64Encode(encFlag), B64Encode(ella.p.to_bytes(-(-ella.p.bit_length() // 8), 'big'))))

    # Main
    OPS = ['Leak', 'Quit']
    TUI = "|\n|  Menu:\n|    " + "\n|    ".join('[' + i[0] + ']' + i[1:] for i in OPS) + "\n|"

    while True:
        try:

            print(TUI)
            choice = input('|  > ').lower()

            # [Q]uit
            if choice == 'q':
                print("|\n|  [~] Au revoir ~ !\n|")
                break

            elif choice == 'l':
                idx, num = [int(i) for i in input('|  > (int int) ').split()]

                leakage = 0
                for _ in range(num):
                    ella.Update()
                    leakage <<= ellaSize
                    leakage |= sum([j * 2 ** i for i,j in enumerate(ella.Leak(idx))])
                print('|    leakage = {}'.format(B64Encode(leakage.to_bytes(-(-leakage.bit_length() // 8), 'big'))))

            else:
                print("|\n|  [!] Invalid choice.")

        except KeyboardInterrupt:
            print("\n|\n|  [~] Au revoir ~ !\n|")
            break

        except Exception as e:
            print('|\n|  [!] ERROR: {}'.format(e))