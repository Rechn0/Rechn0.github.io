#!/usr/bin/env python3
#
# BlackHat MEA 2025 Finals :: Limeade
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
from Crypto.Cipher import AES   # pip install pycryptodome
from Crypto.Util.Padding import pad, unpad

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
class Lime:
    """ You can roll it, spin it, squeeze it, stretch it... It's a lime! """
    def __init__(self, volume: int) -> None:
        self.suco = []
        rinds = list(range(volume))
        while rinds:
            self.suco.append(rinds.pop(randbelow(len(rinds))))
            
    def Roll(self, suco: list) -> list:
        """ Rolls the lime. """
        assert len(suco) == len(self.suco)
        return [suco[i] for i in self.suco]
    
    def Spin(self, suco: list) -> list:
        """ Spins the lime. """
        assert len(suco) == len(self.suco)
        return [suco[self.suco.index(i)] for i in range(len(self.suco))]
    
    def Squeeze(self, suco: list) -> list:
        """ Squeezes the lime. """
        assert not len(suco) % (len(self.suco) - 1).bit_length()
        parts = (len(self.suco) - 1).bit_length()
        pieces = [suco[i:i + parts] for i in range(0, len(suco), parts)]
        pieces = [sum(j * 2 ** i for i,j in enumerate(k)) for k in pieces]
        pieces = [self.suco[i] for i in pieces]
        pieces = [[(j >> i) & 1 for i in range(parts)] for j in pieces]
        return [i for j in pieces for i in j]
    
    def Stretch(self, suco: list) -> list:
        """ Stretches the lime. """
        assert not len(suco) % (len(self.suco) - 1).bit_length()
        parts = (len(self.suco) - 1).bit_length()
        pieces = [suco[i:i + parts] for i in range(0, len(suco), parts)]
        pieces = [sum(j * 2 ** i for i,j in enumerate(k)) for k in pieces]
        pieces = [self.suco.index(i) for i in pieces]
        pieces = [[(j >> i) & 1 for i in range(parts)] for j in pieces]
        return [i for j in pieces for i in j]
    
class Juicer:
    """ A juicer to juice the limes... for that sweet, sweet limeade! """
    def __init__(self, limes: list, volume: int, sugars: int, iceCubes: int, secretIngredient: int) -> None:
        self.limes = limes
        self.volume = volume
        self.sugars = sugars
        self.iceCubes = iceCubes
        self.secretIngredient = secretIngredient

    def _Stir(self, one: list, two: list) -> list:
        """ Stirs the juice. """
        assert len(one) == len(two)
        return [i ^ j for i,j in zip(one, two)]

    def Pour(self, cup: bytes, tap: int) -> bytes:
        """ Pours the juice from the tap. """
        assert len(cup) * 8 <= self.volume
        cup = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(cup, 'big'), n=self.volume)]
        tap = [int(i) for i in '{:0{n}b}'.format((self.secretIngredient + tap) % (2**self.volume), n=self.volume)]
        for i in range(self.sugars):
            cup = self._Stir(self.limes[3*i].Roll(tap), cup)
            for _ in range(self.iceCubes):
                cup = self.limes[3*i + 1].Squeeze(self.limes[3*i + 2].Roll(cup))
        cup = self._Stir(self.limes[3*(i + 1)].Roll(tap), cup)
        return int(''.join(str(i) for i in cup), 2).to_bytes(self.volume // 8, 'big')
    
    def Depour(self, cup: bytes, tap: int) -> bytes:
        """ Sucks the juice back up through the tap... Ehm??? """
        assert len(cup) * 8 <= self.volume
        cup = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(cup, 'big'), n=self.volume)]
        tap = [int(i) for i in '{:0{n}b}'.format((self.secretIngredient + tap) % (2**self.volume), n=self.volume)]
        cup = self._Stir(self.limes[3*self.sugars].Roll(tap), cup)
        for i in range(self.sugars - 1, -1, -1):
            for _ in range(self.iceCubes):
                cup = self.limes[3*i + 2].Spin(self.limes[3*i + 1].Stretch(cup))
            cup = self._Stir(self.limes[3*i].Roll(tap), cup)
        return int(''.join(str(i) for i in cup), 2).to_bytes(self.volume // 8, 'big').lstrip(b'\x00')

#------------------------------------------------------------------------------------------------------------------------------#
#   MAIN LOOP                                                                                                                  #
#------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":

    # Challenge parameters
    volume = 256
    sugars = 2
    iceCubes = 16

    # Challenge setup
    secretIngredient = randbelow(2 ** volume)
    limes = [Lime(volume) for _ in range(3 * sugars + 1)]
    juicer = Juicer(limes, volume, sugars, iceCubes, secretIngredient)

    HDR = """|
|    ___    __ ___ ___             ______
|   |   |  |__|   Y   .-----.---.-|      \ .-----.
|   |.  |  |  |.      |  -__|  _  |.  |   \|  -__|
|   |.  |__|__|. \_/  |_____|___._|.  |    |_____|
|   |:  |   | |:  |   |           |:  |    /
|   |::.. . | |::.|:. |           |::.. . /
|   `-------' `--- ---'           `------'
|
|  [~] Flag = {}
|"""
    print(HDR.format(B64Encode(FlagCryptor(FLAG, secretIngredient.to_bytes(volume // 8, 'big')))))

    print('|  [~] Look at these beautiful limes I bought this morning ~ !')
    print('|    limes = {}'.format('.'.join(B64Encode(bytes(i.suco)) for i in limes)))
    print('|    I made some limeade with them. Feel free to pour yourself some, as long as you bring your own cup and tap ~ !')

    # Main
    OPS = ['Pour', 'Depour', 'Quit']
    TUI = "|\n|  Menu:\n|    " + "\n|    ".join('[' + i[0] + ']' + i[1:] for i in OPS) + "\n|"

    while True:
        try:

            print(TUI)
            choice = input('|  > ').lower()

            # [Q]uit
            if choice == 'q':
                print("|\n|  [~] Stay safe ~ !\n|")
                break

            elif choice == 'p':
                userInput = input("|  > (B64.B64) ").split('.')
                cupFull = juicer.Pour(B64Decode(userInput[0]), int.from_bytes(B64Decode(userInput[1]), 'big'))
                print('|\n|  [~] Enjoooy ~\n|    cupFull = {}'.format(B64Encode(cupFull)))

            elif choice == 'd':
                userInput = input("|  > (B64.B64) ").split('.')
                cupEmpty = juicer.Depour(B64Decode(userInput[0]), int.from_bytes(B64Decode(userInput[1]), 'big'))
                print('|\n|  [~] Here is your cup back.\n|    cupEmpty = {}'.format(B64Encode(cupEmpty)))

            else:
                print("|\n|  [!] Invalid choice.")

        except KeyboardInterrupt:
            print("\n|\n|  [~] Tchau ~ !\n|")
            break

        except Exception as e:
            print('|\n|  [!] ERROR: {}'.format(e))


