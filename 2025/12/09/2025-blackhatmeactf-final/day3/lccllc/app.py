#!/usr/bin/env python3
#
# BlackHat MEA 2025 Finals :: LCC LLC
#
# By Polymero
#

#------------------------------------------------------------------------------------------------------------------------------#
#   IMPORTS                                                                                                                    #
#------------------------------------------------------------------------------------------------------------------------------#
# Documentation imports
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union

# Native imports
import os
import time
import json
import base64
import hashlib

# External dependencies
from flask import *   # pip install Flask

# Local imports
from crypto import McEliece

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{D3BUGG1NG_1S_FUN}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()

#------------------------------------------------------------------------------------------------------------------------------#
#   UTILITY FUNCTIONS                                                                                                          #
#------------------------------------------------------------------------------------------------------------------------------#
B64ALP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

def B64Encode(x: bytes) -> str:
    """ Encodes a bytestring into url-safe base64. """
    return base64.urlsafe_b64encode(x).decode().strip('=')

def B64Decode(x: str) -> bytes:
    """ Decodes a url-safe base64 string into bytes. """
    assert all(i in B64ALP for i in x)
    return base64.urlsafe_b64decode(x.encode() + b'===')

#------------------------------------------------------------------------------------------------------------------------------#
#   TOKEN CLASS                                                                                                                #
#------------------------------------------------------------------------------------------------------------------------------#
class LCC:
    """
    Login Code Cryptography based on McEliece with binary Goppa codes.
    """
    def __init__(self, key: bytes, m: int, t: int) -> None:
        self.hkey = key
        self.code = McEliece.Generate(
            m = m,
            t = t,
            n = 2 ** m - 1
        )

    def HashErrorLocs(self, salt: bytes, timestamp: bytes = None) -> Tuple[bytes, set, bytes]:
        """  """
        if timestamp is None:
            timestamp = int(time.time() * 1000).to_bytes(6, 'big')
        n, t = self.code.n, self.code.t
        nbit, tbit = n.bit_length(), t.bit_length()
        eloc = []
        i = 0
        while len(eloc) < t:
            hint = int.from_bytes(hashlib.sha512(self.hkey + salt + timestamp + i.to_bytes(2, 'big')).digest(), 'big')
            while hint and len(eloc) < t:
                k = hint & (2 ** nbit - 1)
                if k < n:
                    eloc.append(k)
                hint >>= nbit
            i += 1
        if len(eloc) != t:
            raise ValueError()
        etag = sum([eloc.index(j) * t ** i for i,j in enumerate(sorted(eloc))]).to_bytes(-(-(t * tbit) // 8), 'big')
        return timestamp, set(eloc), etag

    def GenerateToken(self, username: str, admin: bool = False) -> str:
        """ Generates a token. """
        salt = os.urandom(24)
        token = json.dumps({
            'username' : username,
            'admin' : admin,
            'salt' : B64Encode(salt)
        }).encode()
        timestamp, eloc, etag = self.HashErrorLocs(salt)
        encToken = self.code.Encrypt(token, eloc)
        return '.'.join(B64Encode(i) for i in [timestamp, salt, etag, encToken])
    
    def LoadToken(self, token: str) -> dict:
        """ Loads a token. """
        try:
            timestamp, salt, etag, encToken = [B64Decode(i) for i in token.split('.')]
            decToken, eloc = self.code.Decrypt(encToken)
            loadedToken = json.loads(decToken.strip(b'\0'))
        except:
            raise ValueError('Failed to load token...')
        # _, _eloc, _etag = self.HashErrorLocs(salt, timestamp)
        try:
            # assert _eloc == eloc
            # assert _etag == etag
            assert salt == B64Decode(loadedToken['salt'])
        except:
            raise ValueError('Invalid token...')
        return loadedToken

#------------------------------------------------------------------------------------------------------------------------------#
#   FLASK APP                                                                                                                  #
#------------------------------------------------------------------------------------------------------------------------------#
app = Flask(__name__)
app.secret_key = os.urandom(16)

lcc = LCC(
    key = app.secret_key,
    m = 11,
    t = 27
)

# Homepage
@app.route('/', methods=['GET'])
def index():
    token = request.cookies.get('token')
    if token:
        try:
            userData = lcc.LoadToken(token)
            flash('Succesfully loaded your token.', 'success')
            if userData['admin'] == True:
                content = FLAG.decode()
            else:
                content = 'Nothing to see here. Where you looking for something?'
            return render_template(
                'index.html',
                username = ' ' + userData['username'],
                content = content
            )
        except ValueError as e:
            flash('ERROR:: {}'.format(str(e)), 'error')
        except Exception as e:
            print('ERROR:: {}'.format(str(e)))
            flash('Something went wrong...', 'error')
    else:
        flash('No token found. Get a token by visiting "./gettoken/<username>".', 'warning')
    return render_template('index.html', username='', content='Please load your token or generate a new one.')

# Get token
@app.route('/gettoken/<username>')
def gettoken(username):
    resp = make_response(redirect('/'))
    resp.set_cookie('token', lcc.GenerateToken(username))
    return resp

if __name__ == '__main__':
    app.run(
        host = '0.0.0.0'
    )