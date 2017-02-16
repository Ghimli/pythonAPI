#!/usr/bin/env python3

from bitcoin.wallet import CKey
import base64,time,requests,hashlib

apikey=""
secret=""

def SignECDSA(key, message):
    sig, i = key.sign_compact(message)

    meta = 27 + i
    if key.is_compressed:
        meta += 4

    return base64.b64encode(chr(meta) + sig)

privkey = CKey(base64.b64decode(secret),False)
nonce=str(int(time.time()))
msg = "nonce="+nonce
sign = SignECDSA(privkey, hashlib.sha256(hashlib.sha256("Bitmaszyna.pl API:\n"+msg).digest()).digest())
print(requests.post('https://bitmaszyna.pl/api/funds', data={'nonce':nonce},  headers={'Rest-Key' : apikey, 'Rest-Sign' : sign}).json())
