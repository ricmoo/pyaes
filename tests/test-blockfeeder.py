import sys
sys.path.append('../pyaes')

import os
import random

import pyaes
from pyaes.blockfeeder import Decrypter, Encrypter

key = os.urandom(32)

plaintext = os.urandom(1000)

for mode_name in pyaes.AESModesOfOperation:
    mode = pyaes.AESModesOfOperation[mode_name]
    print mode.name

    kw = dict(key = key)
    if mode_name in ('cbc', 'cfb', 'ofb'):
        kw['iv'] = os.urandom(16)

    encrypter = Encrypter(mode(**kw))
    ciphertext = ''

    # Feed the encrypter random number of bytes at a time
    index = 0
    while index < len(plaintext):
        length = random.randint(1, 128)
        if index + length > len(plaintext): length = len(plaintext) - index
        ciphertext += encrypter.feed(plaintext[index: index + length])
        index += length
    ciphertext += encrypter.feed(None)

    decrypter = Decrypter(mode(**kw))
    decrypted = ''

    # Feed the decrypter random number of bytes at a time
    index = 0
    while index < len(ciphertext):
        length = random.randint(1, 128)
        if index + length > len(ciphertext): length = len(ciphertext) - index
        decrypted += decrypter.feed(ciphertext[index: index + length])
        index += length
    decrypted += decrypter.feed(None)

    passed = decrypted == plaintext
    cipher_length = len(ciphertext)
    print "  cipher-length=%(cipher_length)s passed=%(passed)s" % locals()
