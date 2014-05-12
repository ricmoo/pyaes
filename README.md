pyaes
=====

A pure-Python implmentation of the AES block cipher algorithm and the common modes of operation (CBC, CFB, CTR, ECB and OFB).


API
---

All keys may be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes) long.

To generate a random key use:
```python
import os

# 128 bit, 192 bit and 256 bit keys
key_128 = os.urandom(16)
key_192 = os.urandom(24)
key_256 = os.urandom(32)
```

To generate keys from simple-to-remember passwords, consider using a _password-based key-derivation function_ such as [scrypt](https://github.com/ricmoo/pyscrypt).


### Common Modes of Operation

There are many modes of operations, each with various pros and cons. In general though, the **CBC** and **CTR** modes are recommended. The **ECB is NOT recommended.**, and is included primarilty for completeness.

Each of the following examples assumes the following key:
```python
import pyaes

# A 256 bit (32 byte) key
key = "This_key_for_demo_purposes_only!"

# For some modes of operation we need a random initialization vector
# of 16 bytes
iv = "InitializationVe"
```


#### Counter Mode of Operation (recommended)

```python
aes = pyaes.AESModeOfOperationCTR(key)
plaintext = "Text may be any length you wish, no padding is required"
ciphertext = aes.encrypt(plaintext)

# '''\xb6\x99\x10=\xa4\x96\x88\xd1\x89\x1co\xe6\x1d\xef;\x11\x03\xe3\xee
#    \xa9V?wY\xbfe\xcdO\xe3\xdf\x9dV\x19\xe5\x8dk\x9fh\xb87>\xdb\xa3\xd6
#    \x86\xf4\xbd\xb0\x97\xf1\t\x02\xe9 \xed'''
print repr(ciphertext)

# The counter mode of operation maintains state, so decryption requires
# a new instance be created
aes = pyaes.AESModeOfOperationCTR(key)
decrypted = aes.decrypt(ciphertext)

# True
print decrypted == plaintext

# To use a custom initial value
counter = pyaes.Counter(initial_value = 100)
aes = pyaes.AESModeOfOperationCTR(key, counter = counter)
ciphertext = aes.encrypt(plaintext)

# '''WZ\x844\x02\xbfoY\x1f\x12\xa6\xce\x03\x82Ei)\xf6\x97mX\x86\xe3\x9d
#    _1\xdd\xbd\x87\xb5\xccEM_4\x01$\xa6\x81\x0b\xd5\x04\xd7Al\x07\xe5
#    \xb2\x0e\\\x0f\x00\x13,\x07'''
print repr(ciphertext)
```


#### Cipher-Block Chaining (recommended)

```python
aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
plaintext = "TextMustBe16Byte"
ciphertext = aes.encrypt(plaintext)

# '\xd6:\x18\xe6\xb1\xb3\xc3\xdc\x87\xdf\xa7|\x08{k\xb6'
print repr(ciphertext)


# The cipher-block chaining mode of operation maintains state, so 
# decryption requires a new instance be created
aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
decrypted = aes.decrypt(ciphertext)

# True
print decrypted == plaintext
```


#### Cipher Feedback

```python
# Each block into the mode of operation must be a multiple of the segment
# size. For this example we choose 8 bytes.
aes = pyaes.AESModeOfOperationCFB(key, iv = iv, segment_size = 8)
plaintext =  "TextMustBeAMultipleOfSegmentSize"
ciphertext = aes.encrypt(plaintext)

# '''v\xa9\xc1w"\x8aL\x93\xcb\xdf\xa0/\xf8Y\x0b\x8d\x88i\xcb\x85rmp
#    \x85\xfe\xafM\x0c)\xd5\xeb\xaf'''
print repr(ciphertext)


# The cipher-block chaining mode of operation maintains state, so 
# decryption requires a new instance be created
aes = pyaes.AESModeOfOperationCFB(key, iv = iv, segment_size = 8)
decrypted = aes.decrypt(ciphertext)

# True
print decrypted == plaintext
```


#### Output Feedback Mode of Operation

```python
aes = pyaes.AESModeOfOperationOFB(key, iv = iv)
plaintext = "Text may be any length you wish, no padding is required"
ciphertext = aes.encrypt(plaintext)

# '''v\xa9\xc1wO\x92^\x9e\rR\x1e\xf7\xb1\xa2\x9d"l1\xc7\xe7\x9d\x87(\xc26s
#    \xdd8\xc8@\xb6\xd9!\xf5\x0cM\xaa\x9b\xc4\xedLD\xe4\xb9\xd8\xdf\x9e\xac
#    \xa1\xb8\xea\x0f\x8ev\xb5'''
print repr(ciphertext)

# The counter mode of operation maintains state, so decryption requires
# a new instance be created
aes = pyaes.AESModeOfOperationOFB(key, iv = iv)
decrypted = aes.decrypt(ciphertext)

# True
print decrypted == plaintext
```


#### Electronic Codebook (NOT recommended)

```python
aes = pyaes.AESModeOfOperationECB(key)
plaintext = "TextMustBe16Byte"
ciphertext = aes.encrypt(plaintext)

# 'L6\x95\x85\xe4\xd9\xf1\x8a\xfb\xe5\x94X\x80|\x19\xc3'
print repr(ciphertext)


# Since there is no state stored in this mode of operation, it
# is not necessary to create a new aes object for decryption.
#aes = pyaes.AESModeOfOperationECB(key)
decrypted = aes.decrypt(ciphertext)

# True
print decrypted == plaintext
```


### AES block cipher

Generally you should use one of the modes of operation above. This may however be useful for experimenting with a custom mode of operation or dealing with encrypted blocks.


The block cipher requires exactly one block of data to encrypt or decrypt, and each block is 16 bytes.

```python
import pyaes

# 16 bytes long
plaintext_block = "Hello World!!!!!"

aes = pyaes.AES()

ciphertext = 
```

Performance
-----------

There is a test case provided in _/tests/test-aes.py_ which does some basic performance testing (its primary purpose is moreso as a regression test).

Based on that test, this library is about 30x slower than [PyCrypto](https://www.dlitz.net/software/pycrypto/) for CBC, ECB and OFB; about 80x slower for CFB; and 300x slower for CTR.

The PyCrypto documentation makes reference to the counter call being responsible for the speed problems of the counter (CTR) mode of operation, which is why they use a specially optimized counter. I will investigate this problem further in the future.


FAQ
---

#### Why do this?

The short answer, *why not?*

The longer answer, is for m [pyscrypt](https://github.com/ricmoo/pyscrypt) library. I required a pure-Python AES implementation that supported 256-bit keys with the counter (CTR) mode of operation. After searching, I found several implementations, but all were missing CTR or only supported 128 bit keys. After all the work of learning AES inside and out to implement the library, it was only a marginal amount of extra work to library-ify a more general solution. So, *why not?*

#### How do I get a question I have added?

E-mail me at pyaes@ricmoo.com with any questions, suggestions, comments, et cetera.


#### Can I give you my money?

Umm... Ok? :-)

_Bitcoin_  - `1LNdGsYtZXWeiKjGba7T997qvzrWqLXLma`
