import pyaes

# A 256 bit (32 byte) key
key = "123456789012345ef890123456789012"

# For some modes of operation we need a random initialization vector
# of 16 bytes
iv = "9988776655443310"


# Each block into the mode of operation must be a multiple of the segment
# size. For this example we choose 8 bytes.
aes = pyaes.AESModeOfOperationCFB(key, iv = iv, segment_size = 4)
plaintext =  "1234567890123456"
ciphertext = aes.encrypt(plaintext)

# '''v\xa9\xc1w"\x8aL\x93\xcb\xdf\xa0/\xf8Y\x0b\x8d\x88i\xcb\x85rmp
#    \x85\xfe\xafM\x0c)\xd5\xeb\xaf'''
#print repr(ciphertext)


# The cipher-block chaining mode of operation maintains state, so 
# decryption requires a new instance be created
aes = pyaes.AESModeOfOperationCFB(key, iv = iv, segment_size = 4)
decrypted = aes.decrypt(ciphertext)
#print decrypted
# True
#print decrypted == plaintext

print "Unencrypted data: ", plaintext
print "Encrypted data  : ", ciphertext
print "Decrypted data  : ", decrypted
print "Enc == Dec      : ", decrypted == plaintext
