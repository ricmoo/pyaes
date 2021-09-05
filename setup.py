#!/usr/bin/env python

from setuptools import find_packages, setup

LONG_DESCRIPTION = '''A pure-Python implementation of the AES (FIPS-197)
block-cipher algorithm and common modes of operation (CBC, CFB, CTR, ECB,
OFB) with no dependencies beyond standard Python libraries. See README.md
for API reference and details.'''

setup(name = 'pyaes',
      version = '1.6.1',
      description = 'Pure-Python Implementation of the AES block-cipher and common modes of operation',
      long_description = LONG_DESCRIPTION,
      author = 'Richard Moore',
      author_email = 'pyaes@ricmoo.com',
      url = 'https://github.com/ricmoo/pyaes',
      packages = find_packages(), 
      classifiers = [
          'Topic :: Security :: Cryptography',
          'License :: OSI Approved :: MIT License',
      ],
      license = "License :: OSI Approved :: MIT License",
     )
