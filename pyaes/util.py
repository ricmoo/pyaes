# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Why to_bufferable?
# Python 3 is very different from Python 2.x when it comes to strings of text
# and strings of bytes; in Python 3, strings of bytes do not exist, instead to
# represent arbitrary binary data, we must use the "bytes" object. This method
# ensures the object behaves as we need it to.


def append_PKCS7_padding(data):
    pad = 16 - (len(data) % 16)
    return data + bytes(bytearray([pad])) * pad

def strip_PKCS7_padding(data):
    if len(data) % 16 != 0:
        raise ValueError("invalid length")

    pad = bytearray(data)[-1]

    if pad > 16:
        raise ValueError("invalid padding byte")

    return data[:-pad]
