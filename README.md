# WinHash
A C++ Hashing wrapper around MS Cryptography API: Next Generation (CNG)

This little project simplifies the usage of CNG hashing functions by hiding all the special API usage management from the user.

It allows to retrieve with a single function call both the resulting hash value as raw data, and as a string.

It also provides an easy way to recursively calculate the Hash of a Hash string value in a loop for cryptographic purposes when we want to apply a hashing function multiple times.

Supported Hashing Algorithms: MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512

Disclaimer
----------
I wrote this for fun to use in other private projects. Use at your own risk.

Author
------
Kyriakos Economou (@kyREcon) / www.anti-reversing.com

MIT License
-----------
Copyright (c) [2019] [Kyriakos Economou]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
