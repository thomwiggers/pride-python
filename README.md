python-PRIDE
============

Simple implementation of PRIDE in python 3. Python 2 is currently not supported.

This implementation does *not* make any claims regarding security!

See https://eprint.iacr.org/2014/453

https://github.com/thomwiggers/python-pride

Licence: New BSD

Usage
-----

    from pride import Pride
    p = Pride(key)
    ciphertext = p.encrypt(message)
    plaintext = p.decrypt(ciphertext)

Results will be `bytearray`s
