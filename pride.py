#!/usr/bin/env python3
# -*- coding: utf8, -*-
"""python-PRIDE

Simple implementation of PRIDE in python 3.

This implementation does *not* make any claims regarding security!

See https://eprint.iacr.org/2014/453

https://github.com/thomwiggers/python-pride

Author: Thom Wiggers
Licence: BSD
"""
from __future__ import print_function, unicode_literals

import six
from itertools import chain


def xor(a, b):
    """Compute the xor of two arrays

    >>> xor([1,0,1], [0, 1, 0])
    [1, 1, 1]
    """
    assert len(a) == len(b)
    return [x ^ y for (x, y) in zip(a, b)]


class Pride(object):

    """Implements PRIDE

    Usage::

        >>> from binascii import unhexlify, hexlify
        >>> p = Pride(unhexlify(b'00000000000000000000000000000000'))
        >>> hexlify(p.encrypt(unhexlify(b'0000000000000000'))
        ...         ) == b'82b4109fcc70bd1f'
        True
        >>> hexlify(p.encrypt(unhexlify(b'ffffffffffffffff'))
        ...        ) == b'd70e60680a17b956'
        True
        >>> hexlify(p.decrypt(unhexlify(b'd70e60680a17b956'))
        ...        ) == b'ffffffffffffffff'
        True
        >>> p = Pride(unhexlify(b'ffffffffffffffff0000000000000000'))
        >>> hexlify(p.encrypt(unhexlify(b'0000000000000000'))
        ...        ) == b'28f19f97f5e846a9'
        True
        >>> p = Pride(unhexlify(b'0000000000000000ffffffffffffffff'))
        >>> hexlify(p.encrypt(unhexlify(b'0000000000000000'))
        ...        ) == b'd123ebaf368fce62'
        True
        >>> p = Pride(unhexlify(b'0000000000000000fedcba9876543210'))
        >>> hexlify(p.encrypt(unhexlify(b'0123456789abcdef'))
        ...        ) == b'd1372929712d336e'
        True

    Identity:

        >>> hexlify(p.decrypt(p.encrypt(unhexlify(b'0000000000000000')))
        ...        ) == b'0000000000000000'
        True

    """

    def __init__(self, key):
        if not len(key) == 16 or not (isinstance(key, six.binary_type) or
                                      isinstance(key, bytearray)):
            raise ValueError("Incorrect key format")
        self.rounds = 20

        key = bytearray(key)  # python 2 support

        self.k_1 = key[8:]
        self.k_0 = key[:8]
        self.k_2 = self.k_0

    def encrypt(self, plain_text):
        if not (isinstance(plain_text, six.binary_type)
                and len(plain_text) == 8):
            raise ValueError("argument should be an 8-byte bytearray")

        plain_text = bytearray(plain_text)  # python 2 support

        state = _permute_inverse(plain_text)
        state = xor(state, self.k_0)

        for i in range(1, self.rounds):
            round_key = _key_derivation(self.k_1, i)
            state = _round_function_enc(state, round_key)

        round_key = _permute_inverse(_key_derivation(self.k_1,
                                                     self.rounds))
        state = xor(state, round_key)
        state = _apply_sbox(state)

        state = _permute(xor(state, self.k_2))

        return bytearray(state)

    def decrypt(self, cipher_text):
        cipher_text = bytearray(cipher_text)  # python 2 str support

        if not len(cipher_text) == 8:
            raise ValueError("argument should be an 8-byte bytearray. "
                             "Type: %s, Length: %d" % (type(cipher_text),
                                                       len(cipher_text)))
        state = _permute_inverse(cipher_text)
        state = xor(state, self.k_2)

        state = _apply_sbox_inverse(state)
        state = xor(state, _permute_inverse(_key_derivation(self.k_1,
                                                            self.rounds)))

        for i in reversed(range(1, self.rounds)):
            round_key = _key_derivation(self.k_1, i)
            state = _round_function_dec(state, round_key)

        state = _permute(xor(state, self.k_0))

        return bytearray(state)


def _round_function_enc(state, round_key):
    """Encryption round function

    >>> from binascii import unhexlify
    >>> k = _key_derivation(unhexlify(b'0000000000000000'), 1)
    >>> _round_function_dec(
    ...     _round_function_enc(unhexlify(b'ffffffffffffffff'), k), k)
    [255, 255, 255, 255, 255, 255, 255, 255]
    """
    state, round_key = bytearray(state), bytearray(round_key)  # py2 support
    round_key = _permute_inverse(round_key)
    state = xor(state, round_key)
    state = _apply_sbox(state)
    state = _permute(state)
    state = [state[1] | state[0] << 8, state[3] | state[2] << 8,
             state[5] | state[4] << 8, state[7] | state[6] << 8]
    state[0] = _apply_matrix(_L0, state[0])
    state[1] = _apply_matrix(_L1, state[1])
    state[2] = _apply_matrix(_L2, state[2])
    state[3] = _apply_matrix(_L3, state[3])
    state = list(
        chain.from_iterable(((x & 0xff00) >> 8, x & 0xff) for x in state))
    state = _permute_inverse(state)

    return state


def _round_function_dec(state, round_key):
    """Decryption round function"""
    state, round_key = bytearray(state), bytearray(round_key)  # py2 support

    state = _permute(state)

    state = [state[1] | state[0] << 8, state[3] | state[2] << 8,
             state[5] | state[4] << 8, state[7] | state[6] << 8]

    state[0] = _apply_matrix(_L0_inverse, state[0])
    state[1] = _apply_matrix(_L1_inverse, state[1])
    state[2] = _apply_matrix(_L2_inverse, state[2])
    state[3] = _apply_matrix(_L3_inverse, state[3])
    state = list(
        chain.from_iterable(((x & 0xff00) >> 8, x & 0xff) for x in state))
    state = _permute_inverse(state)

    state = _apply_sbox_inverse(state)

    round_key = _permute_inverse(round_key)
    state = xor(state, round_key)

    return state


def _permute(state):
    r"""Permute state

    >>> _permute(bytearray([0xff] * 8))
    bytearray(b'\xff\xff\xff\xff\xff\xff\xff\xff')
    >>> _permute(bytearray([0x88] * 4 + [0x00] * 4))
    bytearray(b'\xff\x00\x00\x00\x00\x00\x00\x00')
    >>> _permute(bytearray([0x44] * 8))
    bytearray(b'\x00\x00\xff\xff\x00\x00\x00\x00')
    >>> _permute(bytearray([0x11] * 8))
    bytearray(b'\x00\x00\x00\x00\x00\x00\xff\xff')
    >>> _permute(bytearray([0x00] * 4 + [0x11] * 4))
    bytearray(b'\x00\x00\x00\x00\x00\x00\x00\xff')
    >>> import random
    >>> state = bytearray([random.randint(0,255) for i in range(8)])
    >>> _permute_inverse(_permute(state)) == state
    True
    >>> _permute_inverse(
    ...     _permute(bytearray(b'\x12\x34\x56\x78\x90\xab\xcd\xef'))) == (
    ...     bytearray(b'\x12\x34\x56\x78\x90\xab\xcd\xef'))
    True
    """
    state = bytearray(state)  # python 2 support

    source = list(chain.from_iterable(
        (((state[i] & 0xf0) >> 4, state[i] & 0xf) for i in range(8))))

    state_ = [0] * 4
    for i in range(4):
        for s in range(16):
            state_[i] |= (source[s] & (2**(3-i))) >> (3-i) << (15-s)

    newstate = [0] * 8
    for i in range(4):
        newstate[2 * i] = (state_[i] & 0xff00) >> 8
        newstate[2 * i + 1] = (state_[i] & 0xff)

    return bytearray(newstate)


def _permute_inverse(state):
    r"""Reverse a permutation

    >>> _permute_inverse([0x00] * 6 + [0xff] * 2)
    bytearray(b'\x11\x11\x11\x11\x11\x11\x11\x11')
    >>> _permute_inverse([0xff] + [0x00] * 7)
    bytearray(b'\x88\x88\x88\x88\x00\x00\x00\x00')
    >>> _permute_inverse([0, 0, 255, 255, 0, 0, 0, 0]) == bytearray([0x44]*8)
    True
    """
    state_ = [0x0] * 16

    source = (state[1] | state[0] << 8, state[3] | state[2] << 8,
              state[5] | state[4] << 8, state[7] | state[6] << 8)

    for i in range(16):
        for s in range(4):
            state_[i] |= (source[s] & (2**(15-i))) >> (15-i) << (3-s)

    result = [a << 4 | b for (a, b) in zip(state_[::2], state_[1::2])]

    return bytearray(result)


def _apply_matrix(matrix, state):
    """Apply one of the permutation matrices

    >>> import random
    >>> state = random.randint(0,0xFFFF)
    >>> _apply_matrix(_L0_inverse, _apply_matrix(_L0, state)) == state
    True
    >>> _apply_matrix(_L1_inverse, _apply_matrix(_L1, state)) == state
    True
    >>> _apply_matrix(_L2_inverse, _apply_matrix(_L2, state)) == state
    True
    >>> _apply_matrix(_L3_inverse, _apply_matrix(_L3, state)) == state
    True
    >>> _apply_matrix(_L0, 0b0101101011010111) == 0b000111110000010
    True
    """
    state_ = []
    for row in matrix:
        newrow = 0
        for i in range(16):
            if row[i] == 1:
                newrow ^= (state & (2**(15-i))) >> (15-i)
        state_.append(newrow)
    x = 0
    for j in range(16):
        x |= state_[j] << (15-j)
    return x


def _apply_sbox(state):
    """sbox lookup for 8x8bit registers

    >>> _apply_sbox(
    ...     [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]) == (
    ...     [0x04, 0x8f, 0x15, 0xe9, 0x27, 0xac, 0xbd, 0x63])
    True
    """
    for i in range(8):
        x = state[i]
        state[i] = _sbox(x & 0xF) | _sbox((x & 0xF0) >> 4) << 4

    return state


def _apply_sbox_inverse(state):
    """sbox lookup for 8x8bit registers

    >>> _apply_sbox_inverse(
    ...     [0x04, 0x8f, 0x15, 0xe9, 0x27, 0xac, 0xbd, 0x63]) == (
    ...     [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
    True
    """
    for i in range(8):
        x = state[i]
        state[i] = _sbox_i(x & 0xF) | _sbox_i((x & 0xF0) >> 4) << 4

    return state


def _sbox(bits):
    """Sbox lookup.

    UNSAFE in scenarios where cache timing is possible

    >>> _sbox(0xf)
    3
    >>> _sbox(0x8)
    2
    """
    return _Sbox_table[bits]


def _sbox_i(bits):
    """Sbox lookup.

    UNSAFE in scenarios where cache timing is possible

    >>> _sbox_i(0x0)
    0
    >>> _sbox_i(0x1)
    4
    >>> _sbox_i(0x6)
    14
    """
    return dict(((x, i) for (i, x) in enumerate(_Sbox_table)))[bits]


def _key_derivation(k_1, round_):
    """Subkey derivation function f_i

    >>> _key_derivation([0] * 8, 0)
    [0, 0, 0, 0, 0, 0, 0, 0]
    >>> _key_derivation([0] * 8, 1)
    [0, 193, 0, 165, 0, 81, 0, 197]
    >>> _key_derivation([0] * 8, 2)
    [0, 130, 0, 74, 0, 162, 0, 138]
    >>> _key_derivation([1] * 8, 2)
    [1, 131, 1, 75, 1, 163, 1, 139]
    """
    def g_0(x):
        return (x + 193 * round_) % 256

    def g_1(x):
        return (x + 165 * round_) % 256

    def g_2(x):
        return (x + 81 * round_) % 256

    def g_3(x):
        return (x + 197 * round_) % 256

    k_1 = bytearray(k_1)

    key = [k_1[0], g_0(k_1[1]), k_1[2], g_1(k_1[3]),
           k_1[4], g_2(k_1[5]), k_1[6], g_3(k_1[7])]
    return key


_Sbox_table = [0, 4, 8, 0xf, 1, 5, 0xe, 9, 2, 7, 0xa, 0xc, 0xb, 0xd, 6, 3]

_L0 = _L0_inverse = (
    (0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0),
    (0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0),
    (0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1),
    (1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0),
    (0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0),
    (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0),
    (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1),
    (1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    (0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
    (0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0),
    (0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1),
    (1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    (0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    (0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    (0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0),
)

_L1 = (
    (1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    (0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    (0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
    (0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0),
    (0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    (0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0),
    (1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0),
    (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0),
    (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0),
    (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1),
    (0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1),
    (0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0),
)

_L2 = (
    (0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    (0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0),
    (1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0),
    (1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    (0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    (0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
    (0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0),
    (0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1),
    (0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0),
    (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0),
    (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0),
    (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1),
)

_L3 = _L3_inverse = (
    (1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    (0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
    (0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0),
    (0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1),
    (1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    (0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    (0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    (0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0),
    (0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0),
    (0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0),
    (0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1),
    (1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0),
    (0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0),
    (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0),
    (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1),
)

_L1_inverse = (
    (0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0),
    (1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1),
    (1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    (0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    (0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    (0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    (0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    (0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0),
    (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
    (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0),
    (0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0),
    (0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1),
    (0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1),
    (1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0),
    (0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0),
    (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0),
)

_L2_inverse = (
    (0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    (0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    (0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    (0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0),
    (0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0),
    (1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1),
    (1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    (0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    (0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1),
    (1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0),
    (0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0),
    (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0),
    (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
    (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0),
    (0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0),
    (0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1),
)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
