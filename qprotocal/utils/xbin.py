#!/usr/bin/env python

import binascii
import hashlib
import random


class Xbin(object):
    # def __init__(self):

    # get random hex by length
    def get_random_hex(self, length=1, is_bytes=0):
        random_hex = ''
        for _ in range(0, length):
            random_hex += "{:0>2x}".format(random.randrange(0, 255))
        if is_bytes:
            return bytes().fromhex(random_hex)
        else:
            return random_hex


    def get_md5_value(src, is_bytes=0):
        md5 = hashlib.md5()
        md5.update(src)
        md5_digest = md5.hexdigest()
        if is_bytes:
            return bytes().fromhex(md5_digest)
        else:
            return md5_digest
