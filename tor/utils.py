from enum import Enum
from Crypto.Cipher import AES


class OP(Enum):
    CREATE, CREATED, EXTEND, EXTENDED, RELAY, RELAYED = range(6)


class HopPair:

    def __init__(self, prev, next):
        self.prev = prev
        self.next = next


def aes_encrypt(msg, key):
    padding_len = get_aes_padding(len(msg))
    msg += " " * padding_len
    obj = AES.new(key[0:32], AES.MODE_CBC, 'This is an IV456')
    enc_msg = obj.encrypt(msg)
    return enc_msg


def get_aes_padding(num):
    for i in range(num):
        if (16 * i) > num:
            return (16 * i) - num
