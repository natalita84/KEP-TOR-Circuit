import rsa
from Crypto.Cipher import AES
import os


class Packet:
    def __init__(self, src_id, op, dest, payload):
        """
        Payload[0] will consist of a serialized header that indicates the operation 
        and the destination

        Payload[1] will consist of the sub-packet (or none in the case of a create message)
        Payload[1] will 
        """
        self.src = src_id
        self.op = op
        self.dest = dest
        self.payload = None
        self.__payload = payload[1]
        self.msg = payload[0]

    def decrypt_rsa(self, prikey):
        self.__payload = rsa.decrypt(self.msg, prikey)
        self.__payload = self.__payload.decode('utf-8')
        self.decrypt_packet()
        return True

    def decrypt_aes(self, aes_key):
        aes_obj = AES.new(aes_key[0:32], AES.MODE_CBC, 'This is an IV456')
        decrypted_msg = aes_obj.decrypt(self.msg.strip())
        if decrypted_msg == self.msg:
            return False
        self.msg = decrypted_msg.decode('utf-8')
        self.decrypt_packet()
        return True

    def decrypt_packet(self):
        self.payload = self.__payload

    def __str__(self):
        if (self.op, self.dest, self.payload) == (None, None, None):
            return "This packet is encrypted"
        return "\nOP: {}, Destination: {}, Payload: {}".format(self.op, self.dest, self.payload)
