from pydispatch import dispatcher
import hashlib
import rsa
import time
from utils import *
from packet import Packet
from diffiehellman.diffiehellman import DiffieHellman


class Node:

    def __init__(self, id):
        self.setup_keys()
        self.connect_to_signals()
        self.id = id
        self.send_ops = {
            OP.CREATED: self.get_created_packet,
            OP.EXTENDED: self.get_extended_packet
        }
        self.hop_table = {1: HopPair(prev=None, next=None)}

    def setup_keys(self):
        self.dhke = DiffieHellman(key_length=1024)
        self.dhke.generate_public_key()
        self.__dh_sharedkey = None
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        (self.pubkey, self.__privkey) = rsa.newkeys(1024)

    def connect_to_signals(self):
        dispatcher.connect(self.handle_extend, signal=OP.EXTEND, sender=dispatcher.Any)
        dispatcher.connect(self.handle_create,
                           signal=OP.CREATE, sender=dispatcher.Any)
        dispatcher.connect(self.handle_created, signal=OP.CREATED, sender=dispatcher.Any)

    def handle_extend(self, packet):
        if packet.dest != self.id:
            return None
        iniciopKp=time.time()
        print("{}: Handling EXTEND packet from {}".format(self.id, packet.src))
        if packet.decrypt_aes(self.__dh_sharedkey):
            print("{}: Decryption of EXTEND packet from {} SUCCESS".format(self.id, packet.src))
            forward_packet = packet.payload
            self.hop_table[1].next = packet.dest
            dispatcher.send(signal=forward_packet.op, sender=self, packet=forward_packet)
            return
        print("{}: Decryption of EXTEND packet from {} FAIL".format(self.id, packet.src))
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')

    def handle_create(self, packet):
        if packet.dest != self.id:
            return None
        iniciopKp=time.time()
        print("{}: Handling CREATE packet from {}".format(self.id, packet.src))
        if not packet.decrypt_rsa(self.__privkey):
            print("{}: Decryption of CREATE packet from {} FAIL".format(self.id, packet.src))
            return
        print("{}: Decryption of CREATE packet from {} SUCCESS".format(self.id, packet.src))
        other_key = int(packet.payload)
        self.dhke.generate_shared_secret(other_key)
        self.__dh_sharedkey = self.dhke.shared_key
        self.hop_table[1].prev = packet.src
        self.send_packet(self.hop_table[1].prev, OP.CREATED)
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')

    def send_packet(self, receiver, op, payload=None):
        iniciopKp=time.time()
        packet = self.send_ops[op](receiver, payload)
        dispatcher.send(signal=op, sender=self, packet=packet)
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')

    def get_created_packet(self, receiver, payload=None):
        iniciopKp=time.time()
        key_hash = hashlib.sha1(
            str(self.__dh_sharedkey).encode("utf-8")).hexdigest()
        msg = (self.dhke.public_key, key_hash)
        packet = Packet(src_id=self.id, op=OP.CREATED,
                        dest=receiver, payload=(msg, None))
        print("{}: Sending CREATED packet to {}".format(self.id, receiver))
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')
        return packet

    def get_extended_packet(self, receiver, payload):
        iniciopKp=time.time()
        packet = Packet(self.id, OP.EXTENDED, receiver, payload)
        print("{}: Sending EXTENDED packet to {}".format(self.id, receiver))
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')
        return packet

    def handle_created(self, packet):
        if packet.dest != self.id:
            return None
        iniciopKp=time.time()
        print("{}: Handling CREATE packet from {}".format(self.id, packet.src))
        dh_pub_key, key_hash = packet.msg
        encrypted_dh_pair = aes_encrypt("{}|||{}".format(dh_pub_key, key_hash), self.__dh_sharedkey)
        self.send_packet(self.hop_table[1].prev, OP.EXTENDED, (encrypted_dh_pair, None))
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')

    def __str__(self):
        return self.id
