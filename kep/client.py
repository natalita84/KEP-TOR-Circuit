from pydispatch import dispatcher
from utils import *
from packet import Packet
import rsa
import time
import hashlib
from diffiehellman.diffiehellman import DiffieHellman


class Client:

    def __init__(self, node_table):
        self.next_node = ""
        self.id = "client"
        self.node_table = node_table
        self.send_ops = {
            OP.CREATE: self.get_create_packet,
            OP.EXTEND: self.get_extend_packet
        }
        self.setup_keys()
        self.connect_to_signals()

    def setup_keys(self):
        self.aes_keys = {}
        self.dhke = DiffieHellman()
        self.dhke.generate_public_key()
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        self.__dh_sharedkey = None

    def connect_to_signals(self):
        dispatcher.connect(self.handle_created, signal=OP.CREATED, sender=dispatcher.Any)
        dispatcher.connect(self.handle_extended, signal=OP.EXTENDED, sender=dispatcher.Any)
        dispatcher.connect(self.handle_extended, signal=OP.EXTEND, sender=dispatcher.Any)

    def get_create_packet(self, receivers):
        iniciopKp=time.time()
        receiver = self.node_table[receivers[0]]
        msg = self.dh_pub
        enc_msg = rsa.encrypt(msg, receiver.pubkey)
        packet = Packet(src_id="client", op=OP.CREATE,
                        dest=receiver.id, payload=(enc_msg, None))
        print("client: Sending CREATE packet to {}".format(receiver))
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')
        return packet

    def send_message(self, receivers, op):
        iniciopKp=time.time()
        receivers = receivers.split()
        self.next_node = receivers[len(receivers) - 1]
        packet = self.send_ops[op](receivers)
        dispatcher.send(signal=op, sender=self, packet=packet)
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')

    def handle_created(self, packet):
        if packet.dest != self.id:
            return
        iniciopKp=time.time()
        print("client: Handling CREATED packet from {}".format(packet.src))
        (other_key, key_hash) = packet.msg
        # Generate the shared key
        self.dhke.generate_shared_secret(other_key)
        shared = self.dhke.shared_key
        m_key_hash = hashlib.sha1(str(shared).encode("utf-8")).hexdigest()

        if m_key_hash == key_hash:
            print("{}: DH Hash Comparison from {} SUCCESS".format(self.id, packet.src))
            self.__dh_sharedkey = shared
            self.aes_keys[packet.src] = shared
            print("client: Entry node is now set to: ", self.next_node)
            finpKp=time.time()
            print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')
            return
        print("{}: DH Hash Comparison from {} FAIL".format(self.id, packet.src))
        

    def handle_extended(self, packet):
        if packet.dest != self.id:
            return
        iniciopKp=time.time()
        print("client: Handling CREATED packet from {}".format(packet.src))
        if not packet.decrypt_aes(self.aes_keys[packet.src]):
            print("{}: Decryption of EXTENDED packet from {} FAIL".format(self.id, packet.src))
            return
        print("{}: Decryption of EXTENDED packet from {} SUCCESS".format(self.id, packet.src))
        (other_key, key_hash) = tuple(packet.msg.split('|||'))
        other_key = int(other_key)
        key_hash = key_hash.strip()
        self.dhke.generate_shared_secret(other_key)
        shared = self.dhke.shared_key
        m_key_hash = hashlib.sha1(str(shared).encode("utf-8")).hexdigest()

        if m_key_hash == key_hash:  # Only go through if hash matches
            print("{}: DH Hash Comparison from {} SUCCESS".format(self.id, packet.src))
            self.__dh_sharedkey = shared
            self.aes_keys[packet.src] = shared
            print("client: Connection established with {}".format(self.next_node))
            finpKp=time.time()
            print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')
            return

        print("{}: DH Hash Comparison from {} FAIL".format(self.id, packet.src))
        

    # Extend always gets wrapped with everything in the the AES Keys list
    def get_extend_packet(self, receivers):
        msg = "Type:     Extend"
        iniciopKp=time.time()
        extend_messages = {}
        for j in range(len(receivers) - 1):
            extend_messages[receivers[j]] = aes_encrypt(msg, self.aes_keys[receivers[j]])

        def recursive_extend(recs, node_index):
            if node_index == len(recs) - 1:
                create_packet = self.get_create_packet(recs[node_index:])
                create_packet.src = recs[node_index - 1]
                return create_packet
            return Packet(src_id="client", op=OP.EXTEND, dest=recs[0],
                          payload=(extend_messages[recs[node_index]], recursive_extend(recs, node_index + 1)))

        packet = recursive_extend(receivers, 0)
        finpKp=time.time()
        print('########## Tiempo ##########:',(finpKp-iniciopKp), 'segundos')
        return packet
