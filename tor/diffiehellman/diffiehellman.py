"""
diffiehellmann declares the main key exchange class.
"""

__version__ = '0.13.3'

from hashlib import sha256

from .decorators import requires_private_key
from .exceptions import MalformedPublicKey, RNGError
from .primes import PRIMES
import time

try:
    from ssl import RAND_bytes
    rng = RAND_bytes
except(AttributeError, ImportError):
    raise RNGError


class DiffieHellman:
    """
    Implements the Diffie-Hellman key exchange protocol.

    """

    def __init__(self,
                 key_length=1024):

        self.key_length = key_length
        self.generator = 2
        #self.prime = 32416190071
        self.prime = 2744494569502724254154323577949187234454434817339889529296977291684020654530622930987331258971145839229196442900343
        # 381 bits
        #self.prime = 8146684324432522082900670738352641877281963272089666951897546572264245793135014
        #self.prime = 236744496149483565763557367433668286966347186310877203864673384403103818366787719743494711121936433350364582401558248295891501615714079213481047398389289558367796444657130431
        #self.prime=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFF

    def generate_private_key(self):
        """
        Generates a private key of key_length bits and attaches it to the object as the __private_key variable.

        :return: void
        :rtype: void
        """

        iniciopKp=time.time()
        key_length = self.key_length // 8 + 8
        key = 0

        try:
            key = int.from_bytes(rng(key_length), byteorder='big')
        except:
            key = int(hex(rng(key_length)), base=16)

        self.__private_key = key
        finpKp=time.time()
        print('########## Tiempo  Priv Key##########:',(finpKp-iniciopKp), 'segundos')


    def verify_public_key(self, other_public_key):
        return self.prime - 1 > other_public_key > 2 and pow(other_public_key, (self.prime - 1) // 2, self.prime) == 1

    @requires_private_key
    def generate_public_key(self):
        """
        Generates public key.

        :return: void
        :rtype: void
        """
        iniciopKp=time.time()
        self.public_key = pow(self.generator,
                              self.__private_key,
                              self.prime)
        finpKp=time.time()
        print('########## Tiempo  Pub Key ##########:',(finpKp-iniciopKp), 'segundos')
    @requires_private_key
    def generate_shared_secret(self, other_public_key, echo_return_key=False):
        """
        Generates shared secret from the other party's public key.

        :param other_public_key: Other party's public key
        :type other_public_key: int
        :param echo_return_key: Echo return shared key
        :type bool
        :return: void
        :rtype: void
        """

        self.shared_secret = pow(other_public_key,
                                 self.__private_key,
                                 self.prime)

        shared_secret_as_bytes = self.shared_secret.to_bytes(self.shared_secret.bit_length() // 8 + 1, byteorder='big')

        _h = sha256()
        _h.update(bytes(shared_secret_as_bytes))

        self.shared_key = _h.hexdigest()

        if echo_return_key is True:
            return self.shared_key
