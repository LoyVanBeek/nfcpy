"""Implementation of:
Signature Record Type Definition
Technical Specification
Version 2.0
2014-11-26
[SIGNATURE]
NFC Forum"""

from enum import Enum
import ecdsa

from .record import Record

class SignatureType(Enum):
    # See section 3.3.3.1 and table 5 of the specification
    NoSignaturePresent =            0x00
    RSASSA_PSS_PKCS_1_1024 =        0x01
    RSASSA_PKCS1_v1_5_PKCS_1_1024 = 0x02
    DSA_DSS_1024 =                  0x03
    ECDSA_DSS_P192 =                0x04
    RSASSA_PSS_PKCS_1_2048 =        0x05
    RSASSA_PKCS1_v1_PKCS_1_2048 =   0x06
    DSA_DSS_2048 =                  0x07
    ECDSA_DSS_P224 =                0x08
    ECDSA_DSS_K233 =                0x09
    ECDSA_DSS_B233 =                0x0a
    ECDSA_DSS_P256 =                0x0b
    #RFU                            0x0c_0x7f   Not applicable

class HashType(Enum):
    # See section 3.3.3.1 and table 6 of the specification
    SHA_256_SHS = 0x02
    # Any other value if Reserved for Future Use


class SignatureRecord(Record):
    """NDEF Signature Records are used to sign the previous records in an NDEF message.
    Usage:
    >>> record1 = Record(...)
    >>> sig = SignatureRecord(...)
    >>> message = Message(record1, sig) # First construct the message because the record must know whether is is the first in a message or not.
    >>> sig.sign(record1.to_bytes(), "private_key.pem")
    >>>
    """

    _ecdsa_mapping = {  SignatureType.ECDSA_DSS_P256: ecdsa.NIST256p,
                        SignatureType.ECDSA_DSS_P192: ecdsa.NIST192p,
                        SignatureType.ECDSA_DSS_P224: ecdsa.NIST224p}

    _mappings = _ecdsa_mapping # + other mappings

    def __init__(self,
                 version=None, signature=None,
                 certificate_chain=None, as_uri=None, signature_type=None, hash_type=None,
                 data=None):
        """
        Construct a Signature record from the given parameters.

        :param version: a tuple of (major, minor) version number
        :type signature_type SignatureType
        :type hash_type HashType
        :param as_uri Whether to include the actual signature (then set False) or an URI reference to it (then set to True)
        :type as_uri bool
        """
        super(SignatureRecord, self).__init__('urn:nfc:wkt:Sig')

        if not data:
            self.version = version
            self.chain = certificate_chain
            self.as_uri = as_uri
            self.signature_type = signature_type
            self.hash_type = hash_type
            self.signature = signature
            self.uri = None
        else:
            # Then parse all the data to a signature and have it verified later on
            # TODO

            pass

    def sign(self, data_to_sign, signing_key_file):
        """Calculate the signature for the data_to_sign"""
        if self.signature_type in self._ecdsa_mapping:
            sk = ecdsa.SigningKey.from_pem(signing_key_file) #.generate(curve=self._ecdsa_mapping[self.signature_type])
            signature = sk.sign(data_to_sign)
        else:
            raise NotImplementedError("SignatureType {sigtype} not yet implemented. Available types are {available}".format(sigtype=self.signature_type,
                                                                                                                            available=self._mappings))
        self.signature = signature
        return signature

    def verify(self, data_to_verify, verifying_key_file):
        """Check whether this signature matches with the data to verify"""
        if self.signature_type in self._ecdsa_mapping:
            vk = ecdsa.VerifyingKey.from_pem(verifying_key_file)
            return vk.verify(self.signature, data_to_verify)
        else:
            raise NotImplementedError("SignatureType {sigtype} not yet implemented. Available types are {available}".format(sigtype=self.signature_type,
                                                                                                                            available=self._mappings))

    @property
    def data(self):
        return bytes()

    @data.setter
    def data(self, value):
        pass

    @property
    def signature_field(self):
        """The signature field is layed out in table 4 in section 3.3.3 of the specification.
        - 1 bit URI_present
        - 7 bits Signature Type
        - 8 bits hash type
        - 16 bits signature/URI length
        - N octets of Signature / URI"""
        URI_present = 0b10000000 if self.as_uri else 0b00000000

        return bytes([URI_present | self.signature_type.value,
                      self.hash_type.value,
                      len(self.signature).to_bytes(2, "big"),
                      self.signature])

    @signature_field.setter
    def signature_field(self, data):
        """Parse the data of the signature field
        :type data bytes"""
        self.as_uri = (data[0] & 0b10000000) > 0

        select_sigtype_bits = 0b01111111
        sigtype = data[0] & select_sigtype_bits
        self.signature_type = SignatureType(sigtype)

        if not self.as_uri:
            if self.signature_type == SignatureType.NoSignaturePresent:
                # See section 3.3.3 of the spec: in this condition
                # "the Signature record SHALL NOT be used
                # to verify the preceding record(s) from the beginning of the NDEF message or the previous
                # signature record."
                self.hash_type = None
                self.signature = None
                return
            else:
                self.hash_type = HashType(data[1])

                length = int.from_bytes(data[2:4], "big", signed=False)
                self.signature = data[4:4+length]
        else:
            if self.signature_type != SignatureType.NoSignaturePresent:
                self.hash_type = HashType(data[1])

                length = int.from_bytes(data[2:4], "big", signed=False)
                self.signature = data[4:4+length]
            else:
                raise ValueError("The signature is referenced by URI but SignatureType == 0: No signature present")