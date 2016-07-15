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

class CertificateFormat(Enum):
    X_509 = 0x00
    M2M = 0x01

class SignatureRecord(Record):
    """NDEF Signature Records are used to sign the previous records in an NDEF message.
    Usage:
    >>> record1 = Record(...)
    >>> sig = SignatureRecord(...)
    >>> message = Message(record1, sig) # TODO: Take into account that the ME flag of a record must be considered as zero when signing
    >>> sig.sign(record1.to_bytes(), "private_key.pem")
    >>>
    """

    _ecdsa_mapping = {  SignatureType.ECDSA_DSS_P256: ecdsa.NIST256p,
                        SignatureType.ECDSA_DSS_P192: ecdsa.NIST192p,
                        SignatureType.ECDSA_DSS_P224: ecdsa.NIST224p}

    _mappings = _ecdsa_mapping # + other mappings

    def __init__(self,
                 version=0x20, signature=None,
                 certificate_chain=None, as_uri=None, signature_type=None, hash_type=None, certificate_format=None,
                 next_certificate_uri=None,
                 data=None):
        """
        Construct a Signature record from the given parameters.

        :param version: a tuple of (major, minor) version number
        :type signature_type SignatureType
        :type hash_type HashType
        :param as_uri Whether to include the actual signature (then set False) or an URI reference to it (then set to True)
        :type as_uri bool
        :param certificate_chain a sequence of certificates. Each element must be a bytes-like object.
        :type certificate_chain [bytes]
        :param certificate_format indicates the type of certificate for all of the certificates in certificate_chain
        :type certificate_format CertificateFormat
        """
        super(SignatureRecord, self).__init__('urn:nfc:wkt:Sig')

        if not data:
            self.version = version
            self.certificate_chain = certificate_chain
            self.certificate_format = certificate_format
            self.as_uri = as_uri
            self.signature_type = signature_type
            self.hash_type = hash_type
            self.signature = signature
            self.uri = None
            self.next_certificate_uri = next_certificate_uri
        else:
            # Then parse all the data to a signature and have it verified later on
            # TODO
            self.version = data[0]
            self.signature_field = data[1:]

            pass

    def sign(self, data_to_sign, pem_file=None, der_file=None, key_str_curve=None):
        """
        Calculate the signature for the data_to_sign
        :param data_to_sign: bytes of which to calculate a signature
        :param pem_file: path to .pem file containing a private key
        :param der_file: path to a DER encoded file containing a private key
        :param key_str_curve: tuple of a private key and its curve. E.g. (ecdsa.SigningKey.generate(curve=ecdsa.NIST256p), ecdsa.NIST256p)
        :return:
        """
        if self.signature_type in self._ecdsa_mapping:
            if pem_file:
                sk = ecdsa.SigningKey.from_pem(pem_file) #.generate(curve=self._ecdsa_mapping[self.signature_type])
            elif der_file:
                sk = ecdsa.SigningKey.from_der(der_file)
            elif key_str_curve:
                sk = ecdsa.SigningKey.from_string(key_str_curve[0], curve=key_str_curve[1])
            else:
                raise TypeError("Specify at least a one of pem_file, der_file or key_str")

            signature = sk.sign(data_to_sign)
        else:
            raise NotImplementedError("SignatureType {sigtype} not yet implemented. Available types are {available}".format(sigtype=self.signature_type,
                                                                                                                            available=self._mappings))
        self.signature = signature
        return signature

    def verify(self, data_to_verify, pem_file=None, der_file=None, key_str_curve=None):
        """Check whether this signature matches with the data to verify
        :param pem_file: path to .pem file containing a public key
        :param der_file: path to a DER encoded file containing a public key
        :param key_str_curve: tuple of a public key and its curve. E.g. (ecdsa.SigningKey.generate(curve=ecdsa.NIST256p), ecdsa.NIST256p)
        """
        if self.signature_type in self._ecdsa_mapping:
            if pem_file:
                vk = ecdsa.VerifyingKey.from_pem(pem_file) #.generate(curve=self._ecdsa_mapping[self.signature_type])
            elif der_file:
                vk = ecdsa.VerifyingKey.from_der(der_file)
            elif key_str_curve:
                vk = ecdsa.VerifyingKey.from_string(key_str_curve[0], curve=key_str_curve[1])
            else:
                raise TypeError("Specify at least a one of pem_file, der_file or key_str")
            try:
                return vk.verify(self.signature, data_to_verify)
            except ecdsa.BadSignatureError:
                return False
        else:
            raise NotImplementedError("SignatureType {sigtype} not yet implemented. Available types are {available}".format(sigtype=self.signature_type,
                                                                                                                            available=self._mappings))

    @property
    def data(self):
        return bytes([self.version]) + self.signature_field + self.certificate_chain_field

    @property
    def signature_field(self):
        """The signature field is layed out in table 4 in section 3.3.3 of the specification.
        - 1 bit URI_present
        - 7 bits Signature Type
        - 8 bits hash type
        - 16 bits signature/URI length
        - N octets of Signature / URI"""
        URI_present = 0b10000000 if self.as_uri else 0b00000000

        if self.signature_type == SignatureType.NoSignaturePresent:
            return bytes([URI_present | self.signature_type.value])  # If no signature present: don't put the other fields there
        else:
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

    @property
    def certificate_chain_field(self):
        first_byte =  0b00000000

        uri_present = 0b10000000 if self.next_certificate_uri else 0
        first_byte |= uri_present

        cert_format = int(self.certificate_format.value) << 4
        first_byte |= cert_format

        nbr_of_certs = len(self.certificate_chain)
        assert nbr_of_certs <= 15  # Only 4 bits available
        first_byte |= nbr_of_certs

        first = bytes([first_byte])

        cert_store = bytes([self._encode_certificate_field(cert) for cert in self.certificate_chain])

        if self.next_certificate_uri:
            cert_uri = self._encode_uri_subfield(self.next_certificate_uri)
            return bytes(first + cert_store + cert_uri)
        else:
            return bytes(first + cert_store)

    @staticmethod
    def _encode_certificate_field(certificate_bytes):
        length = len(certificate_bytes).to_bytes(2, 'big')
        return bytes(length + certificate_bytes)

    @staticmethod
    def _decode_certificate_field(byte_sequence):
        """Extracts 1 certificate field from a longer byte sequence.
        The bytes after the certificate are also returned
        :rtype tuple (content, remainder of byte_sequence)"""
        length = int.from_bytes(byte_sequence[:2], byteorder='big')
        content = byte_sequence[2:2+length]

        return content, byte_sequence[:2+length]

    @staticmethod
    def _encode_uri_subfield(uri):
        utf8 = uri.encode('utf8')
        length = len(utf8).to_bytes(2, 'big')
        return bytes(length + utf8)

    @staticmethod
    def _decode_uri_subfield(byte_sequence):
        length = int.from_bytes(byte_sequence[:2], byteorder='big')
        utf8 = byte_sequence[2:2+length]
        content = utf8.decode("utf-8")
        return content

    @certificate_chain_field.setter
    def certificate_chain_field(self, data):
        uri_present = (data[0] & 0b10000000) == 1

        select_cert_format_bits = 0b01110000
        cert_format_bits = data[0] & select_cert_format_bits
        cert_format = cert_format_bits >> 4
        self.signature_type = CertificateFormat(cert_format)

        select_nbr_of_certs_bits = 0b000011111
        nbr_of_certs = data[0] & select_nbr_of_certs_bits

        certificate_chain = []

        rest = data[1:]
        for _ in range(nbr_of_certs):
            cert, rest = self._decode_certificate_field(rest)
            certificate_chain += [cert]

        self.certificate_chain = certificate_chain

        if uri_present:
            if rest:
                self.next_certificate_uri = self._decode_uri_subfield(rest)
            else:
                raise ValueError("Certificate chain field indicated an URI would be present but there were no bytes for the URI found")



    def __str__(self):
        return "SignatureRecord(version={vers}, as_uri={as_uri}, signature_type={sigtype}, signature={signature})".format(
            vers=self.version,
            as_uri=self.as_uri,
            sigtype=self.signature_type,
            signature=self.signature)

    def __repr__(self):
        return "SignatureRecord(version={vers}, as_uri={as_uri}, signature_type={sigtype}, signature={signature})".format(
            vers=self.version,
            as_uri=self.as_uri,
            sigtype=self.signature_type,
            signature=self.signature)