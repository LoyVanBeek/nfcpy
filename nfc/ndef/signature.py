"""Implementation of:
Signature Record Type Definition
Technical Specification
Version 2.0
2014-11-26
[SIGNATURE]
NFC Forum

The M2M certificate implementation is a separate module, not included in this project.
One implementation is at https://github.com/LoyVanBeek/m2m_certificates"""

from enum import Enum
import io

from .record import Record

def debug(i):
    print("{0:08b}".format(i))

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
    >>> sig.signature = ...
    >>>
    """

    RECORD_TYPE = 'urn:nfc:wkt:Sig'

    def __init__(self,
                 version=0x20, signature=None,
                 certificate_chain=None, signature_uri=None, signature_type=None, hash_type=HashType.SHA_256_SHS, certificate_format=None,
                 next_certificate_uri=None,
                 data=None):
        """
        Construct a Signature record from the given parameters.

        :param version: a tuple of (major, minor) version number. OR a Record, so its .data can be parsed for a SignatureRecord
        :type signature_type SignatureType
        :type hash_type HashType
        :param signature_uri Whether to include the actual signature (then set False) or an URI reference to it (then set to True)
        :type signature_uri string the URI of the signature
        :param certificate_chain a sequence of certificates. Each element must be a bytes-like object.
        :type certificate_chain [bytes]
        :param certificate_format indicates the type of certificate for all of the certificates in certificate_chain
        :type certificate_format CertificateFormat
        """
        super(SignatureRecord, self).__init__(SignatureRecord.RECORD_TYPE)

        self._version = None
        self.certificate_chain = None
        self.certificate_format = None
        self.as_uri = None
        self.uri = None
        self.signature_type = None
        self.hash_type = None
        self.signature = None
        self.next_certificate_uri = None

        if isinstance(version, Record):  # In that case, we parse the data of the Record to extract our fields from its .data
            record = version
            if record.type == self.type:
                self.name = record.name
                self.data = record.data
            else:
                raise ValueError("record type mismatch")
        else:
            assert version != None and signature_type != None
            if signature_type != SignatureType.NoSignaturePresent:
                assert certificate_chain and certificate_format != None and hash_type != None

            self._version = version
            self.certificate_chain = certificate_chain
            self.certificate_format = certificate_format
            self.as_uri = signature_uri != None
            self.uri = signature_uri if self.as_uri else None
            self.signature_type = signature_type
            self.hash_type = hash_type if signature_type != SignatureType.NoSignaturePresent else None
            self.signature = signature
            self.next_certificate_uri = next_certificate_uri

    @property
    def data(self):
        if self.signature_type != SignatureType.NoSignaturePresent:
            if not self.signature:
                raise ValueError("This SignatureRecord has no signature yet. Use the sign-method to generate a signature")

            return bytes(self.version + self.signature_field + self.certificate_chain_field)
        else:
            return bytes(self.version + self.signature_field)  # See [SIGNATURE] sec 3.3.3, 1st bullet point

    @data.setter
    def data(self, value):
        buffer = io.BytesIO(value)
        self.version = buffer.read(1)[0]

        self._read_signature_field(buffer)

        if self.signature_type != SignatureType.NoSignaturePresent:  # See [SIGNATURE] sec 3.3.3, 1st bullet point
            self._read_certificate_chain_field(buffer)

    @property
    def version(self):
        return bytes([self._version])

    @version.setter
    def version(self, value):
        self._version = value

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
            return bytes([URI_present | self.signature_type.value, self.hash_type.value]) + \
                   len(self.signature).to_bytes(2, "big") + \
                   self.signature

    @signature_field.setter
    def signature_field(self, data):
        """Parse the data of the signature field
        :type data bytes"""
        buffer = io.BytesIO(data)
        self._read_signature_field(buffer)

    def _read_signature_field(self, f):
        """Read a signature field from a file-like object
        :type f io.BytesIO"""
        first_byte = f.read(1)[0]
        self.as_uri = (first_byte & 0b10000000) > 0

        select_sig_type_bits = 0b01111111
        sig_type = first_byte & select_sig_type_bits
        self.signature_type = SignatureType(sig_type)

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
                self.hash_type = HashType(f.read(1)[0])

                length = int.from_bytes(f.read(2), "big", signed=False)
                self.signature = f.read(length)
        else:
            if self.signature_type != SignatureType.NoSignaturePresent:
                self.hash_type = HashType(f.read(1)[0])

                length = int.from_bytes(f.read(2), "big", signed=False)
                self.signature = f.read(length)
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

        cert_bytes = [self._encode_certificate_field(cert) for cert in self.certificate_chain]
        cert_store = b''.join(cert_bytes)  # A solution based on f writing would be better here as well

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
    def _encode_uri_subfield(uri):
        utf8 = uri.encode('utf8')
        length = len(utf8).to_bytes(2, 'big')
        return bytes(length + utf8)

    @certificate_chain_field.setter
    def certificate_chain_field(self, data):
        buffer = io.BytesIO(data)
        self._read_certificate_chain_field(buffer)

    def _read_certificate_chain_field(self, f):
        """Read a signature field from a file-like object
        :type f io.BytesIO"""
        first_byte = f.read(1)[0]
        uri_present = (first_byte & 0b10000000) == 1

        select_cert_format_bits = 0b01110000
        cert_format_bits = first_byte & select_cert_format_bits
        cert_format = cert_format_bits >> 4
        self.certificate_format = CertificateFormat(cert_format)

        select_nbr_of_certs_bits = 0b00001111
        nbr_of_certs = first_byte & select_nbr_of_certs_bits

        certificate_chain = []

        for _ in range(nbr_of_certs):
            length = int.from_bytes(f.read(2), 'big')
            certificate_chain += [f.read(length)]

        self.certificate_chain = certificate_chain

        if uri_present:
            length = int.from_bytes(f.read(2), 'big')
            self.next_certificate_uri = f.read(length)
        else:
            self.next_certificate_uri = None

    def __str__(self):
        return "SignatureRecord(version={vers}, as_uri={as_uri}, signature_type={sigtype}, signature={signature})".format(
            vers=self.version,
            as_uri=self.as_uri,
            sigtype=self.signature_type,
            signature=self.signature)

    def __repr__(self):
        return "SignatureRecord(version={vers}, as_uri={as_uri}, signature_type={sigtype}, signature={signature}," \
               " hash_type={hsh}, certificate_format={certfmt}, certificate_chain={chain}, next_certificate_uri={nxt_cert_uri})".format(
            vers=self._version,
            as_uri=self.as_uri,
            sigtype=self.signature_type,
            signature=self.signature,
            hsh=self.hash_type,
            certfmt=self.certificate_format,
            chain=self.certificate_chain,
            nxt_cert_uri=self.next_certificate_uri)

    def __eq__(self, other):
        if isinstance(other, SignatureRecord):
            return self._version            == other._version \
                and self.certificate_chain  == other.certificate_chain \
                and self.certificate_format == other.certificate_format \
                and self.as_uri             == other.as_uri \
                and self.signature_type     == other.signature_type \
                and self.hash_type          == other.hash_type \
                and self.signature          == other.signature \
                and self.next_certificate_uri == other.next_certificate_uri
        else:
            return False
