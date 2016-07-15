import unittest

import ecdsa
from ..signature import SignatureRecord, SignatureType, CertificateFormat, HashType
from ..record import Record

class TestEmptySignature(unittest.TestCase):
    def setUp(self):
        self.sig = SignatureRecord(as_uri=None,
                              signature_type=SignatureType.NoSignaturePresent)

    def test_empty_signature(self):
        self.assertEqual(bytes(self.sig), b'\x11' # header flags. 0x11 = 0b00010001. MessageEnd and MessageBegin are both zero, those will be set only when the record is embedded in a message
                                          b'\x03' # Type length (Sig is 3 letters)
                                          b'\x02' # Payload length. After the type, there come 2 bytes.
                                          b'Sig'  # Record type
                                          b'\x20' # version
                                          b'\x00' # sigtype = no sig present. This ends the message
                        )

    def test_parsing(self):
        # Exact same data as in test_empty_signature above
        data = b'\x20' \
               b'\x00'

        # import ipdb; ipdb.set_trace()
        parsed_sig = SignatureRecord(data=data)
        self.assertEqual(parsed_sig.as_uri, self.sig.as_uri)
        self.assertEqual(parsed_sig.signature_type, self.sig.signature_type)


class TestSigningAndVerification(unittest.TestCase):
    def setUp(self):
        self.record = Record('urn:nfc:wkt:T', 'identifier', bytes(b'Hello World'))
        self.record_data = bytes(self.record)

        self.sig = SignatureRecord(as_uri=None, signature_type=SignatureType.ECDSA_DSS_P256,
                                   certificate_chain=[b'dummy'], certificate_format=CertificateFormat.M2M)

        self.curve = ecdsa.NIST256p
        self.signing_key = ecdsa.SigningKey.generate(curve=self.curve)
        self.verifying_key = self.signing_key.get_verifying_key()

    def testVerificationOk(self):
        signature = self.sig.sign(self.record_data, key_str_curve=(self.signing_key.to_string(), self.curve))

        verified = self.sig.verify(data_to_verify=self.record_data, key_str_curve=(self.verifying_key.to_string(), self.curve))

        self.assertEqual(verified, True)

    def testVerificationWrong(self):
        signature = self.sig.sign(self.record_data, key_str_curve=(self.signing_key.to_string(), self.curve))

        tampered_data = bytearray(self.record_data)
        tampered_data[2] -= 1  # Small modification
        verified = self.sig.verify(data_to_verify=tampered_data, key_str_curve=(self.verifying_key.to_string(), self.curve))

        self.assertEqual(verified, False)
