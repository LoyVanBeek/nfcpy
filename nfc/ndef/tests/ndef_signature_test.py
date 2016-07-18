import unittest
import random

import ecdsa
from ..signature import SignatureRecord, SignatureType, CertificateFormat, HashType
from ..record import Record
from ..message import Message

class TestEmptySignature(unittest.TestCase):
    def setUp(self):
        self.sig = SignatureRecord(signature_uri=None,
                                   signature_type=SignatureType.NoSignaturePresent)

        header =  bytes( b'\x11'    # header flags. 0x11 = 0b00010001. MessageEnd and MessageBegin are both zero, those will be set only when the record is embedded in a message
                         b'\x03'    # Type length (Sig is 3 letters)
                         b'\x02')    # Payload length. After the type (Sig), there come 2 bytes of payload
        rectype =        b'Sig'     # Record type
        payload = bytes( b'\x20'    # version
                         b'\x00')   # sigtype = no sig present. This ends the message
        self.bytes = header + rectype + payload

    def test_empty_signature(self):
        self.assertEqual(bytes(self.sig), self.bytes)

    def test_parsing_from_raw_bytes(self):
        parsed_sig = SignatureRecord(Record(data=self.bytes))
        self.assertEqual(parsed_sig.as_uri, self.sig.as_uri)
        self.assertEqual(parsed_sig.signature_type, self.sig.signature_type)

    def test_parsing_via_message(self):
        orig_msg = Message(self.sig)
        msg_bytes = orig_msg.to_bytes()

        parsed_msg = Message(msg_bytes)
        sig_rec = parsed_msg[0]
        parsed_sig = SignatureRecord(sig_rec)

        self.assertEqual(self.sig._version, parsed_sig._version)
        self.assertEqual(self.sig.certificate_chain, parsed_sig.certificate_chain)
        self.assertEqual(self.sig.certificate_format, parsed_sig.certificate_format)
        self.assertEqual(self.sig.as_uri, parsed_sig.as_uri)
        self.assertEqual(self.sig.signature_type, parsed_sig.signature_type)
        self.assertEqual(self.sig.signature, parsed_sig.signature)
        self.assertEqual(self.sig.next_certificate_uri, parsed_sig.next_certificate_uri)
        self.assertEqual(self.sig.hash_type, parsed_sig.hash_type)

        self.assertEqual(self.sig, parsed_sig)


class TestSigningAndVerification(unittest.TestCase):
    def setUp(self):
        self.record = Record('urn:nfc:wkt:T', 'identifier', bytes(b'Hello World'))
        self.record_data = bytes(self.record)

        self.sig = SignatureRecord(signature_uri=None, signature_type=SignatureType.ECDSA_DSS_P256,
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


class TestSignatureWithDummyCertificate(unittest.TestCase):
    def setUp(self):
        self.dummy_certificate_0 = bytes([random.randint(0, 255) for _ in range(317)])  # No real certificate, using length as reported by m2m/m2m_certificate_format.py
        self.dummy_certificate_1 = bytes([random.randint(0, 255) for _ in range(317)])   # No real certificate, using length as reported by m2m/m2m_certificate_format.py

        to_be_signed_data = bytes(list(range(100)))

        self.curve = ecdsa.NIST256p
        self.signing_key = ecdsa.SigningKey.generate(curve=self.curve)
        self.verifying_key = self.signing_key.get_verifying_key()

        self.sig = SignatureRecord(signature_uri=None,
                                   signature_type=SignatureType.ECDSA_DSS_P256,
                                   certificate_chain=[self.dummy_certificate_0], #, self.dummy_certificate_1],
                                   certificate_format=CertificateFormat.M2M)

        self.signature = self.sig.sign(to_be_signed_data, key_str_curve=(self.signing_key.to_string(), self.curve))

    def test_signature_field_roundtrip(self):
        data = bytes(self.sig.signature_field)

        parsed_sig = SignatureRecord(signature_uri=None, signature_type=SignatureType.NoSignaturePresent)

        import io
        buffer = io.BytesIO(data)
        parsed_sig._read_signature_field(buffer)

        self.assertEqual(self.sig.as_uri, parsed_sig.as_uri)
        self.assertEqual(self.sig.signature_type, parsed_sig.signature_type)
        self.assertEqual(self.sig.hash_type, parsed_sig.hash_type)
        self.assertEqual(self.sig.signature, parsed_sig.signature)

    def test_certchain_field_roundtrip(self):
        data = bytes(self.sig.certificate_chain_field)

        # Expected length:
        # 1 byte for URI_Present+Cert_format+Nbr_of_certs
        # 2x :
        #   2 bytes for length
        #   317 bytes for each dummy certificate
        #
        # Total: 320
        self.assertEqual(len(data), 320)

        parsed_sig = SignatureRecord(signature_uri=None, signature_type=SignatureType.NoSignaturePresent)

        import io
        buffer = io.BytesIO(data)
        parsed_sig._read_certificate_chain_field(buffer)

        self.assertEqual(self.sig.certificate_chain, parsed_sig.certificate_chain)
        self.assertEqual(self.sig.certificate_format, parsed_sig.certificate_format)
        self.assertEqual(self.sig.next_certificate_uri, parsed_sig.next_certificate_uri)

        self.assertEqual(self.dummy_certificate_0, parsed_sig.certificate_chain[0])
        # self.assertEqual(self.dummy_certificate_1, parsed_sig.certificate_chain[1])

    def test_round_trip(self):
        # Exact same data as in test_empty_signature above
        data = bytes(self.sig)
        # print(len(data))

        # There should be:
        # 6 bytes of header
        # 3 bytes of type
        # In the payload:
        # 1 byte of version
        # 68 bytes for the signature field:
        #  - 2 byte header of signature field
        #  - 64 bytes of signature + 2 bytes to indicate that length
        #
        # 320 bytes for the certificate chain field
        #  - 1 byte of header
        #  - 1x certificate of 317 bytes as defined in setUp + 2 bytes per certificate to indicate that length
        #
        # The total is then 6+3+1+68+320 = 398

        self.assertEqual(len(data), 398)

        parsed_sig = SignatureRecord(Record(data=data))

        self.assertEqual(self.sig._version, parsed_sig._version)
        self.assertEqual(self.sig.certificate_chain, parsed_sig.certificate_chain)
        self.assertEqual(self.sig.certificate_format, parsed_sig.certificate_format)
        self.assertEqual(self.sig.as_uri, parsed_sig.as_uri)
        self.assertEqual(self.sig.signature_type, parsed_sig.signature_type)
        self.assertEqual(self.sig.hash_type, parsed_sig.hash_type)
        self.assertEqual(self.sig.signature, parsed_sig.signature)
        self.assertEqual(self.sig.next_certificate_uri, parsed_sig.next_certificate_uri)

        self.assertEqual(self.dummy_certificate_0, parsed_sig.certificate_chain[0])
        # self.assertEqual(self.dummy_certificate_1, parsed_sig.certificate_chain[1])

    def test_message_round_trip(self):
        orig_msg = Message(self.sig)
        msg_bytes = orig_msg.to_bytes()

        parsed_msg = Message(msg_bytes)
        sig_rec = parsed_msg[0]
        sig = SignatureRecord(sig_rec)

        self.assertEqual(self.sig, sig)