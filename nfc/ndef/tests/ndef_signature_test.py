import unittest
import random

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


class TestSettingSignatureDirectly(unittest.TestCase):
    def test_setting_directly(self):
        signature = b'0E\x02 g\xff\x81\x98\xbbI\x9b \x0e[\xe9\xb0\xfc}\x1bB\x05i;W\x0b\xc0p\xf2|r\xeas\xaf\xcei\xaf\x02!\x00\xe62\xf29P\r\x8a\xa1\xf85\ti\xa9\xb0"5\xe0\xfbr\x05\xd8\xd8EW\x10}\x99\x96\tl,F'
        signature_record = SignatureRecord(signature_uri=None,
                                           signature_type=SignatureType.ECDSA_DSS_P256,
                                           certificate_chain=[bytes([random.randint(0, 255) for _ in range(317)])],
                                           certificate_format=CertificateFormat.M2M,
                                           next_certificate_uri=None)

        signature_record.signature = signature

        b = signature_record.to_bytes()

        print(b)
