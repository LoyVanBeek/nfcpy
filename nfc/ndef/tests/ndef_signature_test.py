import unittest

import io
from ..signature import SignatureRecord, SignatureType

class TestEmptySignature(unittest.TestCase):
    def setUp(self):
        self.sig = SignatureRecord(as_uri=False,
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

        import ipdb; ipdb.set_trace()
        parsed_sig = SignatureRecord(data=data)
        self.assertEqual(parsed_sig.as_uri, self.sig.as_uri)
        self.assertEqual(parsed_sig.signature_type, self.sig.signature_type)