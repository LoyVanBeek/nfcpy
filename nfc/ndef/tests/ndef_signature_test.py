import unittest

import io
from ..signature import SignatureRecord, SignatureType

class TestEmptySignature(unittest.TestCase):
    def test_empty_signature(self):
        sig = SignatureRecord(as_uri=False,
                              signature_type=SignatureType.NoSignaturePresent)


        self.assertEqual(bytes(sig), b'\x11' # header flags. 0x11 = 0b00010001. MessageEnd and MessageBegin are both zero, those will be set only when the record is embedded in a message
                                     b'\x03' # Type length (Sig is 3 letters)
                                     b'\x02' # Payload length. After the type, there come 2 bytes.
                                     b'Sig'  # Record type
                                     b'\x20' # version
                                     b'\x00' # sigtype = no sig present. This ends the message
                        )