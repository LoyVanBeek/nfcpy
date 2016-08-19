import unittest

from asn1crypto.core import Sequence, ObjectIdentifier, Boolean, OctetString

class DummySequence(Sequence):
    _fields = [
        ('oid0', ObjectIdentifier,  {'optional':True, 'tag':0, 'tag_type':'implicit'}),
        # Interestingly, setting 'default':False (or True) for bool1 makes the unittest fail
        ('bool1', Boolean,          {'optional':True, 'tag':1, 'tag_type':'implicit'}),
        ('octets2', OctetString,    {'optional':True, 'tag':2, 'tag_type':'implicit'}),
    ]

class TestFullDummySequenceCanBeEncodedAndDecoded(unittest.TestCase):
    def test_encoding_does_not_throw(self):
        dummy_seq = DummySequence(value={'oid0':ObjectIdentifier("1.2.3.4"),
                                         'bool1':True,
                                         'octets2':bytes([5,6,7,8])})

        dummy_seq.dump()  # This should not throw an exception

    def test_encoding_can_be_decoded(self):
        dummy_seq = DummySequence(value={'oid0':ObjectIdentifier("1.2.3.4"),
                                         'bool1':True,
                                         'octets2':bytes([5,6,7,8])})

        dummy_dump = dummy_seq.dump()

        decoded = DummySequence.load(dummy_dump)

        self.assertEqual(dummy_seq.native, decoded.native)


class TestPartialDummySequenceCanBeEncodedAndDecoded(unittest.TestCase):
    def test_encoding_can_be_decoded_1(self):
        dummy_seq = DummySequence(value={'oid0':ObjectIdentifier("1.2.3.4"),
                                         # Note that the 2nd element, which is also optional is omitted
                                         'octets2':bytes([5,6,7,8])})

        dummy_dump = dummy_seq.dump()

        decoded = DummySequence.load(dummy_dump)

        self.assertEqual(dummy_seq.native, decoded.native)

        self.assertEqual(decoded.native['oid0'], "1.2.3.4")
        self.assertEqual(decoded.native['octets2'], bytes([5,6,7,8]))


    def test_encoding_can_be_decoded_2(self):
        dummy_seq = DummySequence(value={'bool1': False, # Note that the 1st element, which is also optional, is omitted
                                         'octets2': bytes([5, 6, 7, 8])})

        dummy_dump = dummy_seq.dump()

        decoded = DummySequence.load(dummy_dump)

        self.assertEqual(decoded.native['bool1'], False)
        self.assertEqual(decoded.native['octets2'], bytes([5, 6, 7, 8]))

        self.assertEqual(decoded.native['oid0'], None) # This was not even defined


if __name__ == '__main__':
    unittest.main()
