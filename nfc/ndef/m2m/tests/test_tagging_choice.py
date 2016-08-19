import unittest

from asn1crypto.core import Choice, ObjectIdentifier, Boolean, OctetString

class DummyChoice(Choice):
    _alternatives = [
        ('oid0', ObjectIdentifier,  {'tag':0, 'tag_type':'implicit'}),
        # Setting 'default':False (or True) does not affect the unittest, while is DOES in DummySequence
        ('bool1', Boolean,          {'tag':1, 'tag_type':'implicit', 'default':False}),
        ('octets2', OctetString,    {'tag':2, 'tag_type':'implicit'}),
    ]

class TestFullDummySequenceCanBeEncodedAndDecoded(unittest.TestCase):
    def test_encoding_does_not_throw(self):
        dummy_choice = DummyChoice(name='oid0', value=ObjectIdentifier("1.2.3.4"))

        dummy_choice.dump()  # This should not throw an exception

    def test_encoding_can_be_decoded_1(self):
        dummy_choice = DummyChoice(name='oid0', value=ObjectIdentifier("1.2.3.4"))

        dummy_dump = dummy_choice.dump()

        decoded = DummyChoice.load(dummy_dump)

        self.assertEqual(dummy_choice.native, decoded.native)

    def test_encoding_can_be_decoded_2(self):
        dummy_choice = DummyChoice(name='bool1', value=False)

        dummy_dump = dummy_choice.dump()

        decoded = DummyChoice.load(dummy_dump)

        self.assertEqual(dummy_choice.native, decoded.native)

    def test_encoding_can_be_decoded_3(self):
        dummy_choice = DummyChoice(name='octets2', value=bytes([5,6,7,8]))

        dummy_dump = dummy_choice.dump()

        decoded = DummyChoice.load(dummy_dump)

        self.assertEqual(dummy_choice.native, decoded.native)


if __name__ == '__main__':
    unittest.main()
