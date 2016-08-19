import unittest

from asn1crypto.core import Sequence, Choice, ObjectIdentifier, Boolean, OctetString

class DummySequence(Sequence):
    _fields = [
        ('oid0', ObjectIdentifier,  {'optional':True, 'tag':0, 'tag_type':'implicit'}),
        # Interestingly, setting 'default':False (or True) for bool1 makes the unittest fail
        ('bool1', Boolean,          {'optional':True, 'tag':1, 'tag_type':'implicit'}),
        ('octets2', OctetString,    {'optional':True, 'tag':2, 'tag_type':'implicit'}),
    ]


class DummyChoice(Choice):
    _alternatives = [
        ('oid0', ObjectIdentifier,  {'tag':0, 'tag_type':'implicit'}),
        # Interestingly, setting 'default':False (or True) for bool1 makes the unittest fail
        ('bool1', Boolean,          {'tag':1, 'tag_type':'implicit'}),
        ('octets2', OctetString,    {'tag':2, 'tag_type':'implicit'}),
    ]

class NestedSequence(Sequence):
    _fields = [
        # NOTE: when using a Choice-subtype and tagging it implicitly will give the error below:
        # ValueError: The Choice type can not be implicitly tagged even if in an implicit module - due to its nature any tagging must be explicit
        # while constructing nfc.ndef.m2m.tests.test_tagging_nested_sequence.DummyChoice
        # while constructing nfc.ndef.m2m.tests.test_tagging_nested_sequence.NestedSequence
        ('choice0', DummyChoice,    {'optional':True, 'tag':0, 'tag_type':'explicit'}),
        ('sequence1', DummySequence,{'optional':True, 'tag':1, 'tag_type':'implicit'}),
        ('choice2', DummyChoice,    {'optional':True, 'tag':2, 'tag_type':'explicit'}),
        ('sequence3', DummySequence,{'optional':True, 'tag':3, 'tag_type':'implicit'}),
    ]


class TestNestedSequence(unittest.TestCase):
    def setUp(self):
        self.choice0 = DummyChoice(name='octets2', value=bytes([1,2,3,4]))

        self.seq_1 = DummySequence(value={'oid0':ObjectIdentifier("4.5.6.7"),
                                          'bool1':True,
                                          'octets2':bytes([9,10,11,12,13])})

        self.choice2 = DummyChoice(name='oid0', value=ObjectIdentifier("14.15.16.17"))

        self.seq_3 = DummySequence(value={'oid0':ObjectIdentifier("18.19.20.21"),
                                          'bool1':False,
                                          'octets2':bytes([22,23,24,25])})

        self.nested = NestedSequence(value={'choice0':self.choice0,
                                            'sequence1':self.seq_1,
                                            'choice2':self.choice2,
                                            'sequence3':self.seq_3})

    def test_nested_can_be_encoded(self):
        self.nested.dump()

    def test_nested_can_be_decoded(self):
        dump = self.nested.dump()

        decoded = NestedSequence.load(dump)

        self.assertEqual(self.nested.native, decoded.native)

if __name__ == '__main__':
    unittest.main()
