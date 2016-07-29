import unittest
from .. import m2m_certificate_format as m2m

import base64
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder

class TestAttributeValue(unittest.TestCase):
    def test_country(self):
        orig_attr = m2m.AttributeValue(country='US')
        encoded_attr = der_encoder.encode(orig_attr)
        decoded_attr = der_decoder.decode(encoded_attr)[0]

        self.assertEqual(orig_attr['country'], decoded_attr)

        # self.assertEqual(orig_attr, decoded_attr) # Not possible, because the label of the value is lost

    def test_organization(self):
        orig_attr = m2m.AttributeValue(organization='ACME corp.')
        encoded_attr = der_encoder.encode(orig_attr)
        decoded_attr = der_decoder.decode(encoded_attr)[0]

        self.assertEqual(orig_attr['organization'], decoded_attr)
        # self.assertEqual(orig_attr, decoded_attr) # Not possible, because the label of the value is lost

    def test_could_match_false(self):
        orig_attr1 = m2m.AttributeValue(organization='ACME corp.')
        orig_attr2 = m2m.AttributeValue(country='US')

        encoded_attr2 = der_encoder.encode(orig_attr2)
        decoded_attr2 = der_decoder.decode(encoded_attr2)[0]

        self.assertIsNone(orig_attr1.could_match(decoded_attr2))  # This could NOT be a match

    def test_could_match_true(self):
        orig_attr = m2m.AttributeValue(organization='ACME corp.')

        encoded_attr = der_encoder.encode(orig_attr)
        decoded_attr = der_decoder.decode(encoded_attr)[0]

        self.assertEqual(orig_attr.could_match(decoded_attr), 'organization')  # This could be a match


class TestName(unittest.TestCase):
    def test_name(self):
        orig_name = m2m.Name.new(m2m.AttributeValue(country='US'),
                                 m2m.AttributeValue(organization='ACME corp.'),
                                 m2m.AttributeValue(locality='Fairfield')) # Its either stateOrProvince OR locality in spec page 16
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]

        self.assertEqual(str(orig_name[0]['country']),      str(decoded_name[0]))
        self.assertEqual(str(orig_name[1]['organization']), str(decoded_name[1]))
        self.assertEqual(str(orig_name[2]['locality']),     str(decoded_name[2]))
        # self.assertEqual(orig_name, decoded_name) # Not possible, because the label of the value is lost

        self.assertTrue(orig_name.could_match(decoded_name))


class TestGeneralName(unittest.TestCase):
    def test_rfc822Name(self):
        orig_name = m2m.GeneralName.new(rfc822Name="blablablablabla")
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]
        # import ipdb; ipdb.set_trace()
        self.assertEqual(str(orig_name['rfc822Name']), str(decoded_name))

        self.assertTrue(orig_name.could_match(decoded_name))

    def test_dNSName(self):
        orig_name = m2m.GeneralName.new(dNSName="blablablablabla")
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]
        self.assertEqual(str(orig_name['dNSName']),  str(decoded_name))

        self.assertTrue(orig_name.could_match(decoded_name))

    def test_directoryName(self):
        dirname = m2m.Name.new(  m2m.AttributeValue(country='US'),
                                 m2m.AttributeValue(organization='ACME corp.'),
                                 m2m.AttributeValue(locality='Fairfield')) # Its either stateOrProvince OR locality in spec page 16

        orig_name = m2m.GeneralName.new(directoryName=dirname)
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]
        self.assertEqual(orig_name, decoded_name)

        self.assertTrue(orig_name.could_match(decoded_name))

    def test_uniformResourceIdentifier(self):
        orig_name = m2m.GeneralName.new(uniformResourceIdentifier="blabla.com")
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]
        self.assertEqual(orig_name, decoded_name)

        self.assertTrue(orig_name.could_match(decoded_name))

    def test_iPAddress(self):
        orig_name = m2m.GeneralName.new(iPAddress=bytes([192, 168, 1, 1]))
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]
        self.assertEqual(orig_name, decoded_name)

        self.assertTrue(orig_name.could_match(decoded_name))

    def test_registeredID(self):
        orig_name = m2m.GeneralName.new(registeredID=univ.ObjectIdentifier("1.2.840.10045.3.1.7"))
        encoded_name = der_encoder.encode(orig_name)
        decoded_name = der_decoder.decode(encoded_name)[0]
        self.assertEqual(orig_name, decoded_name)

        self.assertTrue(orig_name.could_match(decoded_name))


class TestAuthKeyID(unittest.TestCase):
    def test_authkey(self):
        subjectAlternativeName = m2m.GeneralName.new(uniformResourceIdentifier="blabla.com")

        orig_key = m2m.AuthKeyId.new(   keyIdentifier=int(123456789).to_bytes(4, byteorder='big'),
                                        authCertIssuer=subjectAlternativeName,
                                        authCertSerialNum=int(987654321).to_bytes(4, byteorder='big'))

        encoded_key = der_encoder.encode(orig_key)
        decoded = der_decoder.decode(encoded_key)
        decoded_key = decoded[0]
        self.assertEqual(orig_key, decoded_key)
        # import ipdb; ipdb.set_trace()
        self.assertTrue(orig_key.could_match(decoded_key))


class TestTbsCertificate(unittest.TestCase):
    def test_tbs(self):
        issuer = m2m.Name.new(   m2m.AttributeValue(country='US'),
                                 m2m.AttributeValue(organization='ACME corp.'),
                                 m2m.AttributeValue(locality='Fairfield')) # Its either stateOrProvince OR locality in spec page 16

        subjectAlternativeName = m2m.GeneralName.new(uniformResourceIdentifier="blabla.com")

        authkey = m2m.AuthKeyId.new( keyIdentifier=int(123456789).to_bytes(4, byteorder='big'),
                                     authCertIssuer=subjectAlternativeName,
                                     authCertSerialNum=int(987654321).to_bytes(4, byteorder='big'))

        orig_tbs = m2m.TBSCertificate.new(
            version=0,
            serialNumber=int(123456789).to_bytes(20, byteorder='big'),
            subject=issuer,
            cAAlgorithm="1.2.840.10045.4.3.2", # ecdsaWithSha256: http://oid-info.com/get/1.2.840.10045.4.3.2
            cAAlgParams=base64.decodebytes(b'BggqhkjOPQMBBw=='),  # EC PARAMETERS http://oid-info.com/get/1.2.840.10045.3.1.7
            issuer=issuer,  # This is a self-signed certificate
            validFrom=int(123456789).to_bytes(4, byteorder='big'), # seconds since epoch, optional
            validDuration=int(123456789).to_bytes(4, byteorder='big'),  # seconds since validFrom, optional
            pKAlgorithm="1.2.840.10045.4.3.2",  # Same as cAAlgorithm
            pubKey=base64.decodebytes(
             b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyCjVqzDqCn5KS2QYmD6bCajY1L8+\nla/50oJSDw5nKZm9zqeUIxwpl215Gz+aeBJOEHEC06fHjnb3TNdQcu1aKg=='),
            authKeyId=authkey, #optional, See https://tools.ietf.org/html/rfc5280#section-4.2.1.1 for explanation
            subjKeyId=int(1).to_bytes(1, byteorder='big'), # Key ID of the subject (which number do we give the private key?)
            keyUsage=0b10100000.to_bytes(1, byteorder='big'),  # digitalSignature & keyEncipherment bit set
            certificatePolicy="2.5.29.32.0",
            extendedKeyUsage="2.16.840.1.114513.29.37"
        )

        encoded_tbs = der_encoder.encode(orig_tbs)
        decoded_tbs = der_decoder.decode(encoded_tbs)[0]

        # print(orig_tbs.prettyPrint())
        # print("-" * 60)
        # print(decoded_tbs.prettyPrint())

        # import ipdb; ipdb.set_trace()
        # self.assertEqual(int(orig_tbs['version']), int(decoded_tbs[0]))
        # self.assertEqual(orig_tbs['serialNumber'], decoded_tbs[1])
        # self.assertEqual(orig_tbs['subject'], decoded_tbs[2])

        # self.assertEqual(orig_tbs, decoded_tbs)