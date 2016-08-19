import unittest
from .. import *

import base64

class TestAttributeValue(unittest.TestCase):
    def test_country(self):
        orig_attr = AttributeValue(name='country', value='US')
        encoded_attr = orig_attr.dump()
        decoded_attr = AttributeValue.load(encoded_attr)

        self.assertEqual(orig_attr.native, decoded_attr.native)
    
    def test_organization(self):
        orig_attr = AttributeValue(name='organization', value='ACME corp.')
        encoded_attr = orig_attr.dump()
        decoded_attr = AttributeValue.load(encoded_attr)

        self.assertEqual(orig_attr.native, decoded_attr.native)
        # self.assertEqual(orig_attr, decoded_attr) # Not possible, because the label of the value is lost

    def test_could_match_false(self):
        orig_attr1 = AttributeValue(name='organization', value='ACME corp.')
        orig_attr2 = AttributeValue(name='country', value='US')

        encoded_attr2 = orig_attr2.dump()
        decoded_attr2 = AttributeValue.load(encoded_attr2)

        self.assertNotEqual(orig_attr1.native, decoded_attr2.native)  # This could NOT be a match

    def test_could_match_true(self):
        orig_attr = AttributeValue(name='organization', value='ACME corp.')

        encoded_attr = orig_attr.dump()
        decoded_attr = AttributeValue.load(encoded_attr)

        self.assertEqual(orig_attr.native, decoded_attr.native)


class TestName(unittest.TestCase):
    def test_name(self):
        orig_name = Name(value= [AttributeValue(name='country', value='US'),
                                 AttributeValue(name='organization', value='ACME corp.'),
                                 AttributeValue(name='locality', value='Fairfield')]) # Its either stateOrProvince OR locality in spec page 16
        encoded_name = orig_name.dump()
        decoded_name = Name.load(encoded_name)
        self.assertEqual(orig_name.native, decoded_name.native)


class TestGeneralName(unittest.TestCase):
    def test_rfc822Name(self):
        orig_name = GeneralName(name='rfc822Name', value="blablablablabla")
        encoded_name = orig_name.dump()
        decoded_name = GeneralName.load(encoded_name)
        # import ipdb; ipdb.set_trace()

        self.assertEqual(orig_name.native, decoded_name.native)

    def test_dNSName(self):
        orig_name = GeneralName(name='dNSName', value="blablablablabla")
        encoded_name = orig_name.dump()
        decoded_name = GeneralName.load(encoded_name)

        self.assertEqual(orig_name.native,  decoded_name.native)

    def test_directoryName(self):
        dirname = Name([AttributeValue(name='country', value='US'),
                        AttributeValue(name='organization', value='ACME corp.'),
                        AttributeValue(name='locality', value='Fairfield')]) # Its either stateOrProvince OR locality in spec page 16

        orig_name = GeneralName(name='directoryName', value=dirname)
        encoded_name = orig_name.dump()
        decoded_name = GeneralName.load(encoded_name)

        self.assertEqual(orig_name.native,  decoded_name.native)

    def test_uniformResourceIdentifier(self):
        orig_name = GeneralName(name='uniformResourceIdentifier', value="blabla.com")
        encoded_name = orig_name.dump()
        decoded_name = GeneralName.load(encoded_name)

        self.assertEqual(orig_name.native,  decoded_name.native)

    def test_iPAddress(self):
        orig_name = GeneralName(name='iPAddress', value=bytes([192, 168, 1, 1]))
        encoded_name = orig_name.dump()
        decoded_name = GeneralName.load(encoded_name)

        self.assertEqual(orig_name.native,  decoded_name.native)

    def test_registeredID(self):
        orig_name = GeneralName(name='registeredID', value=ObjectIdentifier("1.2.840.10045.3.1.7"))
        encoded_name = orig_name.dump()
        decoded_name = GeneralName.load(encoded_name)

        self.assertEqual(orig_name.native,  decoded_name.native)


class TestAuthKeyID(unittest.TestCase):
    def test_authkey(self):
        subjectAlternativeName = GeneralName(name='uniformResourceIdentifier', value="blabla.com")

        orig_key = AuthkeyID(value={'keyIdentifier':int(123456789).to_bytes(4, byteorder='big'),
                                        'authCertIssuer':subjectAlternativeName,
                                        'authCertSerialNum':int(987654321).to_bytes(4, byteorder='big')})

        encoded_key = orig_key.dump()
        decoded_key = AuthkeyID.load(encoded_key)

        self.assertEqual(orig_key.native, decoded_key.native)


class TestTbsCertificate(unittest.TestCase):
    def test_tbs(self):
        issuer = Name([AttributeValue(name='country', value='US'),
                       AttributeValue(name='organization', value='ACME corp.'),
                       AttributeValue(name='locality', value='Fairfield')]) # Its either stateOrProvince OR locality in spec page 16

        subjectAlternativeName = GeneralName(name='uniformResourceIdentifier', value="blabla.com")

        authkey = AuthkeyID({'keyIdentifier':int(123456789).to_bytes(4, byteorder='big'),
                             'authCertIssuer':subjectAlternativeName,
                             'authCertSerialNum':int(987654321).to_bytes(4, byteorder='big')})

        orig_tbs = TBSCertificate({
            'version':0,
            'serialNumber':int(123456789).to_bytes(20, byteorder='big'),
            'subject':issuer,
            'cAAlgorithm':"1.2.840.10045.4.3.2", # ecdsaWithSha256: http://oid-info.com/get/1.2.840.10045.4.3.2
            'cAAlgParams':base64.decodebytes(b'BggqhkjOPQMBBw=='),  # EC PARAMETERS http://oid-info.com/get/1.2.840.10045.3.1.7
            'issuer':issuer,  # This is a self-signed certificate
            'validFrom':int(123456789).to_bytes(4, byteorder='big'), # seconds since epoch, optional
            'validDuration':int(123456789).to_bytes(4, byteorder='big'),  # seconds since validFrom, optional
            'pKAlgorithm':"1.2.840.10045.4.3.2",  # Same as cAAlgorithm
            'pubKey':base64.decodebytes(b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyCjVqzDqCn5KS2QYmD6bCajY1L8+\nla/50oJSDw5nKZm9zqeUIxwpl215Gz+aeBJOEHEC06fHjnb3TNdQcu1aKg=='),
            'authKeyId':authkey, #optional, See https://tools.ietf.org/html/rfc5280#section-4.2.1.1 for explanation
            'subjKeyId':int(1).to_bytes(1, byteorder='big'), # Key ID of the subject (which number do we give the private key?)
            'keyUsage':0b10100000.to_bytes(1, byteorder='big'),  # digitalSignature & keyEncipherment bit set
            'certificatePolicy':"2.5.29.32.0",
            'extendedKeyUsage':"2.16.840.1.114513.29.37"}
        )

        encoded_tbs = orig_tbs.dump()
        decoded_tbs = TBSCertificate.load(encoded_tbs)

        self.assertEqual(orig_tbs.dump(), decoded_tbs.dump())


class TestCryptography(unittest.TestCase):
    def setUp(self):
        self.private = '/tmp/unittest_private_key.pem'
        self.public = '/tmp/unittest_public_key.pem'

        generate_ec_private_key(private_key_path=self.private)
        extract_ec_public_key(private_key_path=self.private, public_key_path=self.public)

        subject = Name()
        subject[0] = AttributeValue(name='country', value=PrintableString(value='US'))
        subject[1] = AttributeValue(name='organization', value=UTF8String(value='ACME corp.'))
        subject[2] = AttributeValue(name='locality', value=UTF8String(value='Fairfield'))

        pubkey = contentbytes_from_pem_file(self.public)
        builder = CertificateBuilder(subject, pubkey)

        builder.version = 0
        builder.ca_algorithm = "1.2.840.10045.4.3.2"  # ECDSA with SHA256, see http://oid-info.com/get/1.2.840.10045.4.3.2
        builder.ca_algorithm_parameters = ObjectIdentifier(value="1.2.840.10045.3.1.7").dump()  # EC PARAMETERS as bytes
        # Parameters for the elliptic curve: http://oid-info.com/get/1.2.840.10045.3.1.7
        builder.self_signed = True  # builder.issuer = subject
        builder.pk_algorithm = "1.2.840.10045.4.3.2"  # Same as cAAlgorithm
        builder.subject_key_id = int(1).to_bytes(1, byteorder='big')
        builder.key_usage = 0b10100000.to_bytes(1, byteorder='big')  # digitalSignature & keyEncipherment bit set
        # builder.basicConstraints =  # Omit if end-entity cert
        builder.certificate_policy = "2.5.29.32.0"  # Anypolicy: http://www.oid-info.com/get/2.5.29.32.0
        builder.extended_key_usage = "2.16.840.1.114513.29.37"  # Optional in ASN1 but explanation in spec says it MUST be present. Variant of X509 http://www.oid-info.com/get/2.5.29.37.0
        # builder.crl_distribution_point_uri =  IA5String(u'www.acme.com/')

        self.orig_cert = builder.build(signing_private_key_path=self.private)

    def test_crypto_pass_without_modification(self):
        orig_dump = self.orig_cert.dump()

        decoded_cert = Certificate.load(orig_dump)

        self.assertEqual(decoded_cert.dump(), orig_dump)
        self.assertEqual(self.orig_cert['tbsCertificate'].dump(), decoded_cert['tbsCertificate'].dump())  # This is what we need for signatures
        self.assertEqual(self.orig_cert['tbsCertificate']['pubKey'].dump(), decoded_cert['tbsCertificate']['pubKey'].dump())  # This is what we need for signatures
        self.assertEqual(self.orig_cert['cACalcValue'].dump(), decoded_cert[ 'cACalcValue'].dump())  # This is what we need for signatures

        verifier = CertificateVerifier(self.public)

        self.assertTrue(verifier.verify(self.orig_cert))
        self.assertTrue(verifier.verify(decoded_cert))

    def test_crypto_fail_with_tbs_modification(self):
        orig_dump = self.orig_cert.dump()

        modified_dump = bytearray(orig_dump)
        modified_dump[10] += 1  # We modify the to-be-signed content, so the signature changes

        decoded_cert = Certificate.load(modified_dump)

        self.assertNotEqual(self.orig_cert['tbsCertificate'].dump(), decoded_cert['tbsCertificate'].dump())

        verifier = CertificateVerifier(self.public)

        self.assertFalse(verifier.verify(decoded_cert))

    def test_crypto_fail_with_signature_modification(self):
        orig_dump = self.orig_cert.dump()

        modified_dump = bytearray(orig_dump)
        modified_dump[-1] += 1  # We modify the last byte, so the signature changes

        decoded_cert = Certificate.load(modified_dump)

        self.assertNotEqual(self.orig_cert['cACalcValue'].dump(), decoded_cert[ 'cACalcValue'].dump())

        verifier = CertificateVerifier(self.public)

        self.assertFalse(verifier.verify(decoded_cert))