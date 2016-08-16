#! /usr/bin/python3

"""Format for M2M certificates as defined in
Signature Record Type Definition
Technical Specification
Version 2.0
2014-11-26
[SIGNATURE]
NFC Forum (tm)

[SEC1]:
STANDARDS FOR EFFICIENT CRYPTOGRAPHY
SEC 1: Elliptic Curve Cryptography
September 20, 2000
Version 1.0
http://www.secg.org/SEC1-Ver-1.0.pdf"""

from asn1crypto.core import Sequence, SequenceOf, ObjectIdentifier, Boolean, OctetString, Choice, \
    PrintableString, UTF8String, IA5String, Integer
from asn1crypto.x509 import ExtensionId

from binascii import hexlify

# TODO: SIZEs are not encoded yet.

class Extension(Sequence):
    _fields = [
        ('extnID', ExtensionId),
        ('criticality', Boolean, {'default': False}),
        ('extnValue', OctetString),
    ]


class X509Extensions(SequenceOf):
    _child_spec = Extension


class AttributeValue(Choice):
    _alternatives = [
        ('country', PrintableString),
        ('organization', UTF8String),
        ('organizationalUnit', UTF8String),
        ('distinguishedNameQualifier', PrintableString),
        ('stateOrProvince', UTF8String),
        ('locality', UTF8String),
        ('commonName', UTF8String),
        ('serialNumber', PrintableString),
        ('domainComponent', IA5String),
        ('registeredId', ObjectIdentifier),
        ('octetsName', OctetString),
    ]


class Name(SequenceOf):
    _child_spec = AttributeValue


class GeneralName(Choice):
    _alternatives = [
        ('rfc822Name', IA5String),
        ('dNSName',    IA5String),
        ('directoryName', Name),
        ('uniformResourceIdentifier', IA5String),
        ('iPAddress', OctetString),
        ('registeredID', ObjectIdentifier),
    ]


class AuthkeyID(Sequence):
    _fields = [
        ('keyIdentified', OctetString, {'optional':True}),
        ('authCertIssuer', GeneralName, {'optional':True}),
        ('authCertSerialNum', OctetString, {'optional':True}),
    ]


class Version(Integer):
    # _map = {
    #     0: 'v1',
    # }
    pass

class CaPkAlgorithm(ObjectIdentifier):
    _map = {'2.16.840.1.114513.1.0': 'ecdsa-with-sha256-secp192r1',
            '2.16.840.1.114513.1.1': 'ecdsa-with-sha256-secp224r1',
            '2.16.840.1.114513.1.2': 'ecdsa-with-sha256-sect233k1',
            '2.16.840.1.114513.1.3': 'ecdsa-with-sha256-sect233r1',
            '2.16.840.1.114513.1.4': 'ecqv-with-sha256-secp192r1',
            '2.16.840.1.114513.1.5': 'ecqv-with-sha256-secp224r1',
            '2.16.840.1.114513.1.6': 'ecqv-with-sha256-sect233k1',
            '2.16.840.1.114513.1.7': 'ecqv-with-sha256-sect233r1',
            '2.16.840.1.114513.1.8': 'rsa-with-sha256',
            '2.16.840.1.114513.1.9': 'ecdsa-with-sha256-secp256r1',
            '2.16.840.1.114513.1.10': 'ecqv-with-sha256-secp256r1',}

class TBSCertificate(Sequence):
    _fields = [
        ('version', Integer), #Version, {'default':Version('v1')}),
        ('serialNumber', OctetString),
        ('cAAlgorithm', CaPkAlgorithm, {'optional':True}),
        ('cAAlgParams', OctetString, {'optional':True}),
        ('issuer', Name, {'optional':True}),
        ('validFrom', OctetString, {'optional':True}),
        ('validDuration', OctetString, {'optional':True}),
        ('subject', Name),
        ('pKAlgorithm', CaPkAlgorithm, {'optional':True}),
        ('pKAlgParams', OctetString, {'optional':True}),
        ('pubKey', OctetString, {'optional':True}),
        ('authKeyId', AuthkeyID, {'optional':True}),
        ('subjKeyId', OctetString, {'optional':True}),
        ('keyUsage', OctetString, {'optional':True}),
        ('basicConstraints', Integer, {'optional':True}),
        ('certificatePolicy', ObjectIdentifier, {'optional':True}),
        ('subjectAltName', GeneralName, {'optional':True}),
        ('issuerAltName', GeneralName, {'optional':True}),
        ('extendedKeyUsage', ObjectIdentifier, {'optional':True}),
        ('authInfoAccessOCSP', IA5String, {'optional':True}),
        ('cRLDistribPointURI', IA5String, {'optional':True}),
        ('x509extensions', X509Extensions, {'optional':True}),
    ]


class Certificate(Sequence):
    _fields = [
        ('tbsCertificate', TBSCertificate),
        ('cACalcValue', OctetString)
    ]


class FieldElement(OctetString): pass # See [SEC1], Clause 2.3.5
class ECPoint(OctetString): pass # See [SEC1], Clause 2.3.3

class Y_Choice(Choice):
    _alternatives = [
        ('b', Boolean,
         'f', FieldElement) # See [SEC1]
    ]


class ECDSA_Sig_Value(Sequence):
    _fields = [
        ('r', Integer),
        ('s', Integer),
        ('a', Integer, {'optional':True}),
        ('y', Y_Choice, {'optional':True}),
    ]


class ECDSA_Full_R(Sequence):
    _fields = [
        ('r', ECPoint), # See [SEC1], Clause 2.3.3
        ('s', Integer),
    ]

class RSA_Signature(OctetString): pass

class RSAPublicKey(Sequence):
    _fields = [
        ('modulus', Integer), # n
        ('publicExponent', Integer) # e
    ]


class ECDSA_Signature(Choice):
    _alternatives = [
        ('two-ints-plus', ECDSA_Sig_Value),
        ('point-int', ECDSA_Full_R),
    ]

if __name__ == "__main__":
    issuer = Name()
    issuer[0] = AttributeValue(value={'country':PrintableString(value='US')})
    issuer[1] = AttributeValue(value={'organization':UTF8String(value='Big CAhuna corporation')})
    issuer[2] = AttributeValue(value={'locality':UTF8String(value='San Fransisco')})
    issuer[3] = AttributeValue(value={'serialNumber':PrintableString(value='987654321')})

    issuerAlternativeName = GeneralName(value=issuer)

    subject = Name()
    subject[0] = AttributeValue(value={'country':PrintableString(value='US')})
    subject[1] = AttributeValue(value={'organization':UTF8String(value='ACME Corporation')})
    subject[2] = AttributeValue(value={'locality':UTF8String(value='Fairfield')})
    subject[3] = AttributeValue(value={'serialNumber':PrintableString(value='123456789')})

    subjectAlternativeName = GeneralName(value=subject)

    # import pudb; pudb.set_trace()
    # break /usr/local/lib/python3.5/dist-packages/asn1crypto/core.py:3022 # 1264
    tbs = TBSCertificate()
    tbs['version'] = 0
    tbs['serialNumber'] = OctetString(value=int(123456789).to_bytes(4, byteorder='big'))
    tbs['cAAlgorithm'] = "1.2.3.4" #ObjectIdentifier("1.2.3.4")
    tbs['cAAlgParams'] = OctetString(value=bytes([0,1,2,3,4,5,6,7,8,9]))
    tbs['issuer'] = issuer
    tbs['validFrom'] = OctetString(value=int(123456789).to_bytes(4, byteorder='big'))
    tbs['validDuration'] = OctetString(value=int(123456789).to_bytes(4, byteorder='big'))
    tbs['subject'] = subject
    tbs['pKAlgorithm'] = "1.2.3.4" #ObjectIdentifier("1.2.3.4")
    tbs['pKAlgParams'] = OctetString(value=int(123456789).to_bytes(4, byteorder='big'))
    tbs['pubKey'] = OctetString(value=int(123456789).to_bytes(4, byteorder='big'))
    tbs['authKeyId'] = AuthkeyID()
    tbs['subjKeyId'] = OctetString(value=int(123456789).to_bytes(4, byteorder='big'))
    tbs['keyUsage'] = OctetString(value=int(0).to_bytes(1, byteorder='big'))
    #tbs['basicConstraints'] =  # Omit if end-entity cert
    tbs['certificatePolicy'] = "2.5.29.3" #ObjectIdentifier("2.5.29.3")
    tbs['subjectAltName'] = subjectAlternativeName
    tbs['issuerAltName'] = issuerAlternativeName
    tbs['extendedKeyUsage'] = "2.5.29.37" #ObjectIdentifier("2.5.29.37") #Any key purpose
    #tbs['authInfoAccessOCSP'] =
    tbs['cRLDistribPointURI'] =  IA5String(u'www.ultimaker.com/')
    #tbs['x509extensions'] =

    dummy = Certificate(value={'cACalcValue': ECDSA_Signature(value={'two-ints-plus': ECDSA_Sig_Value(value={'r':123456789, 's':987654321})}),
                               'tbsCertificate':tbs})

    dumped = dummy.dump()
    hex = hexlify(dumped)
    print(hex)
    print(len(hex))