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
http://www.secg.org/SEC1-Ver-1.0.pdf

M2M-Certificate-Definition
    {joint-iso-ccitt (2) country (16) usa (840) us-company (1)
     nfc-forum (114513) modules (5) m2m-certificate (0)}

-- Structure Must be DER encoded
DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

...

-- Notes:
-- * The times are represented using UNIX time, i.e. # of seconds
--   since the unix epoch: http://en.wikipedia.org/wiki/Unix_time
--   The validFrom field permits 40-bit values to avoid problems in
--   2038 (when 32-bit values won’t be enough).
--
-- * The keyUsage field conveys a single octet equal to the
--   second octet of the DER encoding of the following BIT STRING
--
--  KeyUsage ::= BIT STRING {
--  digitalSignature (0),
--  nonRepudiation (1),
--  keyEncipherment (2),
--  dataEncipherment (3),
--  keyAgreement (4),
--  keyCertSign (5),
--  Use keyCertSign also for an ECQV certificate issuer
--  cRLSign (6)
--  the last bit in the byte is always zero (7)
--  }
--
END

For some documentation on ASN.1, look at
- http://www.zytrax.com/books/ldap/apb/asn1.pdf
- http://www.obj-sys.com/asn1tutorial/node4.html
- http://stackoverflow.com/questions/3296761/i-need-an-example-to-understand-implicit-tagging-in-asn-1
"""



# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import base64
import enum
import subprocess
from datetime import datetime, timedelta
import inspect
import re
import sys
import textwrap
import time

from asn1crypto import x509, keys, core
from asn1crypto.util import int_to_bytes, int_from_bytes, timezone
from asn1crypto.core import CLASS_NAME_TO_NUM_MAP
from oscrypto import asymmetric, util

from asn1crypto.core import Sequence, SequenceOf, ObjectIdentifier, Boolean, OctetString, Choice, \
    PrintableString, UTF8String, IA5String, Integer
from asn1crypto.x509 import ExtensionId

from binascii import hexlify

# TODO: SIZEs are not encoded yet.
# TODO: tagging. Spec says 'DEFINITIONS AUTOMATIC TAGS' so all elements should have a tag somehow

class Extension(Sequence):
    """
    Extension ::= SEQUENCE {
        extnID              OBJECT IDENTIFIER,
        criticality         BOOLEAN DEFAULT FALSE,
        extnValue           OCTET STRING
    }
    """
    _fields = [
        ('extnID', ExtensionId),
        ('criticality', Boolean, {'default': False}),
        ('extnValue', OctetString),
    ]


class X509Extensions(SequenceOf):
    """
    X509Extensions ::= SEQUENCE OF Extension
    """
    _child_spec = Extension


class AttributeValue(Choice):
    """
    AttributeValue ::= CHOICE {
        country             PrintableString (SIZE (2)),
        organization        UTF8String (SIZE (1..32)),
        organizationalUnit  UTF8String (SIZE (1..32)),
        distinguishedNameQualifier PrintableString (SIZE (1..32)),
        stateOrProvince     UTF8String (SIZE (1..4)),
        locality            UTF8String (SIZE (1..32)),
        commonName          UTF8String (SIZE (1..32)),
        serialNumber        PrintableString (SIZE (1..32)),
        domainComponent     IA5String (SIZE (1..32)),
        registeredId        OBJECT IDENTIFIER,
        octetsName          OCTET STRING (SIZE (1..8))
    }
    """
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
    """
    Name ::= SEQUENCE SIZE (1..4) OF AttributeValue
    """
    _child_spec = AttributeValue


class GeneralName(Choice):
    """
    GeneralName ::= CHOICE {
        rfc822Name          IA5String (SIZE (1..128)),
        dNSName             IA5String (SIZE (1..128)),
        directoryName       Name,
        uniformResourceIdentifier IA5String (SIZE (1..128)),
        iPAddress           OCTET STRING (SIZE (1..16)),
                            --4 octets for IPV4 16 octets for IPV6
        registeredID        OBJECT IDENTIFIER
    }
    """
    _alternatives = [
        ('rfc822Name', IA5String),
        ('dNSName',    IA5String),
        ('directoryName', Name),
        ('uniformResourceIdentifier', IA5String),
        ('iPAddress', OctetString),
        ('registeredID', ObjectIdentifier),
    ]


class AuthkeyID(Sequence):
    """
    AuthKeyId ::= SEQUENCE {
        keyIdentifier       OCTET STRING OPTIONAL,
        authCertIssuer      GeneralName OPTIONAL,
        authCertSerialNum   OCTET STRING (SIZE(1..20)) OPTIONAL
    }
    """
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
    """
    TBSCertificate ::= SEQUENCE {
    version             INTEGER {v1(0)} DEFAULT v1,
    serialNumber        OCTET STRING (SIZE (1..20)),
    cAAlgorithm         OBJECT IDENTIFIER OPTIONAL, -- Identifies
                        -- CA algorithm, hash function, and
                        -- optionally other required parameters
                        -- (e.g. In the case of ECC, the curve).
                        --
                        -- Required for signature verification but may
                        -- be omitted from the transmitted cert and
                        -- filled in from the pKAlgorithm of a
                        -- superior cert (provided not root cert) prior
                        -- to signature verification.
                        -- For omitting rules, see B.3
                        --
    cAAlgParams         OCTET STRING OPTIONAL,  -- Identifies
                        -- CA algorithm parameters
                        --
                        -- This specification does not provide for
                        -- omitting this field in transmission and
                        -- subsequently replacing it from a superior
                        -- certificate for signature verification
                        --
    issuer              Name OPTIONAL, -- Identifies
                        -- issuer name
                        --
                        -- Required for signature verification but may
                        -- be omitted from the transmitted cert and
                        -- filled in from the subject field of a
                        -- superior cert (provided not root cert) prior
                        -- to signature verification
                        --
    validFrom           OCTET STRING (SIZE (4..5)) OPTIONAL,
                        -- Unix time. If omitted no validity specified
    validDuration       OCTET STRING (SIZE (1..4)) OPTIONAL,
                        -- # of seconds. If omitted no expiry specified
    subject             Name,
    pKAlgorithm         OBJECT IDENTIFIER OPTIONAL, -- Default is
                        -- same as cAAlgorithm in this certificate.
                        -- For omitting rules, see B.3
    pKAlgParams         OCTET STRING OPTIONAL,
    pubKey              OCTET STRING OPTIONAL,
                        -- Omit for an ECQV certificate, see A.2
    authKeyId           AuthKeyId OPTIONAL,
    subjKeyId           OCTET STRING OPTIONAL,
    keyUsage            OCTET STRING (SIZE (1)) OPTIONAL, -- Critical
                        -- One byte containing a bit string,
                        -- as described below
    basicConstraints    INTEGER (0..7) OPTIONAL, -- If absent this is
                        -- an end-entity cert; max intermed path length
                        -- for CA certificate
    certificatePolicy   OBJECT IDENTIFIER OPTIONAL, -- May use the
                        -- current version of this policy
    subjectAltName      GeneralName OPTIONAL,
    issuerAltName       GeneralName OPTIONAL,
    extendedKeyUsage    OBJECT IDENTIFIER OPTIONAL,
    authInfoAccessOCSP  IA5String OPTIONAL,-- OCSP responder URI
    cRLDistribPointURI  IA5String OPTIONAL,-- CRL distribution point URI
    x509extensions      X509Extensions OPTIONAL,
    ...
}
    """
    _fields = [
        ('version', Integer), #Version, {'default':Version('v1')}),
        ('serialNumber', OctetString),
        ('cAAlgorithm', CaPkAlgorithm, {'optional':True}), #, 'tag':1 makes this appear like a boolean
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
    """
    -- The APPLICATION 20 tag is intended to make the M2M format apparent
    -- by inspecting the first octet of the encoding

    Certificate ::= [APPLICATION 20] IMPLICIT SEQUENCE {
        tbsCertificate      TBSCertificate, -- To be signed certificate
        cACalcValue         OCTET STRING -- Contains signature for a signed
                            -- certificate or public key derivation value
                            -- for an ECQV cert, see B.2
    }
    """
    _fields = [
        ('tbsCertificate', TBSCertificate),
        ('cACalcValue', OctetString)
    ]

    tag = 20
    class_ = CLASS_NAME_TO_NUM_MAP['application']


class AlgorithmObjectIdentifiers(enum.Enum):
    ecdsa_with_sha256_secp192r1     = ObjectIdentifier("2.16.840.1.114513.1.0")
    ecdsa_with_sha256_secp224r1     = ObjectIdentifier("2.16.840.1.114513.1.1")
    ecdsa_with_sha256_sect233k1     = ObjectIdentifier("2.16.840.1.114513.1.2")
    ecdsa_with_sha256_sect233r1     = ObjectIdentifier("2.16.840.1.114513.1.3")
    ecqv_with_sha256_secp192r1      = ObjectIdentifier("2.16.840.1.114513.1.4")
    ecqv_with_sha256_secp224r1      = ObjectIdentifier("2.16.840.1.114513.1.5")
    ecqv_with_sha256_sect233k1      = ObjectIdentifier("2.16.840.1.114513.1.6")
    ecqv_with_sha256_sect233r1      = ObjectIdentifier("2.16.840.1.114513.1.7")
    rsa_with_sha256                 = ObjectIdentifier("2.16.840.1.114513.1.8")
    ecdsa_with_sha256_secp256r1     = ObjectIdentifier("2.16.840.1.114513.1.9")
    ecqv_with_sha256_secp256r1      = ObjectIdentifier("2.16.840.1.114513.1.10")


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

if sys.version_info < (3,):
    int_types = (int, long)  # noqa
    str_cls = unicode  # noqa
    byte_cls = str
else:
    int_types = (int,)
    str_cls = str
    byte_cls = bytes


__version__ = '0.14.2'
__version_info__ = (0, 14, 2)


def _writer(func):
    """
    Decorator for a custom writer, but a default reader
    """

    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)

class CertificateBuilder(object):
    _version = 0
    _serial_number = None
    _ca_algorithm = None
    _ca_algorithm_parameters = None
    _issuer = None
    _valid_from = None
    _valid_duration = None
    _subject = None
    _pk_algorithm = None
    _pk_algorithm_parameters = None
    _public_key = None
    _authkey_id = None
    _subject_key_id = None
    _key_usage = None
    _basic_constraints = None
    _certificate_policy = None
    _subject_alternative_name = None
    _issuer_alternative_name = None
    _extended_key_usage = None
    _auth_info_access_ocsp = None
    _crl_distribution_point_uri = None
    _x509_extensions = None

    _self_signed = False


    def __init__(self, subject, subject_public_key):
        """
        Unless changed, certificates will use SHA-256 for the signature,
        and will be valid from the moment created for one year. The serial
        number will be generated from the current time and a random number.
        :param subject:
            An asn1crypto.x509.Name object, or a dict - see the docstring
            for .subject for a list of valid options
        :param subject_public_key:
            An asn1crypto.keys.PublicKeyInfo object containing the public key
            the certificate is being issued for
        """

        self.subject = subject
        self.public_key = subject_public_key
        self.ca = False

        self._hash_algo = 'sha256'
        self._other_extensions = {}

    @_writer
    def self_signed(self, value):
        """
        A bool - if the certificate should be self-signed.
        """

        self._self_signed = bool(value)

        if self._self_signed:
            self._issuer = None

    @_writer
    def serial_number(self, value):
        """
        An int representable in 160 bits or less - must uniquely identify
        this certificate when combined with the issuer name.
        """

        if not isinstance(value, int_types):
            raise TypeError(_pretty_message(
                '''
                serial_number must be an integer, not %s
                ''',
                _type_name(value)
            ))

        if value < 0:
            raise ValueError(_pretty_message(
                '''
                serial_number must be a non-negative integer, not %s
                ''',
                repr(value)
            ))

        if len(int_to_bytes(value)) > 20:
            required_bits = len(int_to_bytes(value)) * 8
            raise ValueError(_pretty_message(
                '''
                serial_number must be an integer that can be represented by a
                160-bit number, specified requires %s
                ''',
                required_bits
            ))

        self._serial_number = value

    @_writer
    def ca_algorithm(self, value):
        self._ca_algorithm = value

    @_writer
    def ca_algorithm_parameters(self, value):
        self._ca_algorithm_parameters = value

    @_writer
    def issuer(self, value):
        """
        m2m.Name
        """

        self._issuer = value

    @_writer
    def valid_from(self, value):
        """
        A datetime.datetime object of when the certificate becomes valid.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                valid_from must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._valid_from = (value - datetime.utcfromtimestamp(0)).total_seconds().to_bytes(5, byteorder='big')

    @_writer
    def valid_duration(self, value):
        """
        A datetime.datetime object of when the certificate is last to be
        considered valid.
        """

        if not isinstance(value, timedelta):
            raise TypeError(_pretty_message(
                '''
                valid_duration must be an instance of datetime.timedelta, not %s
                ''',
                _type_name(value)
            ))

        self._valid_duration = value.total_seconds().to_bytes(5, byteorder='big')

    @_writer
    def subject(self, value):
        """
        A Name object
        """

        is_dict = isinstance(value, dict)
        if not isinstance(value, Name):
            raise TypeError(_pretty_message(
                '''
                subject must be an instance of m2m.Name,
                not %s
                ''',
                _type_name(value)
            ))

        self._subject = value

    @_writer
    def pk_algorithm(self, value):
        self._pk_algorithm = value

    @_writer
    def pk_algorithm_parameters(self, value):
        self._pk_algorithm_parameters = value

    @_writer
    def public_key(self, value):
        """
        A byte sequence containing the public key
        """
        if not isinstance(value, bytearray) and not isinstance(value, bytes):
            raise TypeError(_pretty_message(
                '''
                public_key must be an sequence of bytes,
                not %s
                ''',
                _type_name(value)
            ))

        self._public_key = value

    @_writer
    def authkey_id(self, value):
        self._authkey_id = value

    @_writer
    def subject_key_id(self, value):
        self._subject_key_id = value

    @_writer
    def key_usage(self, value):
        self._key_usage = value

    @_writer
    def basic_constraints(self, value):
        self._basic_constraints = value

    @_writer
    def certificate_policy(self, value):
        self._certificate_policy = value

    @_writer
    def subject_alternative_name(self, value):
        self._subject_alternative_name = value

    @_writer
    def issuer_alternative_name(self, value):
        self._issuer_alternative_name = value

    @_writer
    def extended_key_usage(self, value):
        self._extended_key_usage = value

    @_writer
    def auth_info_access_ocsp(self, value):
        self._auth_info_access_ocsp = value

    @_writer
    def crl_distribution_point_uri(self, value):
        self._crl_distribution_point_uri = value

    @_writer
    def x509_extensions(self, value):
        self._x509_extensions = value

    def build(self, signing_private_key_path, debug=False):
        """
        Validates the certificate information, constructs the ASN.1 structure
        and then signs it
        :param signing_private_key:
            path to a .pem file with a private key
        :return:
            An m2m.Certificate object of the newly signed
            certificate
        """
        if self._self_signed is not True and self._issuer is None:
            raise ValueError(_pretty_message(
                '''
                Certificate must be self-signed, or an issuer must be specified
                '''
            ))

        if self._self_signed:
            self._issuer = self._subject

        if self.serial_number is None:
            time_part = int_to_bytes(int(time.time()))
            random_part = util.rand_bytes(4)
            self.serial_number = int_from_bytes(time_part + random_part)

        # Only re non-optionals are always in this dict
        properties = {
            'version':Integer(value=self._version),
            'serialNumber':OctetString(value=self.serial_number.to_bytes(20, byteorder='big')),
            'subject':self.subject,
        }

        # Optional fields are only added if they're not None
        if self.ca_algorithm is not None:
            properties['cAAlgorithm'] = self.ca_algorithm
        if self.ca_algorithm_parameters is not None:
            properties['cAAlgParams'] = OctetString(value=self.ca_algorithm_parameters)
        if self.issuer is not None:
            properties['issuer'] = self.issuer
        if self.valid_from is not None:
            properties['validFrom'] = self.valid_from
        if self.valid_duration is not None:
            properties['validDuration'] =  self.valid_duration
        if self.pk_algorithm is not None:
            properties['pKAlgorithm'] = self.pk_algorithm
        if self.pk_algorithm_parameters is not None:
            properties['pKAlgParams'] = OctetString(value=self.pk_algorithm_parameters)
        if self.public_key is not None:
            properties['pubKey'] = OctetString(value=self.public_key)
        if self.authkey_id is not None:
            properties['authKeyId'] = self.authkey_id
        if self.subject_key_id is not None:
            properties['subjKeyId'] = OctetString(value=self.subject_key_id)
        if self.key_usage is not None:
            properties['keyUsage'] = OctetString(value=self.key_usage)
        if self.basic_constraints is not None:
            properties['basicConstraints'] =  Integer(value=self.basic_constraints)
        if self.certificate_policy is not None:
            properties['certificatePolicy'] = self.certificate_policy
        if self.subject_alternative_name is not None:
            properties['subjectAltName'] = self.subject_alternative_name
        if self.issuer_alternative_name is not None:
            properties['issuerAltName'] = self.issuer_alternative_name
        if self.extended_key_usage is not None:
            properties['extendedKeyUsage'] = self.extended_key_usage
        if self.auth_info_access_ocsp is not None:
            properties['authInfoAccessOCSP'] = self.auth_info_access_ocsp
        if self.crl_distribution_point_uri is not None:
            properties['cRLDistribPointURI'] = self.crl_distribution_point_uri
        if self.x509_extensions is not None:
            properties['x509extensions'] = self.x509_extensions

        # import ipdb; ipdb.set_trace()
        # break /usr/local/lib/python3.5/dist-packages/asn1crypto/core.py:2786
        tbs_cert = TBSCertificate(properties)

        bytes_to_sign = tbs_cert.dump()
        signature = generate_signature(bytes_to_sign, signing_private_key_path)

        # assert verify_signature(bytes_to_sign, signature, "public.pem")

        if debug:
            print("Signed_bytes ({len}): {content}".format(len=len(bytes_to_sign), content=hexlify(bytes_to_sign)))
            print("Build - Signature ({len}): {content}".format(len=len(signature), content=hexlify(signature)))


        return Certificate({
            'tbsCertificate': tbs_cert,
            'cACalcValue': signature
        })

def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:
     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace
    :param string:
        The string to format
    :param *params:
        Params to interpolate into the string
    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output


def _type_name(value):
    """
    :param value:
        A value to get the object name of
    :return:
        A unicode string of the object name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)


def generate_ec_private_key(curve='prime256v1', private_key_path='private.pem'):
    """openssl ecparam -genkey -name prime256v1 -out private.pem"""
    proc = subprocess.Popen(
        ['openssl', 'ecparam','-genkey', '-name', curve,'-out', private_key_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()

    if err:
        raise OSError(err)

def extract_ec_public_key(private_key_path='private.pem', public_key_path='public.pem'):
    """openssl ec -in private.pem -pubout -out public.pem"""
    proc = subprocess.Popen(
        ['openssl', 'ec', '-in', private_key_path, '-pubout', public_key_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()

    if not err:
        with open(public_key_path, 'rb') as signature_file:
            signature = signature_file.read()
            return signature
    else:
        raise OSError(err)

def m2m_certificate_to_file(certificate, certificate_path, debug=False):
    with open(certificate_path, 'wb+') as cert_file:
        cert_file.write(b'------BEGIN CERTIFICATE------'+b'\n')
        encoded = certificate.dump()
        if debug:
            print("Writing to file: {}".format(hexlify(encoded)))
        cert_file.write(base64.encodebytes(encoded))
        cert_file.write(b'------END CERTIFICATE------')

def m2m_bytes_from_file(certificate_path):
    with open(certificate_path, 'rb') as cert_file:
        lines = cert_file.readlines()
        content_lines = lines[1:-1]
        content = b''.join(content_lines)
        return base64.decodebytes(content)

def m2m_certificate_from_file(certificate_path):
    b = m2m_bytes_from_file(certificate_path)
    return m2m_certificate_from_bytes(b)

def m2m_certificate_from_bytes(byte_sequence):
    return Certificate.load(byte_sequence)

def generate_signature(to_be_signed_bytes, private_key_path='private.pem'):
    """openssl dgst -sha256 -sign private.pem -out signature.der message.txt"""
    byte_path = "/tmp/to_be_signed.tmp"
    with open(byte_path, 'wb') as byte_file:
        byte_file.write(to_be_signed_bytes)

    signature_path = "/tmp/signature.der"
    proc = subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign', private_key_path, '-out', signature_path, byte_path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()

    if not err:
        with open(signature_path, 'rb') as signature_file:
            signature = signature_file.read()
            return signature
    else:
        raise OSError(err)

def verify_signature(signed_bytes, signature, public_key_path='public.pem'):
    """openssl dgst -sha256 -verify public.pem -signature signature.der message.txt"""
    byte_path = "/tmp/signed.tmp"
    with open(byte_path, 'wb') as byte_file:
        byte_file.write(signed_bytes)

    signature_path = "/tmp/signature.der"
    with open(signature_path, 'wb') as signature_file:
        signature_file.write(signature)

    proc = subprocess.Popen(['openssl', 'dgst', '-sha256', '-verify', public_key_path, '-signature', signature_path, byte_path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if not err:
        return out.strip() == b"Verified OK"
    else:
        raise OSError(err)


class CertificateVerifier(object):
    def __init__(self, public_key_path):
        self.public_key_path = public_key_path

    def verify(self, certificate, debug=False):
        signed_bytes = certificate['tbsCertificate'].dump()
        octet_string = certificate['cACalcValue']
        signature = octet_string.native  # We want to content of the octet string, which happens to be ASN.1 encoded as well; A sequence of 2 ints in case of ECDSA

        if debug:
            print("Signed_bytes ({len}): {content}".format(len=len(signed_bytes), content=hexlify(signed_bytes)))
            print("Verify - Signature ({len}): {content}".format(len=len(signature), content=hexlify(signature)))

        return verify_signature(signed_bytes, signature, self.public_key_path)

    def verify_bytes(self, certificate_bytes):
        decoded_certificate = Certificate.load(certificate_bytes)
        return self.verify(decoded_certificate)

if __name__ == "__main__":
    subject = Name()
    subject[0] = AttributeValue(name='country', value=PrintableString(value='US'))
    subject[1] = AttributeValue(name='organization', value=UTF8String(value='ACME corp.'))
    subject[2] = AttributeValue(name='locality', value=UTF8String(value='Fairfield'))

    pubkey = base64.decodebytes(b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyCjVqzDqCn5KS2QYmD6bCajY1L8+\nla/50oJSDw5nKZm9zqeUIxwpl215Gz+aeBJOEHEC06fHjnb3TNdQcu1aKg==')
    builder = CertificateBuilder(subject, pubkey)

    builder.version = 0
    builder.serial_number = 123456789
    builder.ca_algorithm = "1.2.840.10045.4.3.2" # ECDSA with SHA256, see http://oid-info.com/get/1.2.840.10045.4.3.2
    builder.ca_algorithm_parameters = base64.decodebytes(b'BggqhkjOPQMBBw==') # EC PARAMETERS
    # Parameters for the elliptic curve: http://oid-info.com/get/1.2.840.10045.3.1.7
    builder.self_signed = True #builder.issuer = subject
    builder.pk_algorithm = pKAlgorithm="1.2.840.10045.4.3.2"  # Same as cAAlgorithm
    builder.subject_key_id = int(1).to_bytes(1, byteorder='big')
    builder.key_usage = 0b10100000.to_bytes(1, byteorder='big') # digitalSignature & keyEncipherment bit set
    # builder.basicConstraints =  # Omit if end-entity cert
    builder.certificate_policy = "2.5.29.32.0"  # Anypolicy: http://www.oid-info.com/get/2.5.29.32.0
    builder.extended_key_usage = "2.16.840.1.114513.29.37" # Optional in ASN1 but explanation in spec says it MUST be present. Variant of X509 http://www.oid-info.com/get/2.5.29.37.0
    # builder.crl_distribution_point_uri =  IA5String(u'www.acme.com/')

    orig_cert = builder.build(signing_private_key_path="private.pem", debug=True)

    orig_dump = orig_cert.dump()
    orig_dump_hex = hexlify(orig_dump)
    print("Original certificate ({len}): {content}".format(content=orig_dump_hex, len=len(orig_dump)))

    # import ipdb; ipdb.set_trace()
    # break /usr/local/lib/python3.5/dist-packages/asn1crypto/core.py:270
    decoded_cert = Certificate.load(orig_dump)
    # When loading, all that happens is that some .contents is set to the bytes we pass it.
    # .contents is not processed in any way further.


    assert decoded_cert.dump() == orig_dump  # Good: the encoding stays the same when repeated, as opposed to pyasn1
    assert orig_cert['tbsCertificate'].dump() == decoded_cert['tbsCertificate'].dump()  # This is what we need for signatures
    assert orig_cert['cACalcValue'].dump() == decoded_cert['cACalcValue'].dump()  # This is what we need for signatures

    verifier = CertificateVerifier('public.pem')

    try:
        print("Orig_cert verification: {}".format(verifier.verify(orig_cert, debug=True)))
    except OSError as ose:
        print("Could not verify certificate: {}".format(ose))

    try:
        print("Decoded_cert verification: {}".format(verifier.verify(decoded_cert, debug=True)))
    except OSError as ose:
        print("Could not verify certificate: {}".format(ose))