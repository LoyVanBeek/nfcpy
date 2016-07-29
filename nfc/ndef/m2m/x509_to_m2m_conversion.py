#! /usr/bin/env python

import datetime
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import hashes

from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder

from . import m2m_certificate_format as m2m

# Some fields of the M2M AttributeValue that do not fit with X.509 NameOIDs
# 'registeredId'
# 'octetsName'
# Some X509 attributes also do not have an equivalent in M2M though, AFAIK
oid2m2m_map = {
    # 'BUSINESS_CATEGORY',
    'COMMON_NAME': 'commonName',
    'COUNTRY_NAME': 'country',
    'DN_QUALIFIER': 'distinguishedNameQualifier',
    'DOMAIN_COMPONENT': 'domainComponent',
    # 'EMAIL_ADDRESS',
    # 'GENERATION_QUALIFIER',
    # 'GIVEN_NAME',
    # 'JURISDICTION_COUNTRY_NAME',
    # 'JURISDICTION_LOCALITY_NAME',
    # 'JURISDICTION_STATE_OR_PROVINCE_NAME',
    'LOCALITY_NAME': 'locality',
    'ORGANIZATIONAL_UNIT_NAME': 'organizationalUnit',
    'ORGANIZATION_NAME': 'organization',
    # 'PSEUDONYM',
    'SERIAL_NUMBER': 'serialNumber',
    'STATE_OR_PROVINCE_NAME': 'stateOrProvince',
    # 'SURNAME',
    # 'TITLE'
}

# This mapping is not 1:1, as not all hashes are supported by M2M and
# some algorithms (eg. Elliptic Curve Qu-Vanstone abbreviated to ECQV) are not in the cryptography-library
# Further, some curves are also not supported by the cryptography-library
map_algohashcurve_to_oid = {
    (ec.EllipticCurvePublicKey, hashes.SHA256, ec.SECP192R1): m2m.AlgorithmObjectIdentifiers.ecdsa_with_sha256_secp192r1,
    (ec.EllipticCurvePublicKey, hashes.SHA256, ec.SECP224R1): m2m.AlgorithmObjectIdentifiers.ecdsa_with_sha256_secp224r1,
    (ec.EllipticCurvePublicKey, hashes.SHA256, ec.SECT233K1): m2m.AlgorithmObjectIdentifiers.ecdsa_with_sha256_sect233k1,
    # (ec.EllipticCurvePublicKey, hashes.SHA256, ec.SECP223R1):m2m.AlgorithmObjectIdentifiers.ecdsa_with_sha256_sect233r1,
    #("algo", hashes.SHA256, ec.SECP192R1): m2m.AlgorithmObjectIdentifiers.ecqv_with_sha256_secp192r1,
    #("algo", hashes.SHA256, ec.SECP224R1): m2m.AlgorithmObjectIdentifiers.ecqv_with_sha256_secp224r1,
    #("algo", hashes.SHA256, ec.SECT233K1): m2m.AlgorithmObjectIdentifiers.ecqv_with_sha256_sect233k1,
    # ("algo", hashes.SHA256, ec.SECP223R1):                   m2m.AlgorithmObjectIdentifiers.ecqv_with_sha256_sect233r1, #SECP223R1 does not exist in cryptography
    (rsa.RSAPublicKey, hashes.SHA256, None): m2m.AlgorithmObjectIdentifiers.rsa_with_sha256,
    (ec.EllipticCurvePublicKey, hashes.SHA256, ec.SECP256R1): m2m.AlgorithmObjectIdentifiers.ecdsa_with_sha256_secp256r1,
    #("algo", hashes.SHA256, ec.SECP256R1): m2m.AlgorithmObjectIdentifiers.ecqv_with_sha256_secp256r1
}

#Map a curve used in Elliptic Curve Crypto to its OID.
# See RFC 5480, section 2.1.1.1.  Named Curve
map_ec_to_oid = {
    ec.SECP192R1: "1.2.840.10045.3.1.1",  # http://oid-info.com/get/1.2.840.10045.3.1.1
    ec.SECP224R1: "1.3.132.0.33",  # http://oid-info.com/get/1.3.132.0.33
    ec.SECT233K1: "1.3.132.0.26",  # http://oid-info.com/get/1.3.132.0.26
    ec.SECP256R1: "1.2.840.10045.3.1.7"  # http://oid-info.com/get/1.2.840.10045.3.1.7
}

class M2mConverter(object):
    @staticmethod
    def x509_name_to_m2m_name(x509_name):
        """x509_name = x509_cert.issuer or x509_cert.subject"""

        from cryptography.x509.oid import NameOID
        attrs = [attr for attr in dir(NameOID) if not attr.startswith('_')]  # Get all the possible attributes of a name

        all_attrs = {attr: x509_name.get_attributes_for_oid(getattr(NameOID, attr)) for attr in
                     attrs}  # Get all the attributes in that name, some may be empty
        filled_attrs = {k: v for k, v in all_attrs.items() if v}  # Filter out the empty attributes

        m2m_attribute_values = []

        for attr_name, filled_attr in filled_attrs.items():
            attr = filled_attr[0]
            m2m_attr_name = oid2m2m_map[attr_name]
            m2m_attr_val = m2m.AttributeValue(**{m2m_attr_name: attr.value})
            m2m_attribute_values += [m2m_attr_val]

        m2m_name = m2m.Name.new(*m2m_attribute_values)

        return m2m_name

    @staticmethod
    def x509_datetime_to_m2m_datetime(x509_datetime):
        epoch = datetime.datetime.utcfromtimestamp(0)
        seconds = (x509_datetime - epoch).total_seconds()
        return int(seconds).to_bytes(4, byteorder='big')

    @staticmethod
    def x509_validity_to_m2m_validity(x509_cert):
        seconds = (x509_cert.not_valid_after - x509_cert.not_valid_before).total_seconds()  # seconds since validFrom
        validFrom = M2mConverter.x509_datetime_to_m2m_datetime(x509_cert.not_valid_before)
        validDuration = int(seconds).to_bytes(4, byteorder='big')

        return validFrom, validDuration

    @staticmethod
    def x509_algo_to_m2m_cAAlgorithm(x509_cert):
        public_key = x509_cert.public_key()

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                return (map_algohashcurve_to_oid[(rsa.RSAPublicKey,
                                                  type(x509_cert.signature_hash_algorithm),
                                                  None)], None)
            elif isinstance(public_key, dsa.DSAPublicKey):  # Not supported by M2M though
                return (map_algohashcurve_to_oid[(dsa.DSAPublicKey,
                                                  type(x509_cert.signature_hash_algorithm),
                                                  None)], None)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return (map_algohashcurve_to_oid[(ec.EllipticCurvePublicKey,
                                                  type(x509_cert.signature_hash_algorithm),
                                                  type(public_key.curve))],
                        der_encoder.encode(univ.ObjectIdentifier(map_ec_to_oid[type(public_key.curve)])))
        except KeyError as key_error:
            print("Certificate cannot be converted to M2M, an algorithm cannot be encoded".format(key_error))
            raise key_error

    @staticmethod
    def x509_to_m2m_tbs(x509_cert):
        """Convert a to-be-signed X.509 certificate to a to-be-signed M2M certificate.
        <Converting a full X.509 certificate is pointless, because since the encoding is different.
        That would make the signature over the to-be-signed X.509 bytes not match the to-be-signed M2M bytes.

        it would make more sense to use cryptography.x509.CertificateSigningRequest here, but that lacks the validTo/From fields"""
        m2m_issuer = M2mConverter.x509_name_to_m2m_name(x509_cert.issuer)
        m2m_subject = M2mConverter.x509_name_to_m2m_name(x509_cert.subject)

        m2m_public_key = x509_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) # TODO: is SubjectPublicKeyInfo the correct format?

        ca_algo = M2mConverter.x509_algo_to_m2m_cAAlgorithm(x509_cert)

        validFrom, validDuration = M2mConverter.x509_validity_to_m2m_validity(x509_cert)

        tbs = m2m.TBSCertificate.new(version=0,
                                     serialNumber=int(x509_cert.serial_number).to_bytes(20, byteorder='big'),
                                     subject=m2m_subject,
                                     cAAlgorithm=str(ca_algo[0].value),
                                     cAAlgParams=ca_algo[1],  # TODO:  I would expect this to be redundant info, since the same info is embedded above in cAAlgorithm
                                     issuer=m2m_issuer,
                                     validFrom=validFrom,  # optional
                                     validDuration=validDuration,  # seconds since validFrom, optional
                                     pKAlgorithm=str(ca_algo[0].value),  # Same as cAAlgorithm
                                     pubKey=m2m_public_key,
                                     )
        return tbs

    @staticmethod
    def x509_pem_to_m2m_csr(x509_path, m2m_path):
        with open(x509_path, 'rb') as cert_file:
            pem_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())

            m2m_tbs = M2mConverter.x509_to_m2m_tbs(cert)

            with open(m2m_path, 'wb') as m2m_file:
                m2m_file.write(b'------BEGIN CERTIFICATE REQUEST------' + b'\n')
                m2m_file.write(base64.encodebytes(der_encoder.encode(m2m_tbs)))
                m2m_file.write(b'------BEGIN CERTIFICATE REQUEST------')

    @staticmethod
    def x509_pem_to_m2m_pem(x509_path, m2m_path, private_key_path):
        with open(x509_path, 'rb') as cert_file:
            pem_data = cert_file.read()
            x509_cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            m2m_tbs = M2mConverter.x509_to_m2m_tbs(x509_cert)
            m2m.sign_certificate(m2m_tbs, private_key_path)

            with open(m2m_path, 'wb') as m2m_file:
                m2m_file.write(b'------BEGIN CERTIFICATE------' + b'\n')
                m2m_file.write(base64.encodebytes(der_encoder.encode(m2m_tbs)))
                m2m_file.write(b'------END CERTIFICATE------')

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: x509_to_m2m_conversion.py x509_cert.pem m2m_cert.pem [private_key.pem]"
              "The [private_key.pem] is used to optionally sign the converted certificate")
        exit(-1)
    elif len(sys.argv) == 3:
        M2mConverter.x509_pem_to_m2m_csr(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 4: #Then we have a private key as well
        M2mConverter.x509_pem_to_m2m_pem(sys.argv[1], sys.argv[2], sys.argv[3])





