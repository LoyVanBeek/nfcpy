#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import unittest

import sys, os
sys.path.insert(1, os.path.split(sys.path[0])[0])

import io
import nfc.ndef
from nose.tools import raises

class TestRecord(unittest.TestCase):

    def test_init_args_none(self):
        record = nfc.ndef.Record()
        self.assertEqual(record.type, '')
        self.assertEqual(record.name, '')
        self.assertEqual(record.data, '')

    def test_init_args_type(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T')
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        self.assertEqual(record.name, '')
        self.assertEqual(record.data, '')

    def test_init_args_type_name(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier')
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        self.assertEqual(record.name, 'identifier')
        self.assertEqual(record.data, '')

    def test_init_args_type_name_data_1(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier', 'Hello World')
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        self.assertEqual(record.name, 'identifier')
        self.assertEqual(record.data, 'Hello World')

    def test_init_args_type_data(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T', data='Hello World')
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        self.assertEqual(record.name, '')
        self.assertEqual(record.data, 'Hello World')

    def test_init_args_name(self):
        record = nfc.ndef.Record(record_name='identifier')
        self.assertEqual(record.type, 'unknown')
        self.assertEqual(record.name, 'identifier')
        self.assertEqual(record.data, '')

    def test_init_args_type_name_data_2(self):
        record = nfc.ndef.Record(record_name='identifier', data='Hello World')
        self.assertEqual(record.type, 'unknown')
        self.assertEqual(record.name, 'identifier')
        self.assertEqual(record.data, 'Hello World')

    # def test_init_args_data_string(self):
    #     data=b'\xDA\x0A\x0B\x01' + b'text/plain0Hello World' + 10*b'\x00'
    #     record = nfc.ndef.Record(data=bytearray(data))
    #     self.assertEqual(record.type, 'text/plain')
    #     self.assertEqual(record.name, '0')
    #     self.assertEqual(record.data, 'Hello World')

    def test_init_args_data_bytearray(self):
        data=bytearray(b'\xDA\x0A\x0B\x01text/plain0Hello World' + bytes(10*b'\x00'))
        record = nfc.ndef.Record(data=data)
        self.assertEqual(record.type, 'text/plain')
        self.assertEqual(record.name, '0')
        self.assertEqual(record.data, 'Hello World')

    def test_init_args_data_bytestream(self):
        data=io.BytesIO(b'\xDA\x0A\x0B\x01text/plain0Hello World' + bytes(10*b'\x00'))
        record = nfc.ndef.Record(data=data)
        self.assertEqual(record.type, 'text/plain')
        self.assertEqual(record.name, '0')
        self.assertEqual(record.data, 'Hello World')
        self.assertEqual(data.tell() - data.seek(0, 2), -10)

    def test_init_args_data_invalid_type(self):
        try: record = nfc.ndef.Record(data=1)
        except TypeError: pass
        else: raise AssertionError("TypeError not raised")

    def test_parse_record_type(self):
        record = nfc.ndef.Record(data=b'\xD0\x00\x00')
        self.assertEqual(record.type, '')
        record = nfc.ndef.Record(data='\xD1\x01\x00T')
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        record = nfc.ndef.Record(data='\xD2\x0A\x00text/plain')
        self.assertEqual(record.type, 'text/plain')
        record = nfc.ndef.Record(data='\xD3\x1B\x00http://example.com/type.dtd')
        self.assertEqual(record.type, 'http://example.com/type.dtd')
        record = nfc.ndef.Record(data='\xD4\x10\x00example.com:type')
        self.assertEqual(record.type, 'urn:nfc:ext:example.com:type')
        record = nfc.ndef.Record(data=b'\xD5\x00\x00')
        self.assertEqual(record.type, 'unknown')
        record = nfc.ndef.Record(data=b'\xD6\x00\x00')
        self.assertEqual(record.type, 'unchanged')

    def test_set_record_type(self):
        record = nfc.ndef.Record()
        record.type = 'urn:nfc:wkt:T'
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        record.type = 'text/plain'
        self.assertEqual(record.type, 'text/plain')
        record.type = 'http://example.com/type.dtd'
        self.assertEqual(record.type, 'http://example.com/type.dtd')
        record.type = 'urn:nfc:ext:example.com:type'
        self.assertEqual(record.type, 'urn:nfc:ext:example.com:type')
        record.type = 'unknown'
        self.assertEqual(record.type, 'unknown')
        record.type = 'unchanged'
        self.assertEqual(record.type, 'unchanged')
        record.type = ''
        self.assertEqual(record.type, '')
        try: record.type = 1
        except ValueError: pass

    def test_generate_string(self):
        record = nfc.ndef.Record()
        self.assertEqual(str(record), '\x10\x00\x00')
        
    def test_generate_bytearray(self):
        record = nfc.ndef.Record()
        self.assertEqual(bytearray(record), bytearray(b'\x10\x00\x00'))
        
    def test_generate_list(self):
        record = nfc.ndef.Record()
        self.assertEqual(list(record), list('\x10\x00\x00'))
        
    def test_generate_parsed(self):
        record = nfc.ndef.Record(data=b'\xD0\x00\x00')
        self.assertEqual(str(record), '\xD0\x00\x00')
        record = nfc.ndef.Record(data=b'\xD1\x01\x00T')
        self.assertEqual(str(record), '\xD1\x01\x00T')
        record = nfc.ndef.Record(data='\xD2\x0A\x00text/plain')
        self.assertEqual(str(record), '\xD2\x0A\x00text/plain')
        record = nfc.ndef.Record(data='\xD3\x1B\x00http://example.com/type.dtd')
        self.assertEqual(str(record), '\xD3\x1B\x00http://example.com/type.dtd')
        record = nfc.ndef.Record(data='\xD4\x10\x00example.com:type')
        self.assertEqual(str(record), '\xD4\x10\x00example.com:type')
        record = nfc.ndef.Record(data=b'\xD5\x00\x00')
        self.assertEqual(str(record), '\xD5\x00\x00')
        record = nfc.ndef.Record(data=b'\xD6\x00\x00')
        self.assertEqual(str(record), '\xD6\x00\x00')

    def test_generate_record_type(self):
        record = nfc.ndef.Record()
        self.assertEqual(str(record), '\x10\x00\x00')
        record.type = 'urn:nfc:wkt:T'
        self.assertEqual(str(record), '\x11\x01\x00T')
        record.type = 'text/plain'
        self.assertEqual(str(record), '\x12\x0A\x00text/plain')
        record.type = 'http://example.com/type.dtd'
        self.assertEqual(str(record), '\x13\x1B\x00http://example.com/type.dtd')
        record.type = 'urn:nfc:ext:example.com:type'
        self.assertEqual(str(record), '\x14\x10\x00example.com:type')
        record.type = 'unknown'
        self.assertEqual(str(record), '\x15\x00\x00')
        record.type = 'unchanged'
        self.assertEqual(str(record), '\x16\x00\x00')

    def test_generate_record_type_name(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier')
        self.assertEqual(str(record), '\x19\x01\x00\x0ATidentifier')

    def test_generate_record_type_name_data(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier', 'payload')
        self.assertEqual(str(record), '\x19\x01\x07\x0ATidentifierpayload')

    def test_generate_record_long_payload(self):
        record = nfc.ndef.Record('urn:nfc:wkt:T', 'id', bytearray(256))
        self.assertEqual(str(record), '\x09\x01\x00\x00\x01\x00\x02Tid' + 256 * '\x00')

    def test_decode_record_long_payload(self):
        data = '\x09\x01\x00\x00\x01\x00\x02Tid' + str(bytearray(256))
        record = nfc.ndef.Record(data=data)
        self.assertEqual(record.type, 'urn:nfc:wkt:T')
        self.assertEqual(record.name, 'id')
        self.assertEqual(record.data, str(bytearray(256)))

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_01(self):
        nfc.ndef.Record(data='\x00')
        
    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_02(self):
        nfc.ndef.Record(data=b'\x00\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_03(self):
        nfc.ndef.Record(data=b'\x00\x00\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_04(self):
        nfc.ndef.Record(data=b'\x00\x00\x00\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_05(self):
        nfc.ndef.Record(data=b'\x00\x00\x00\x00\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_06(self):
        nfc.ndef.Record(data=b'\x10\x04\x00\x00\x00\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_07(self):
        nfc.ndef.Record(data=b'\x10\x00\x04\x00\x00\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_08(self):
        nfc.ndef.Record(data=b'\x00\x00\x00\x00\x01\x00')

    @raises(nfc.ndef.LengthError)
    def test_decode_invalid_length_09(self):
        nfc.ndef.Record(data=b'\x00\x00\x00\x00\x00\x01')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_01(self):
        nfc.ndef.Record(data=b'\x10\x01\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_02(self):
        nfc.ndef.Record(data=b'\x15\x01\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_03(self):
        nfc.ndef.Record(data=b'\x16\x01\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_04(self):
        nfc.ndef.Record(data=b'\x11\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_05(self):
        nfc.ndef.Record(data=b'\x12\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_06(self):
        nfc.ndef.Record(data=b'\x13\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_07(self):
        nfc.ndef.Record(data=b'\x14\x00\x00')

    @raises(nfc.ndef.FormatError)
    def test_decode_invalid_format_08(self):
        nfc.ndef.Record(data=b'\x10\x00\x01\x00')

    #------------------------------------------------------------------- RecordList

    def test_bv_record_list_init(self):
        rl = nfc.ndef.record.RecordList([nfc.ndef.Record()])

    @raises(TypeError)
    def test_bi_record_list_init(self):
        rl = nfc.ndef.record.RecordList(["invalid"])

    def test_bv_record_list_append(self):
        rl = nfc.ndef.record.RecordList()
        rl.append(nfc.ndef.Record())
        self.assertEqual(len(rl), 1)

    @raises(TypeError)
    def test_bi_record_list_append(self):
        rl = nfc.ndef.record.RecordList()
        rl.append("invalid")

    def test_bv_record_list_extend(self):
        rl = nfc.ndef.record.RecordList()
        rl.extend([nfc.ndef.Record(), nfc.ndef.Record()])
        self.assertEqual(len(rl), 2)

    @raises(TypeError)
    def test_bi_record_list_extend(self):
        rl = nfc.ndef.record.RecordList()
        rl.extend(["invalid", "invalid"])

    def test_bv_record_list_setitem(self):
        rl = nfc.ndef.record.RecordList([nfc.ndef.Record()])
        rl[0] = nfc.ndef.Record()
        self.assertEqual(len(rl), 1)

    @raises(TypeError)
    def test_bi_record_list_setitem(self):
        rl = nfc.ndef.record.RecordList([nfc.ndef.Record()])
        rl[0] = "invalid"

