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

from ..message import Message
from ..record import Record
from ..text_record import TextRecord

class TestTextRecord(unittest.TestCase):

    def test_init_args_none(self):
        record = TextRecord()
        self.assertEqual(record.text, '')
        self.assertEqual(record.language, b'en')
        self.assertEqual(record.encoding, 'UTF-8')
        
    def test_init_args_text(self):
        record = TextRecord("Hello World")
        self.assertEqual(record.text, "Hello World")
        self.assertEqual(record.language, b"en")
        self.assertEqual(record.encoding, 'UTF-8')
        self.assertEqual(bytes(record), b'\x11\x01\x0ET\x02enHello World')
        
    def test_init_kwargs_text(self):
        record = TextRecord(text="Hello World")
        self.assertEqual(record.text, "Hello World")
        self.assertEqual(record.language, b"en")
        self.assertEqual(record.encoding, 'UTF-8')
        self.assertEqual(bytes(record), b'\x11\x01\x0ET\x02enHello World')
        
    def test_init_kwargs_lang(self):
        record = TextRecord(language="de")
        self.assertEqual(record.text, "")
        self.assertEqual(record.language, b"de")
        self.assertEqual(record.encoding, 'UTF-8')
        self.assertEqual(bytes(record), b'\x11\x01\x03T\x02de')
        
    def test_init_args_text_kwargs_lang(self):
        record = TextRecord("Hallo Welt", language="de")
        self.assertEqual(record.text, "Hallo Welt")
        self.assertEqual(record.language, b"de")
        self.assertEqual(record.encoding, 'UTF-8')
        self.assertEqual(bytes(record), b'\x11\x01\x0DT\x02deHallo Welt')
        
    def test_init_kwargs_text_encoding(self):
        record = TextRecord(text="text", encoding="UTF-16")
        self.assertEqual(record.text, "text")
        self.assertEqual(record.language, b"en")
        self.assertEqual(record.encoding, 'UTF-16')
        self.assertEqual(bytes(record), b'\x11\x01\x0DT\x82en\xff\xfet\x00e\x00x\x00t\x00')
        
    def test_init_arg_record(self):
        record = Record(data=b'\x11\x01\x0DT\x02deHallo Welt')
        record = TextRecord(record)
        self.assertEqual(record.text, "Hallo Welt")
        self.assertEqual(record.language, b"de")
        self.assertEqual(record.encoding, 'UTF-8')
        self.assertEqual(bytes(record), b'\x11\x01\x0DT\x02deHallo Welt')
        
    def test_text_encode_utf8(self):
        record = TextRecord(text='\xa1\xa2')
        self.assertEqual(bytes(record), b'\x11\x01\x07T\x02en\xc2\xa1\xc2\xa2')

    def test_text_encode_utf16(self):
        record = TextRecord(text='\xa1\xa2', encoding="UTF-16")
        self.assertEqual(bytes(record), b'\x11\x01\x09T\x82en\xff\xfe\xa1\x00\xa2\x00')

    def test_text_decode_utf8(self):
        data=b'\x11\x01\x07T\x02fr\xc2\xa1\xc2\xa2'
        record = TextRecord(Record(data=data))
        self.assertEqual(record.text, '\xa1\xa2')
        self.assertEqual(record.language, b"fr")

    def test_text_decode_utf16(self):
        data=b'\x11\x01\x09T\x82fr\xff\xfe\xa1\x00\xa2\x00'
        record = TextRecord(Record(data=data))
        self.assertEqual(record.text, '\xa1\xa2')
        self.assertEqual(record.language, b"fr")

    def test_data_length_error(self):
        data=b'\x11\x01\x0DT\x0DdeHallo Welt'
        record = TextRecord(Record(data=data))
        self.assertEqual(record.language, b"deHallo Welt")
        self.assertEqual(record.text, "")

