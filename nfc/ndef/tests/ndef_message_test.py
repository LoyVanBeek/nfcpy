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

import io

from ..record import Record
from ..message import Message
from ..error import FormatError, LengthError

class TestMessageInit(unittest.TestCase):

    def test_init_args_none(self):
        message = Message()
        assert isinstance(message, Message)

    def test_init_args_bytestr(self):
        message = Message(b"\xD0\x00\x00")
        assert len(message) == 1

    def test_init_args_bytearray(self):
        message = Message(bytearray(b"\xD0\x00\x00"))
        assert len(message) == 1

    def test_init_args_bytestream(self):
        message = Message(io.BytesIO(b"\xD0\x00\x00"))
        assert len(message) == 1

    def test_generate_bytestr(self):
        message = Message(b"\xD0\x00\x00")
        assert str(message) == b"\xD0\x00\x00"

    def test_init_args_one_record(self):
        record = Record()
        message = Message(record)
        assert str(message) == b"\xD0\x00\x00"

    def test_init_args_two_records(self):
        record = Record()
        message = Message(record, record)
        assert str(message) == b"\x90\x00\x00\x50\x00\x00"

class TestMessageMethods(unittest.TestCase):
    def test_method_length(self):
        message = Message()
        assert len(message) == 0

    def test_method_getitem(self):
        message = Message()
        try: assert message[0]
        except IndexError: pass

    def test_method_append(self):
        message = Message()
        message.append(Record())
        assert len(message) == 1
        assert isinstance(message[0], Record)

    def test_method_extend(self):
        message = Message()
        message.extend([Record()])
        assert len(message) == 1
        assert isinstance(message[0], Record)

    def test_method_insert(self):
        message = Message()
        message.insert(0, Record())
        assert len(message) == 1
        assert isinstance(message[0], Record)

class TestMessageFailure(unittest.TestCase):

    def test_failure_mb_not_set(self):
        try: message = Message(b"\x10\x00\x00")
        except FormatError: pass

    def test_failure_length_error(self):
        try: message = Message(b"\x10\x01\x00")
        except LengthError: pass
