# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
#
# NFC Data Exchange Format (NDEF) package
#
"""
Support for decoding and encoding of NFC Data Exchange Format (NDEF)
records and messages.
"""

from .error import *
from .message import Message
from .record import Record
from .text_record import TextRecord
from .uri_record import UriRecord
from .smart_poster import SmartPosterRecord
from .handover import HandoverRequestMessage
from .handover import HandoverSelectMessage
from .handover import HandoverCarrierRecord
from .bt_record import BluetoothConfigRecord
from .wifi_record import WifiConfigRecord
from .wifi_record import WifiPasswordRecord
from .signature import SignatureRecord, SignatureType, HashType
