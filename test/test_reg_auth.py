# Copyright (c) 2016 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


import os
import tempfile
import unittest
import json

from u2flib_host.utils import websafe_encode
from u2flib_host.soft import SoftU2FDevice
from u2flib_host.register import register
from u2flib_host.authenticate import authenticate


VERSION = 'U2F_V2'
FACET = 'https://example.com'
CHALLENGE = 'challenge'
KEY_HANDLE = websafe_encode(b'\0' * 64)

REG_DATA = json.dumps({
    'version': VERSION,
    'challenge': CHALLENGE,
    'appId': FACET
})

AUTH_DATA = json.dumps({
    'version': VERSION,
    'challenge': CHALLENGE,
    'appId': FACET,
    'keyHandle': KEY_HANDLE
})


class TestRegister(unittest.TestCase):
    def setUp(self):
        print('write')
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(json.dumps({"counter": 0, "keys": {}}).encode('utf8'))
            self.device_path = f.name

    def tearDown(self):
        os.unlink(self.device_path)

    def test_register(self):
        dev = SoftU2FDevice(self.device_path)

        resp = register([dev], REG_DATA, FACET)
        self.assertIn('registrationData', resp)

    def test_authenticate(self):
        dev = SoftU2FDevice(self.device_path)

        try:
            authenticate([dev], AUTH_DATA, FACET, False)
            self.fail('Key handle should not match')
        except ValueError:
            pass
