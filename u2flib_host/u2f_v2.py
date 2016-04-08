# Copyright (c) 2013 Yubico AB
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

from u2flib_host.constants import INS_ENROLL, INS_SIGN
from u2flib_host.utils import websafe_decode, websafe_encode
from u2flib_host.appid import verify_facet
from u2flib_host.yubicommon.compat import string_types, int2byte

from hashlib import sha256
import json

VERSION = 'U2F_V2'


def register(device, data, facet):
    """
    Register a U2F device

    data = {
        "version": "U2F_V2",
        "challenge": string, //b64 encoded challenge
        "appId": string, //app_id
    }

    """

    if isinstance(data, string_types):
        data = json.loads(data)

    if data['version'] != VERSION:
        raise ValueError('Unsupported U2F version: %s' % data['version'])

    app_id = data.get('appId', facet)
    verify_facet(app_id, facet)
    app_param = sha256(app_id.encode('utf8')).digest()

    client_data = {
        'typ': 'navigator.id.finishEnrollment',
        'challenge': data['challenge'],
        'origin': facet
    }
    client_data = json.dumps(client_data)
    client_param = sha256(client_data.encode('utf8')).digest()

    request = client_param + app_param

    p1 = 0x03
    p2 = 0
    response = device.send_apdu(INS_ENROLL, p1, p2, request)

    return {
        'registrationData': websafe_encode(response),
        'clientData': websafe_encode(client_data)
    }


def authenticate(device, data, facet, check_only=False):
    """
    Signs an authentication challenge

    data = {
        'version': "U2F_V2",
        'challenge': websafe_encode(self.challenge),
        'appId': self.binding.app_id,
        'keyHandle': websafe_encode(self.binding.key_handle)
    }

    """

    if isinstance(data, string_types):
        data = json.loads(data)

    if data['version'] != VERSION:
        raise ValueError('Unsupported U2F version: %s' % data['version'])

    app_id = data.get('appId', facet)
    verify_facet(app_id, facet)
    app_param = sha256(app_id.encode('utf8')).digest()

    key_handle = websafe_decode(data['keyHandle'])

    # Client data
    client_data = {
        'typ': 'navigator.id.getAssertion',
        'challenge': data['challenge'],
        'origin': facet
    }
    client_data = json.dumps(client_data)
    client_param = sha256(client_data.encode('utf8')).digest()

    request = client_param + app_param + int2byte(
        len(key_handle)) + key_handle

    p1 = 0x07 if check_only else 0x03
    p2 = 0
    response = device.send_apdu(INS_SIGN, p1, p2, request)

    return {
        'clientData': websafe_encode(client_data),
        'signatureData': websafe_encode(response),
        'keyHandle': data['keyHandle']
    }
