#    Copyright (C) 2014  Yubico AB
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from u2flib_host.constants import INS_ENROLL, INS_SIGN
from u2flib_host.utils import websafe_decode, websafe_encode, H
import json

VERSION = 'U2F_V2'


def verify_facet(app_id, facet):
    pass  # TODO: Verify facet.


def enroll(device, data, facet, rup=True):
    """
    Enroll a U2F device

    data = {
        "version": "U2F_V2",
        "challenge": string, //b64 encoded challenge
        "app_id": string, //app_id
        "sessionId": string //opaque session ID
    }

    """

    if isinstance(data, basestring):
        data = json.loads(data)

    if data['version'] != VERSION:
        raise ValueError("Unsupported U2F version: %s" % data['version'])

    app_id = data['app_id']
    verify_facet(app_id, facet)
    app_param = H(app_id)

    client_data = {
        'typ': "navigator.id.finishEnrollment",
        'challenge': data['challenge'],
        'origin': facet
    }
    client_data = json.dumps(client_data)
    client_param = H(client_data)

    request = client_param + app_param

    p1 = 3 if rup else 0
    p2 = 0
    response = device.send_apdu(INS_ENROLL, p1, p2, request)

    return {
        "registrationData": websafe_encode(response),
        "bd": websafe_encode(client_data),
        "sessionId": data['sessionId']
    }


def sign(device, data, facet, rup=False):
    """
    Signs an assertion challenge

    data = {
        'version': "U2F_V2",
        'challenge': websafe_encode(self.challenge),
        'app_id': self.binding.app_id,
        'key_handle': websafe_encode(self.binding.key_handle),
        'sessionId': websafe_encode(self.session_id)
    }

    """

    if isinstance(data, basestring):
        data = json.loads(data)

    if data['version'] != VERSION:
        raise ValueError("Unsupported U2F version: %s" % data['version'])

    app_id = data['app_id']
    verify_facet(app_id, facet)
    app_param = H(app_id)

    key_handle = websafe_decode(data['key_handle'])

    # Client data
    client_data = {
        'typ': "navigator.id.getAssertion",
        'challenge': data['challenge'],
        'origin': facet
    }
    client_data = json.dumps(client_data)
    client_param = H(client_data)

    request = chr(0x03) + client_param + app_param + chr(len(key_handle)) + key_handle

    p1 = 3 if rup else 0
    p2 = 0
    response = device.send_apdu(INS_SIGN, p1, p2, request)

    return {
        "bd": websafe_encode(client_data),
        "sign": websafe_encode(response),
        "challenge": data['challenge'],
        "sessionId": data['sessionId'],
        "app_id": data['app_id']
    }
