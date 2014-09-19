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
from u2flib_host.appid import verify_facet
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

    if isinstance(data, basestring):
        data = json.loads(data)

    if data['version'] != VERSION:
        raise ValueError('Unsupported U2F version: %s' % data['version'])

    app_id = data.get('appId', facet)
    verify_facet(app_id, facet)
    app_param = H(app_id)

    client_data = {
        'typ': 'navigator.id.finishEnrollment',
        'challenge': data['challenge'],
        'origin': facet
    }
    client_data = json.dumps(client_data)
    client_param = H(client_data)

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

    if isinstance(data, basestring):
        data = json.loads(data)

    if data['version'] != VERSION:
        raise ValueError('Unsupported U2F version: %s' % data['version'])

    app_id = data.get('appId', facet)
    verify_facet(app_id, facet)
    app_param = H(app_id)

    key_handle = websafe_decode(data['keyHandle'])

    # Client data
    client_data = {
        'typ': 'navigator.id.getAssertion',
        'challenge': data['challenge'],
        'origin': facet
    }
    client_data = json.dumps(client_data)
    client_param = H(client_data)

    request = client_param + app_param + chr(
        len(key_handle)) + key_handle

    p1 = 0x07 if check_only else 0x03
    p2 = 0
    response = device.send_apdu(INS_SIGN, p1, p2, request)

    return {
        'clientData': websafe_encode(client_data),
        'signatureData': websafe_encode(response),
        'keyHandle': data['keyHandle']
    }
