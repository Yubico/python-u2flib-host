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
from urlparse import urlparse

VERSION = 'v0'


def prepare_ho(origin):
    url = urlparse(origin)
    canonical = '%s://%s' % (url.scheme, url.hostname.encode('idna'))
    if url.port:
        if not ((url.scheme == 'http' and url.port == 80)
           or (url.scheme == 'https' and url.port == 443)):
            canonical += ':%d' % url.port

    return H(canonical)


def enroll(device, keys, origin, rup=True):
    """
    keys = {
        "v1": "BPi7ppTCEi...", #b64 encoded DER encoded ys
        "v2": "..."
    }
    """

    ys = websafe_decode(keys[VERSION])
    ho = prepare_ho(origin)
    data = ys + ho

    p1 = 3 if rup else 0
    p2 = 0
    response = device.send_apdu(INS_ENROLL, p1, p2, data)
    return {
        'version': VERSION,
        'dh': websafe_encode(response[:65]),
        'grm': websafe_encode(response[65:])
    }


def sign(device, params, origin, rup=False):
    """
    params = {
        "version": "v0",
        "key_handle": "PCbxwb-Al...",
        "challenge": "gaj0GUFl15...",
    }
    """

    hk = websafe_decode(params['key_handle'])
    challenge = websafe_decode(params['challenge'])
    ho = prepare_ho(origin)

    data = challenge + ho + hk

    p1 = 3 if rup else 0
    p2 = 0
    response = device.send_apdu(INS_SIGN, p1, p2, data)
    return {
        'touch': '%d' % ord(response[0]),
        'enc': websafe_encode(response[1:])
    }
