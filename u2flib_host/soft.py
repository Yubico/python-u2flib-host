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

try:
    from M2Crypto import EC, BIO
except ImportError:
    print "The soft U2F token requires M2Crypto."
    raise

from u2flib_host.utils import H
from u2flib_host.device import U2FDevice
from u2flib_host.constants import INS_ENROLL, INS_SIGN
from u2flib_host import exc
import json
import os
import struct

CURVE = EC.NID_X9_62_prime256v1

CERT = """
MIIBhzCCAS6gAwIBAgIJAJm+6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwW
WXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYx
NDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ+w3gnnXEPIBl1J3pol6IviRAMc
/hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF/XCGvHYEto1AwTjAdBgNVHQ4E
FgQUDai/k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai/k1dOImjupkub
YxhOkoX3sZ4wDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnY
VWhuyCbZ+OKNtSpovBB7A5OHAH52dK9/AiEA+mT4tz5eJV8W2OwVxcq6ZIjrwqXc
jXSy2G0k27yAUDk=
""".decode('base64')
CERT_PRIV = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMyk3gKcDg5lsYdl48fZoIFORhAc9cQxmn2Whv/+ya+2oAoGCCqGSM49
AwEHoUQDQgAEO+GX3XN+mD2fsN4J51xDyAZdSd6aJeiL4kQDHP4QiGRWww8DLOG0
lnhXcKoxn4w5SAgK3ZozFpwxf1whrx2BLQ==
-----END EC PRIVATE KEY-----
"""


class SoftU2FDevice(U2FDevice):

    """
    This simulates the U2F browser API with a soft U2F device connected.

    It can be used for testing.

    """

    def __init__(self, filename):
        super(SoftU2FDevice, self).__init__()
        self.filename = filename
        try:
            with open(filename, 'r') as fp:
                self.data = json.load(fp)
        except IOError:
            self.data = {'counter': 0, 'keys': {}}

    def _persist(self):
        with open(self.filename, 'w') as fp:
            json.dump(self.data, fp)

    def get_supported_versions(self):
        return ['U2F_V2']

    def send_apdu(self, ins, p1=0, p2=0, data=''):
        if ins == INS_ENROLL:
            return self._register(data)
        elif ins == INS_SIGN:
            return self._authenticate(data)
        raise exc.APDUError(0x6d00)  # INS not supported.

    def _register(self, data):
        client_param = data[:32]
        app_param = data[32:]

        # ECC key generation
        privu = EC.gen_params(CURVE)
        privu.gen_key()
        pub_key = str(privu.pub().get_der())[-65:]

        # Store
        key_handle = os.urandom(64)
        bio = BIO.MemoryBuffer()
        privu.save_key_bio(bio, None)
        self.data['keys'][key_handle.encode('hex')] = {
            'priv_key': bio.read_all(),
            'app_param': app_param.encode('hex')
        }
        self._persist()

        # Attestation signature
        cert_priv = EC.load_key_bio(BIO.MemoryBuffer(CERT_PRIV))
        cert = CERT
        digest = H(chr(0x00) + app_param + client_param + key_handle + pub_key)
        signature = cert_priv.sign_dsa_asn1(digest)

        raw_response = chr(0x05) + pub_key + chr(len(key_handle)) + \
            key_handle + cert + signature

        return raw_response

    def _authenticate(self, data):
        client_param = data[:32]
        app_param = data[32:64]
        kh_len = ord(data[64])
        key_handle = data[65:65 + kh_len].encode('hex')
        if key_handle not in self.data['keys']:
            raise ValueError("Unknown key handle!")

        # Unwrap:
        unwrapped = self.data['keys'][key_handle]
        if app_param != unwrapped['app_param'].decode('hex'):
            raise ValueError("Incorrect app param!")
        priv_pem = unwrapped['priv_key'].encode('ascii')
        privu = EC.load_key_bio(BIO.MemoryBuffer(priv_pem))

        # Increment counter
        self.data['counter'] += 1
        self._persist()

        # Create signature
        touch = chr(1)  # Always indicate user presence
        counter = struct.pack('>I', self.data['counter'])

        digest = H(app_param + touch + counter + client_param)
        signature = privu.sign_dsa_asn1(digest)
        raw_response = touch + counter + signature

        return raw_response
