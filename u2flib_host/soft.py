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

from __future__ import print_function

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    print("The soft U2F token requires cryptography.")
    raise

from u2flib_host.device import U2FDevice
from u2flib_host.constants import INS_ENROLL, INS_SIGN
from u2flib_host.yubicommon.compat import byte2int, int2byte
from u2flib_host import exc
import base64
import json
import os
import struct

# AKA NID_X9_62_prime256v1 in OpenSSL
CURVE = ec.SECP256R1

CERT = base64.b64decode(b"""
MIIBhzCCAS6gAwIBAgIJAJm+6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwW
WXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYx
NDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ+w3gnnXEPIBl1J3pol6IviRAMc
/hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF/XCGvHYEto1AwTjAdBgNVHQ4E
FgQUDai/k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai/k1dOImjupkub
YxhOkoX3sZ4wDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnY
VWhuyCbZ+OKNtSpovBB7A5OHAH52dK9/AiEA+mT4tz5eJV8W2OwVxcq6ZIjrwqXc
jXSy2G0k27yAUDk=
""")
CERT_PRIV = b"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMyk3gKcDg5lsYdl48fZoIFORhAc9cQxmn2Whv/+ya+2oAoGCCqGSM49
AwEHoUQDQgAEO+GX3XN+mD2fsN4J51xDyAZdSd6aJeiL4kQDHP4QiGRWww8DLOG0
lnhXcKoxn4w5SAgK3ZozFpwxf1whrx2BLQ==
-----END EC PRIVATE KEY-----
"""


def _b16text(s):
    """Encode a byte string s as base16 in a textual (unicode) string."""
    return base64.b16encode(s).decode('ascii')


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

    def send_apdu(self, ins, p1=0, p2=0, data=b''):
        if ins == INS_ENROLL:
            return self._register(data)
        elif ins == INS_SIGN:
            return self._authenticate(data)
        raise exc.APDUError(0x6d00)  # INS not supported.

    def _register(self, data):
        client_param = data[:32]
        app_param = data[32:]

        # ECC key generation
        privu = ec.generate_private_key(CURVE(), default_backend())
        pubu = privu.public_key()
        pub_key_der = pubu.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_key = pub_key_der[-65:]

        # Store
        key_handle = os.urandom(64)
        priv_key_pem = privu.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.data['keys'][_b16text(key_handle)] = {
            'priv_key': priv_key_pem.decode('ascii'),
            'app_param': _b16text(app_param),
        }
        self._persist()

        # Attestation signature
        cert = CERT
        cert_priv = serialization.load_pem_private_key(
            CERT_PRIV, password=None, backend=default_backend(),
        )
        signer = cert_priv.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(
            b'\x00' + app_param + client_param + key_handle + pub_key
        )
        signature = signer.finalize()

        raw_response = b'\x05' + pub_key + int2byte(len(key_handle)) + \
            key_handle + cert + signature

        return raw_response

    def _authenticate(self, data):
        client_param = data[:32]
        app_param = data[32:64]
        kh_len = byte2int(data[64])
        key_handle = _b16text(data[65:65+kh_len])
        if key_handle not in self.data['keys']:
            raise ValueError("Unknown key handle!")

        # Unwrap:
        unwrapped = self.data['keys'][key_handle]
        if app_param != base64.b16decode(unwrapped['app_param']):
            raise ValueError("Incorrect app param!")
        priv_pem = unwrapped['priv_key'].encode('ascii')
        privu = serialization.load_pem_private_key(
            priv_pem, password=None, backend=default_backend(),
        )

        # Increment counter
        self.data['counter'] += 1
        self._persist()

        # Create signature
        touch = b'\x01' # Always indicate user presence
        counter = struct.pack('>I', self.data['counter'])

        signer = privu.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(app_param + touch + counter + client_param)
        signature = signer.finalize()
        raw_response = touch + counter + signature

        return raw_response
