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

from u2flib_host import u2f_v2
from u2flib_host import hid_transport

import json
import six

TRANSPORTS = [
    hid_transport
]

LIB_VERSIONS = {
    'U2F_V2': u2f_v2
}


def list_devices():
    # Combine list_devices for all transports, ignoring exceptions.
    devices = []
    for transport in TRANSPORTS:
        try:
            devices.extend(transport.list_devices())
        except Exception:
            pass
    return devices


def get_lib(device, data):
    if isinstance(data, six.string_types):
        data = json.loads(data)

    version = data['version']
    if version not in device.get_supported_versions():
        raise ValueError("Device does not support U2F version: %s" % version)
    if version not in LIB_VERSIONS:
        raise ValueError("Library does not support U2F version: %s" % version)

    return LIB_VERSIONS[version]


def register(device, data, facet):
    lib = get_lib(device, data)
    return lib.register(device, data, facet)


def authenticate(device, data, facet, check_only=False):
    lib = get_lib(device, data)
    return lib.authenticate(device, data, facet, check_only)
