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

from u2flib_host import u2f_v2
from u2flib_host import ccid_transport, hid_transport

TRANSPORTS = [
    ccid_transport,
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
        except:
            pass
    return devices


def get_lib(data):
    return LIB_VERSIONS[data.get('version', 'U2F_V2')]


def register(device, data, facet):
    version = data.get('version')
    if version not in device.get_supported_versions():
        raise ValueError("Device does not support U2F version: %s" % version)
    if version not in LIB_VERSIONS:
        raise ValueError("Library does not support U2F version: %s" % version)

    lib = LIB_VERSIONS[version]
    return lib.register(device, data, facet)


def authenticate(device, data, facet, check_only=False):
    version = data['version']
    if version not in device.get_supported_versions():
        raise ValueError("Device does not support U2F version: %s" % version)
    if version not in LIB_VERSIONS:
        raise ValueError("Library does not support U2F version: %s" % version)

    lib = LIB_VERSIONS[version]
    return lib.authenticate(device, data, facet, check_only)
