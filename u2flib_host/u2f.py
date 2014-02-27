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

from u2flib_host import u2f_v0, u2f_v2
from u2flib_host import winusb, ccid

TRANSPORTS = [
    winusb,
    ccid
]

LIB_VERSIONS = {
    'v0': u2f_v0,
    'U2F_V2': u2f_v2
}


def list_devices():
    # Combine list_devices for all transports.
    return [dev for trans in TRANSPORTS for dev in trans.list_devices()]


def get_lib(data):
    version = data.get('version', 'v0')
    return LIB_VERSIONS[data.get('version', 'v0')]


def enroll(device, data, facet, rup=True):
    version = data.get('version', 'v0')
    if version not in device.get_supported_versions():
        raise ValueError("Device does not support U2F version: %s" % version)
    if version not in LIB_VERSIONS:
        raise ValueError("Library does not support U2F version: %s" % version)

    lib = LIB_VERSIONS[version]
    return lib.enroll(device, data, facet, rup)


def sign(device, data, facet, rup=False):
    version = data['version']
    if version not in device.get_supported_versions():
        raise ValueError("Device does not support U2F version: %s" % version)
    if version not in LIB_VERSIONS:
        raise ValueError("Library does not support U2F version: %s" % version)

    lib = LIB_VERSIONS[version]
    return lib.sign(device, data, facet, rup)
