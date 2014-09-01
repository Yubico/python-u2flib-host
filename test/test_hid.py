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

from u2flib_host.hid_transport import list_devices
from nose import SkipTest


def get_device():
    devs = list_devices()
    if len(devs) != 1:
        raise SkipTest("Tests require a single U2FHID device")
    return devs[0]


def test_open_close():
    dev = get_device()
    for i in xrange(0, 10):
        dev.open()
        dev.close()


def test_echo():
    msg1 = 'hello world!'
    msg2 = '            '
    msg3 = ''
    with get_device() as dev:
        resp1 = dev.send_apdu(0x40, 0, 0, msg1)
        resp2 = dev.send_apdu(0x40, 0, 0, msg2)
        resp3 = dev.send_apdu(0x40, 0, 0, msg3)
    assert resp1 == msg1
    assert resp2 == msg2
    assert resp3 == msg3
