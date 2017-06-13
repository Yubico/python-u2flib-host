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

from u2flib_host.constants import APDU_OK, INS_GET_VERSION
from u2flib_host.yubicommon.compat import int2byte
from u2flib_host import exc
import struct


class U2FDevice(object):

    """
    A handle to a U2F device.
    device.open() needs to be called prior to using the device, and
    device.close() should be called when the device is no longer needed, to
    ensure that any held resources are released.
    As an aternative, the 'with' statement can be used:

        with device as dev:
            dev.send_apdu(...)
    """

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __del__(self):
        self.close()

    def open(self):
        """
        Opens the device for use.
        """
        pass

    def close(self):
        """
        Closes the device, making it available for use by others.
        """
        pass

    def get_supported_versions(self):
        """
        Gets a list of supported U2F versions from the device.
        """
        if not hasattr(self, '_versions'):
            try:
                self._versions = [self.send_apdu(INS_GET_VERSION).decode()]
            except exc.APDUError as e:
                # v0 didn't support the instruction.
                self._versions = ['v0'] if e.code == 0x6d00 else []

        return self._versions

    def _do_send_apdu(self, apdu_data):
        """
        Sends an APDU to the device, and returns the response.
        """
        # Subclasses should implement this.
        raise NotImplementedError('_do_send_apdu not implemented!')

    def send_apdu(self, ins, p1=0, p2=0, data=b''):
        """
        Sends an APDU to the device, and waits for a response.
        """
        if data is None:
            data = b''
        elif isinstance(data, int):
            data = int2byte(data)

        size = len(data)
        l0 = size >> 16 & 0xff
        l1 = size >> 8 & 0xff
        l2 = size & 0xff
        apdu_data = struct.pack('B B B B B B B %is B B' % size,
                                0, ins, p1, p2, l0, l1, l2, data, 0x04, 0x00)
        try:
            resp = self._do_send_apdu(apdu_data)
        except Exception as e:
            # TODO Use six.reraise if/when Six becomes an agreed dependency.
            raise exc.DeviceError(e)
        status = struct.unpack('>H', resp[-2:])[0]
        data = resp[:-2]
        if status != APDU_OK:
            raise exc.APDUError(status)
        return data
