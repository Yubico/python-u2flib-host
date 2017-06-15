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

from u2flib_host import u2f, exc, __version__
from u2flib_host.constants import APDU_USE_NOT_SATISFIED
from u2flib_host.utils import u2str
from u2flib_host.yubicommon.compat import text_type

import time
import json
import argparse
import sys


def authenticate(devices, params, facet, check_only):
    """
    Interactively authenticates a AuthenticateRequest using an attached U2F
    device.
    """
    for device in devices[:]:
        try:
            device.open()
        except:
            devices.remove(device)

    try:
        prompted = False
        while devices:
            removed = []
            for device in devices:
                try:
                    return u2f.authenticate(device, params, facet, check_only)
                except exc.APDUError as e:
                    if e.code == APDU_USE_NOT_SATISFIED:
                        if check_only:
                            sys.stderr.write('\nCorrect U2F device present!\n')
                            sys.exit(0)
                        if not prompted:
                            sys.stderr.write('\nTouch the flashing U2F device '
                                             'to authenticate...\n')
                            prompted = True
                    else:
                        removed.append(device)
                except exc.DeviceError:
                    removed.append(device)
            devices = [d for d in devices if d not in removed]
            for d in removed:
                d.close()
            time.sleep(0.25)
    finally:
        for device in devices:
            device.close()
    sys.stderr.write('\nThe required U2F device is not present!\n')
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Authenticaties an AuthenticateRequest.\n"
        "Takes a JSON formatted AuthenticateRequest object on stdin, and "
        "returns the resulting AuthenticateResponse on stdout.",
        add_help=True
    )
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s ' + __version__)
    parser.add_argument('facet', help='the facet for the challenge')
    parser.add_argument('-c', '--check-only', action="store_true", help='Check if '
                        'the key handle is correct only, don\'t sign.')
    parser.add_argument('-i', '--infile', help='specify a file to read '
                        'AuthenticateRequest from, instead of stdin')
    parser.add_argument('-o', '--outfile', help='specify a file to write '
                        'the AuthenticateResponse to, instead of stdout')
    parser.add_argument('-s', '--soft', help='Specify a soft U2F token file to use')
    return parser.parse_args()


def main():
    args = parse_args()

    facet = text_type(args.facet)
    if args.infile:
        with open(args.infile, 'r') as f:
            data = f.read()
    else:
        if sys.stdin.isatty():
            sys.stderr.write('Enter AuthenticateRequest JSON data...\n')
        data = sys.stdin.read()

    params = json.loads(data)
    if args.soft:
        from u2flib_host.soft import SoftU2FDevice
        devices = [SoftU2FDevice(args.soft)]
    else:
        devices = u2f.list_devices()
    result = authenticate(devices, params, facet, args.check_only)

    if args.outfile:
        with open(args.outfile, 'w') as f:
            json.dump(result, f)
        sys.stderr.write('Output written to %s\n' % args.outfile)
    else:
        sys.stderr.write('\n---Result---\n')
        print(json.dumps(result))


if __name__ == '__main__':
    main()
