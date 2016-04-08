
from u2flib_host.constants import INS_ENROLL, INS_SIGN, APDU_USE_NOT_SATISFIED
from u2flib_host.utils import websafe_decode, websafe_encode
from u2flib_host.exc import APDUError
from u2flib_host import u2f_v2
import unittest
import json

VERSION = 'U2F_V2'
FACET = 'https://example.com'
CHALLENGE = 'challenge'
KEY_HANDLE = websafe_encode(b'\0' * 64)

REG_DATA = json.dumps({
    'version': VERSION,
    'challenge': CHALLENGE,
    'appId': FACET
})

AUTH_DATA = json.dumps({
    'version': VERSION,
    'challenge': CHALLENGE,
    'appId': FACET,
    'keyHandle': KEY_HANDLE
})

DUMMY_RESP = b'a_dummy_response'


class MockDevice(object):

    def __init__(self, response):
        self._response = response

    def send_apdu(self, ins, p1, p2, request):
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.request = request

        if isinstance(self._response, Exception):
            raise self._response
        return self._response


class TestU2FV2(unittest.TestCase):

    def test_register(self):
        device = MockDevice(DUMMY_RESP)
        response = u2f_v2.register(device, REG_DATA, FACET)

        self.assertEqual(device.ins, INS_ENROLL)
        self.assertEqual(device.p1, 0x03)
        self.assertEqual(device.p2, 0x00)
        self.assertEqual(len(device.request), 64)

        self.assertEqual(websafe_decode(response['registrationData']),
                         DUMMY_RESP)

        client_data = json.loads(websafe_decode(response['clientData'])
                                 .decode('utf8'))
        self.assertEqual(client_data['typ'], 'navigator.id.finishEnrollment')
        self.assertEqual(client_data['origin'], FACET)
        self.assertEqual(client_data['challenge'], CHALLENGE)

    def test_authenticate(self):
        device = MockDevice(DUMMY_RESP)
        response = u2f_v2.authenticate(device, AUTH_DATA, FACET, False)

        self.assertEqual(device.ins, INS_SIGN)
        self.assertEqual(device.p1, 0x03)
        self.assertEqual(device.p2, 0x00)
        self.assertEqual(len(device.request), 64 + 1 + 64)
        self.assertEqual(device.request[-64:], websafe_decode(KEY_HANDLE))

        self.assertEqual(response['keyHandle'], KEY_HANDLE)
        self.assertEqual(websafe_decode(response['signatureData']), DUMMY_RESP)

        client_data = json.loads(websafe_decode(response['clientData'])
                                 .decode('utf8'))
        self.assertEqual(client_data['typ'], 'navigator.id.getAssertion')
        self.assertEqual(client_data['origin'], FACET)
        self.assertEqual(client_data['challenge'], CHALLENGE)

    def test_authenticate_check_only(self):
        device = MockDevice(APDUError(APDU_USE_NOT_SATISFIED))

        try:
            u2f_v2.authenticate(device, AUTH_DATA, FACET, True)
            self.fail('authenticate should throw USE_NOT_SATISIFIED')
        except APDUError as e:
            self.assertEqual(device.ins, INS_SIGN)
            self.assertEqual(device.p1, 0x07)
            self.assertEqual(e.code, APDU_USE_NOT_SATISFIED)
