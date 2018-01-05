import pytest

from zwip.Controller import Frame, InvalidFrame, REQUEST, RESPONSE, FUNC_ID_ZW_GET_VERSION

class TestFrame(object):

    request_get_version_bytearray = bytearray([0x01, 0x03, 0x00, 0x15, 0xe9])

    def test_basics(self):
        frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
        assert frame
        assert frame.function == FUNC_ID_ZW_GET_VERSION
        assert frame.frame_type == REQUEST
        frame2 = Frame(RESPONSE, FUNC_ID_ZW_GET_VERSION)
        assert frame != frame2

    def test_as_bytearray(self):
        frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
        array = frame.as_bytearray()
        assert array == self.request_get_version_bytearray

    def test_parse(self):
        frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
        parsed_frame = Frame.parse(self.request_get_version_bytearray)
        assert parsed_frame == frame

    def test_parse_bad_length(self):
        array = bytearray(self.request_get_version_bytearray)
        array[1] = 1
        with pytest.raises(InvalidFrame, match='Length mismatch'):
            parsed_frame = Frame.parse(array)

    def test_parse_too_long(self):
        array = self.request_get_version_bytearray + bytearray([0])
        with pytest.raises(InvalidFrame, match='Length mismatch'):
            parsed_frame = Frame.parse(array)

    def test_parse_too_short(self):
        array = self.request_get_version_bytearray[:len(self.request_get_version_bytearray)-1]
        with pytest.raises(InvalidFrame, match='Length mismatch'):
            parsed_frame = Frame.parse(array)

    def test_parse_bad_checksum(self):
        array = bytearray(self.request_get_version_bytearray)
        array[-1] = 0
        with pytest.raises(InvalidFrame, match='Checksum incorrect'):
            parsed_frame = Frame.parse(array)

    def test_parse_bad_sof(self):
        array = bytearray(self.request_get_version_bytearray)
        array[0] = 17
        with pytest.raises(InvalidFrame, match='No SOF at beginning'):
            parsed_frame = Frame.parse(array)

    def test_parse_empty(self):
        array = bytearray([])
        with pytest.raises(InvalidFrame, match='Frame too short'):
            parsed_frame = Frame.parse(array)

        array = bytearray([1]) # 1 == SOF
        with pytest.raises(InvalidFrame, match='Frame too short'):
            parsed_frame = Frame.parse(array)
