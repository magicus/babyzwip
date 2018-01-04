import pytest

from zwip.Controller import Frame, InvalidFrame, REQUEST, FUNC_ID_ZW_GET_VERSION

class TestFrame(object):

    request_get_version_bytearray = bytearray([0x01, 0x03, 0x00, 0x15, 0xe9])

    def test_basics(self):
        frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
        assert frame
        assert frame.function == FUNC_ID_ZW_GET_VERSION
        assert frame.frame_type == REQUEST

    def test_as_bytearray(self):
        frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
        array = frame.as_bytearray()
        assert array == self.request_get_version_bytearray

    def test_parse(self):
        frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
        parsed_frame = Frame.parse(self.request_get_version_bytearray)
        assert parsed_frame == frame

    def test_parse_with_errors(self):
        # set length byte wrong
        array = self.request_get_version_bytearray
        array[1] = 1
        with pytest.raises(InvalidFrame):
            parsed_frame = Frame.parse(array)

        # make it too long
        array = self.request_get_version_bytearray + bytearray([0])
        with pytest.raises(InvalidFrame):
            parsed_frame = Frame.parse(array)

        # make it too short
        array = self.request_get_version_bytearray[:len(self.request_get_version_bytearray)-1]
        with pytest.raises(InvalidFrame):
            parsed_frame = Frame.parse(array)

        # set checksum byte wrong
        array = self.request_get_version_bytearray
        array[-1] = 0
        with pytest.raises(InvalidFrame):
            parsed_frame = Frame.parse(array)

        # mess up SOF
        array = self.request_get_version_bytearray
        array[0] = 17
        with pytest.raises(InvalidFrame):
            parsed_frame = Frame.parse(array)
