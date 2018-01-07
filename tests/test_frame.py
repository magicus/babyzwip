import pytest

from zwip.Controller import *

class TestFrame(object):

    request_get_version_bytearray = bytearray([0x01, 0x03, 0x00, 0x15, 0xe9])

    def test_basics(self):
        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
        assert frame
        assert frame.function == cmd.FUNC_ID_ZW_GET_VERSION
        assert frame.frame_type == REQUEST
        frame2 = Frame(RESPONSE, cmd.FUNC_ID_ZW_GET_VERSION)
        assert frame != frame2

    def test_as_bytearray(self):
        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
        array = frame.as_bytearray()
        assert array == self.request_get_version_bytearray

    def test_parse(self):
        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
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

class TestRawFrame:

    def test_raw_frame_exchange(self):
        sender = FakeSender()
        sender.open(RawFrameProtocol)
        port = sender.port

        controller = SerialController()
        controller.open(sender.port, RawFrameProtocol)

        protocol = controller.protocol
        remote = sender.remote_protocol()

        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
        protocol.write_frame(frame)

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == frame
        if isinstance(remote_frame, BadPacket):
            remote.write_frame(SimplePacket(NAK))
        elif isinstance(remote_frame, Frame):
            remote.write_frame(SimplePacket(ACK))

        pro_frame = protocol.get_frame(block=True)
        assert pro_frame == SimplePacket(ACK)
        if isinstance(pro_frame, BadPacket):
            protocol.write_frame(SimplePacket(NAK))
        elif isinstance(pro_frame, Frame):
            protocol.write_frame(SimplePacket(ACK))

        frame2 = Frame(RESPONSE, cmd.FUNC_ID_ZW_GET_VERSION)
        remote.write_frame(frame2)

        pro_frame = protocol.get_frame(block=True)
        assert pro_frame == frame2
        if isinstance(pro_frame, BadPacket):
            protocol.write_frame(SimplePacket(NAK))
        elif isinstance(pro_frame, Frame):
            protocol.write_frame(SimplePacket(ACK))

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == SimplePacket(ACK)
        if isinstance(remote_frame, BadPacket):
            remote.write_frame(SimplePacket(NAK))
        elif isinstance(remote_frame, Frame):
            remote.write_frame(SimplePacket(ACK))

        assert not remote.has_frame()
        assert not protocol.has_frame()

        controller.close()
        sender.close()

    def test_cooked_frame_exchange(self):
        sender = FakeSender()
        sender.open()
        port = sender.port

        controller = SerialController()
        controller.open(sender.port)

        protocol = controller.protocol
        remote = sender.remote_protocol()

        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
        protocol.write_frame(frame)

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == frame

        frame2 = Frame(RESPONSE, cmd.FUNC_ID_ZW_GET_VERSION)
        remote.write_frame(frame2)

        pro_frame = protocol.get_frame(block=True)
        assert pro_frame == frame2

        assert not remote.has_frame()
        assert not protocol.has_frame()

        controller.close()
        sender.close()

    def test_raw_to_cooked_frame_exchange(self):
        sender = FakeSender()
        sender.open(RawFrameProtocol)
        port = sender.port

        controller = SerialController()
        controller.open(sender.port)

        protocol = controller.protocol
        remote = sender.remote_protocol()

        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
        protocol.write_frame(frame)

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == frame
        if isinstance(remote_frame, BadPacket):
            remote.write_frame(SimplePacket(NAK))
        elif isinstance(remote_frame, Frame):
            remote.write_frame(SimplePacket(ACK))

        frame2 = Frame(RESPONSE, cmd.FUNC_ID_ZW_GET_VERSION)
        remote.write_frame(frame2)

        pro_frame = protocol.get_frame(block=True)
        assert pro_frame == frame2

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == SimplePacket(ACK)
        if isinstance(remote_frame, BadPacket):
            remote.write_frame(SimplePacket(NAK))
        elif isinstance(remote_frame, Frame):
            remote.write_frame(SimplePacket(ACK))

        assert not remote.has_frame()
        assert not protocol.has_frame()

        controller.close()
        sender.close()

    def test_bad_data_from_controller(self):
        sender = FakeSender()
        sender.open(RawFrameProtocol)
        port = sender.port

        controller = SerialController()
        controller.open(sender.port)

        protocol = controller.protocol
        remote = sender.remote_protocol()

        frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
        protocol.write_frame(frame)

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == frame

        frame2 = BadPacket(bytearray([17, 47]))
        remote.write_frame(frame2)

        remote_frame = remote.get_frame(block=True)
        assert remote_frame == SimplePacket(NAK)
        remote_frame = remote.get_frame(block=True)
        assert remote_frame == SimplePacket(NAK)

        assert not remote.has_frame()
        assert not protocol.has_frame()

        controller.close()
        sender.close()

