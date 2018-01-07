import socketserver
import struct
import threading
from queue import Queue

import serial
import serial.tools.list_ports
import serial.threaded

SOF = 0x01
ACK = 0x06
NAK = 0x15
CAN = 0x18

frame_type_str = {
    SOF: "SOF",
    ACK: "ACK",
    NAK: "NAK",
    CAN: "CAN"
}

REQUEST = 0x00
RESPONSE = 0x01

# "Bunch" suggestion from https://stackoverflow.com/a/2597440
class Bunch(object):
  def __init__(self, adict):
    self.__dict__.update(adict)

commands = {
    'FUNC_ID_ZW_GET_VERSION': 0x15,
    'FUNC_ID_ZW_MEMORY_GET_ID': 0x20,
    'FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES': 0x05,
    'FUNC_ID_SERIAL_API_GET_CAPABILITIES': 0x07,
    'FUNC_ID_ZW_GET_SUC_NODE_ID': 0x56,
    'FUNC_ID_ZW_GET_VIRTUAL_NODES': 0xA5,
    'FUNC_ID_SERIAL_API_GET_INIT_DATA': 0x02
}

cmd = Bunch(commands)

class FrameProtocol(serial.threaded.Protocol):
    class State:
        Open, WantLength, WantData = range(3)

    def __init__(self):
        self.packet = bytearray()
        self.in_packet = False
        self.transport = None
        self.state = self.State.Open
        self.wanted_length = 0
        self.input_queue = Queue()

    def connection_made(self, transport):
        """Store transport"""
        self.transport = transport

    def connection_lost(self, exc):
        """Forget transport"""
        self.transport = None
        self.in_packet = False
        del self.packet[:]
        self.state = self.State.Open
        self.wanted_length = 0
        super().connection_lost(exc)

    def data_received(self, data):
        for byte in serial.iterbytes(data):
            intval = int.from_bytes(byte, "big")  # network byte order

            if self.state == self.State.Open:
                if intval == ACK:
                    self.handle_simple_packet([ACK])
                elif intval == NAK:
                    self.handle_simple_packet([NAK])
                elif intval == CAN:
                    self.handle_simple_packet([CAN])
                elif intval == SOF:
                    self.state = self.State.WantLength
                    self.packet.extend(byte)
                    # FIXME: set timeout for this operation?
                else:
                    self.handle_bad_data(byte)
            elif self.state == self.State.WantLength:
                self.wanted_length = intval
                self.packet.extend(byte)
                self.state = self.State.WantData
                # FIXME: timeout?
            elif self.state == self.State.WantData:
                self.packet.extend(byte)
                if len(self.packet) == self.wanted_length+2:
                    self.handle_packet(self.packet)
                    self.state = self.State.Open
                    self.wanted_length = 0
                    self.packet = bytearray()

    def _frame_received(self, frame):
        self.input_queue.put(frame)

    def handle_simple_packet(self, packet):
        frame = SimplePacket.parse(packet)
        self._frame_received(frame)

    def handle_packet(self, packet):
        frame = Frame.parse(packet)
        self._frame_received(frame)

    def handle_bad_data(self, data):
        frame = BadPacket.parse(data)
        self._frame_received(frame)

    def write(self, data):
        self.transport.write(data)

    def write_frame(self, frame):
        self.write(frame.as_bytearray())
        print("sent frame: {}".format(frame))

    def has_frame(self):
        return not self.input_queue.empty()

    def get_frame(self, block=True, timeout=None):
        return self.input_queue.get(block, timeout)

class InvalidFrame(Exception):
    pass


class SerialPacket:
    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def as_bytearray(self):
        raise NotImplemented

class SimplePacket(SerialPacket):
    def __init__(self, frame_type):
        self.frame_type = frame_type

    def __str__(self):
        type_str = frame_type_str[self.frame_type]
        return "<SimplePacket: {}>".format(type_str)

    @classmethod
    def parse(cls, frame_bytes):
        try:
            if not frame_bytes[0] in frame_type_str:
                raise InvalidFrame('No valid frame type: {}'.format(frame_bytes[0]))

            frame_type = frame_bytes[0]
            return cls(frame_type)
        except IndexError as e:
            raise InvalidFrame('Frame too short') from e

    def as_bytearray(self):
        frame_bytes = bytearray([self.frame_type])
        return frame_bytes

class BadPacket(SerialPacket):
    def __init__(self, data):
        self.data = data

    def __str__(self):
        type_str = frame_type_str[self.frame_type]
        return "<BadPacket: {}>".format(self.data)

    @classmethod
    def parse(cls, data):
        return cls(data)

    def as_bytearray(self):
        frame_bytes = bytearray([self.data])
        return frame_bytes

class Frame(SerialPacket):
    def __init__(self, frame_type, function, data=None):
        self.frame_type = frame_type
        self.function = function
        self.data = data if data else []

    def __str__(self):
        type_str = "REQUEST" if self.frame_type == 0 else "RESPONSE"
        return "<Frame[{}:{}]: {}>".format(type_str, self.function, bytearray(self.data))

    @classmethod
    def parse(cls, frame_bytes):
        try:
            if frame_bytes[0] != SOF:
                raise InvalidFrame('No SOF at beginning')

            if frame_bytes[1] != len(frame_bytes)-2:
                raise InvalidFrame('Length mismatch')

            checksum = cls.calc_checksum(frame_bytes[1:])
            if checksum != 0:
                raise InvalidFrame('Checksum incorrect')

            frame_type = frame_bytes[2]
            function = frame_bytes[3]
            data = list(frame_bytes[4:-1])
            return cls(frame_type, function, data)
        except IndexError as e:
            raise InvalidFrame('Frame too short') from e

    @staticmethod
    def calc_checksum(frame_bytes):
        # Update checksum
        checksum = 0xFF
        for b in frame_bytes:
            checksum ^= b
        return checksum

    def as_bytearray(self):
        # The first 0 will be replaced by length, the last 0 with checksum
        frame_bytes = bytearray([SOF, 0, self.frame_type, self.function] + self.data + [0])
        # Update length (Don't count SOF and length byte)
        frame_bytes[1] = len(frame_bytes)-2
        # Update checksum (including length but excluding SOF)
        frame_bytes[-1] = self.calc_checksum(frame_bytes[1:])
        return frame_bytes

def locate_usb_controller():
    uzb_sticks = [port.device for port in serial.tools.list_ports.grep('VID:PID=0658:0200')]
    if not uzb_sticks:
        print("no UZB sticks found")
        return None
    elif len(uzb_sticks) > 1:
        print("multiple uzb sticks found: {}".format(uzb_sticks))
        return None
    else:
        return uzb_sticks[0]


class FakeProtocolHandler(socketserver.BaseRequestHandler):
    class FakeTransport:
        def __init__(self, request):
            self.request = request

        def write(self, data):
            self.request.sendall(data)

    def setup(self):
        transport = self.FakeTransport(self.request)
        self.server.protocol = FrameProtocol()
        self.server.protocol.connection_made(transport)

    def finish(self):
        self.server.protocol.connection_lost(None)

    def handle(self):
        while not self.server.stop_server:
            # self.request is the TCP socket connected to the client
            self.data = self.request.recv(1024)
            if self.data:
                self.server.protocol.data_received(self.data)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    stop_server = False
    protocol = None

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.daemon_threads = True

class FakeController:
    protocol = None

    HOST, PORT = "localhost", 10111

    def open(self):
        self.server = ThreadedTCPServer((self.HOST, self.PORT), FakeProtocolHandler)
        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        port = "socket://{}:{}".format(self.HOST, self.PORT)
        self.serialport = serial.serial_for_url(port, baudrate=115200, timeout=3)
        t = serial.threaded.ReaderThread(self.serialport, FrameProtocol)
        t.start()
        self.transport, self.protocol = t.connect()

    def close(self):
        self.transport.close()
        self.serialport.close()

        self.server.stop_server = True
        self.server.shutdown()

    def remote_protocol(self):
        return self.server.protocol


class RealController:
    protocol = None

    def open(self):
        port = locate_usb_controller()
        self.serialport = serial.serial_for_url(port, baudrate=115200, timeout=3)
        t = serial.threaded.ReaderThread(self.serialport, FrameProtocol)
        t.start()
        self.transport, self.protocol = t.connect()

    def close(self):
        self.transport.close()
        self.serialport.close()


def main():
    controller = FakeController()
    controller.open()

    import time
    time.sleep(1)

    protocol = controller.protocol
    remote = controller.remote_protocol()

    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
    protocol.write_frame(frame)

    remote_frame = remote.get_frame(block=True)
    print("GOT rem REQ: {}".format(remote_frame))
    if isinstance(remote_frame, BadPacket):
        remote.write_frame(SimplePacket(NAK))
    elif isinstance(remote_frame, Frame):
        remote.write_frame(SimplePacket(ACK))

    pro_frame = protocol.get_frame(block=True)
    print("GOT pro ACK: {}".format(pro_frame))
    if isinstance(pro_frame, BadPacket):
        protocol.write_frame(SimplePacket(NAK))
    elif isinstance(pro_frame, Frame):
        protocol.write_frame(SimplePacket(ACK))

    frame2 = Frame(RESPONSE, cmd.FUNC_ID_ZW_GET_VERSION)
    remote.write_frame(frame2)

    pro_frame = protocol.get_frame(block=True)
    print("GOT pro RES: {}".format(pro_frame))
    if isinstance(pro_frame, BadPacket):
        protocol.write_frame(SimplePacket(NAK))
    elif isinstance(pro_frame, Frame):
        protocol.write_frame(SimplePacket(ACK))

    remote_frame = remote.get_frame(block=True)
    print("GOT rem ACK: {}".format(remote_frame))
    if isinstance(remote_frame, BadPacket):
        remote.write_frame(SimplePacket(NAK))
    elif isinstance(remote_frame, Frame):
        remote.write_frame(SimplePacket(ACK))

    time.sleep(1)
    print("remote", remote.has_frame())
    print("protocol", protocol.has_frame())
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame(block=True)))
    print("protocol", protocol.has_frame())


    controller.close()
    exit(1)

    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_MEMORY_GET_ID)
    protocol.write_frame(frame)
    remote_frame = remote.get_frame(block=True)
    if isinstance(remote_frame, BadPacket):
        remote.write_frame(SimplePacket(NAK))
    elif isinstance(remote_frame, Frame):
        remote.write_frame(SimplePacket(ACK))

    print("GOT remote: {}".format(remote_frame))
    remote.write_frame(remote_frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES)
    protocol.write_frame(frame)
    remote_frame = remote.get_frame(block=True)
    print("GOT remote: {}".format(remote_frame))
    remote.write_frame(SimplePacket(ACK))
    frame2 = Frame(RESPONSE, cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES)
    remote.write_frame(frame2)
    print("GOT: {}".format(protocol.get_frame(block=True)))
    remote_frame = remote.get_frame(block=True)
    print("GOT remote: {}".format(remote_frame))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES)
    protocol.write_frame(frame)
    remote_frame = remote.get_frame(block=True)
    print("GOT remote: {}".format(remote_frame))
    remote.write_frame(SimplePacket(ACK))
    remote.write_frame(remote_frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_SUC_NODE_ID)
    protocol.write_frame(frame)
    remote_frame = remote.get_frame(block=True)
    print("GOT remote: {}".format(remote_frame))
    remote.write_frame(SimplePacket(ACK))
    remote.write_frame(remote_frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(3)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    controller.close()

if __name__ == '__main__':
    main()
