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

    def handle_simple_packet(self, packet):
        """Process packets - to be overridden by subclassing"""
        # raise NotImplementedError('please implement functionality in handle_packet')
        frame = SimplePacket.parse(packet)
        self.input_queue.put(frame)

    def handle_packet(self, packet):
        """Process packets - to be overridden by subclassing"""
        # raise NotImplementedError('please implement functionality in handle_packet')
        frame = Frame.parse(packet)
        self.input_queue.put(frame)
        self.write(bytearray([ACK]))

    def handle_bad_data(self, data):
        print("got bad data: {}".format(data))
        self.write(bytearray([NAK]))

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
        return "<SimpleFrame: {}>".format(type_str)

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


class ControllerInterface:
    def __init__(self):
        pass

    def read(self, length=1):
        pass

    def write(self, data):
        pass

    def open(self):
        pass

    def close(self):
        pass


class FakeController(ControllerInterface):
    def read(self, length=1):
        print(self._buffer)
        # return self._buffer.pop(0)
        value = self._buffer[0:length]
        del self._buffer[0:length]
        return value

    def _add_data(self, data):
        ba = bytearray(data)
        self._buffer.extend(ba)

    def __init__(self):
        super().__init__()
        self._buffer = bytearray()
        # ba2 = bytearray('\01\04hej\00', 'ascii')
        ba3 = struct.pack('B4p', SOF, bytes('hej\00', 'ascii'))
        # self._add_data([SOF, 4, 'h', 'e', 'j', 0])
        self._add_data(ba3)


class UsbController(ControllerInterface):
    def __init__(self, port):
        super().__init__()
        self._port = port
        self._serial = serial.serial_for_url(port, baudrate=115200, timeout=3)
        print("opened: {}".format(self._serial))

    def close(self):
        self._serial.close()

    def read(self, length=1):
        data = self._serial.read(length)
        print("read data {}".format(data))
        return data

    def write(self, data):
        self._serial.write(data)


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


class Controller:
    def __init__(self, interface):
        self._interface = interface

    def next_msg(self):
        msg_type = self._interface.read(1)
        if msg_type[0] == SOF:
            length = self._interface.read(1)
            content = self._interface.read(length[0])
            return content
        else:
            return None



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
                # just send back the same data, but upper-cased
                self.request.sendall(self.data)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    stop_server = False
    protocol = None

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.daemon_threads = True

class FakeController:
    protocol = None

    HOST, PORT = "localhost", 10112

    def open(self):
        self.server = ThreadedTCPServer((self.HOST, self.PORT), FakeProtocolHandler)
        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        port = "socket://localhost:10112"
        self.serialport = serial.serial_for_url(port, baudrate=115200, timeout=3)
        t = serial.threaded.ReaderThread(self.serialport, FrameProtocol)
        t.start()
        self.transport, self.protocol = t.connect()

    def close(self):
        self.transport.close()
        self.serialport.close()

        self.server.stop_server = True
        self.server.shutdown()


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

    protocol = controller.protocol

    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_VERSION)
    protocol.write_frame(frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_MEMORY_GET_ID)
    protocol.write_frame(frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES)
    protocol.write_frame(frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES)
    protocol.write_frame(frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(1)
    frame = Frame(REQUEST, cmd.FUNC_ID_ZW_GET_SUC_NODE_ID)
    protocol.write_frame(frame)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    time.sleep(3)
    while protocol.has_frame():
        print("GOT: {}".format(protocol.get_frame()))

    controller.close()

if __name__ == '__main__':
    main()
