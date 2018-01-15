from queue import Queue
import socketserver
import threading

from zwip.constants import *
from zwip import hex_string

import serial
import serial.tools.list_ports
import serial.threaded


class RawFrameProtocol(serial.threaded.Protocol):
    class State:
        Open, WantLength, WantData = range(3)

    def __init__(self):
        self.packet = bytearray()
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
        self.packet = None
        self.state = self.State.Open
        self.wanted_length = 0
        super().connection_lost(exc)

    def data_received(self, data):
        for byte in data:
            # print("got byte: ", byte)
            if self.state == self.State.Open:
                if byte == ACK:
                    self.handle_simple_packet(ACK)
                elif byte == NAK:
                    self.handle_simple_packet(NAK)
                elif byte == CAN:
                    self.handle_simple_packet(CAN)
                elif byte == SOF:
                    self.packet.append(byte)
                    self.state = self.State.WantLength
                    # FIXME: set timeout for this operation?
                else:
                    self.handle_bad_data([byte])
            elif self.state == self.State.WantLength:
                self.packet.append(byte)
                self.wanted_length = byte
                self.state = self.State.WantData
                # FIXME: timeout?
            elif self.state == self.State.WantData:
                self.packet.append(byte)
                if len(self.packet) == self.wanted_length+2:
                    self.handle_packet(self.packet)

                    self.state = self.State.Open
                    self.wanted_length = 0
                    self.packet = bytearray()

    def _frame_received(self, frame):
        self.input_queue.put(frame)

    def handle_simple_packet(self, byte):
        frame = SimplePacket.parse(byte)
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
        self.write(frame.as_bytes())

    def has_frame(self):
        return not self.input_queue.empty()

    def get_frame(self, block=True, timeout=None):
        return self.input_queue.get(block, timeout)


class FrameProtocol(RawFrameProtocol):
    def _frame_received(self, frame):
        if isinstance(frame, BadPacket):
            self.write_frame(SimplePacket(NAK))
        elif isinstance(frame, Frame):
            print("__recv__frame:{}".format(frame))
            self.write_frame(SimplePacket(ACK))
            self.input_queue.put(frame)


class InvalidFrame(Exception):
    pass


class SerialPacket:
    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def as_bytes(self):
        raise NotImplemented


class SimplePacket(SerialPacket):
    def __init__(self, frame_type):
        self.frame_type = frame_type

    def __str__(self):
        type_str = frame_type_str[self.frame_type]
        return "<SimplePacket: {}>".format(type_str)

    @classmethod
    def parse(cls, frame_byte):
        try:
            if frame_byte not in frame_type_str:
                raise InvalidFrame('No valid frame type: {}'.format(frame_byte))

            frame_type = frame_byte
            return cls(frame_type)
        except IndexError:
            raise InvalidFrame('Frame too short')

    def as_bytes(self):
        frame_bytes = bytes([self.frame_type])
        return frame_bytes


class BadPacket(SerialPacket):
    def __init__(self, data: bytes):
        self.data = data

    def __str__(self):
        return "<BadPacket: {}>".format(self.data)

    @classmethod
    def parse(cls, data):
        return cls(bytes(data))

    def as_bytes(self):
        return self.data


class Frame(SerialPacket):
    def __init__(self, frame_type, func, data=None):
        self.frame_type = frame_type
        self.func = func
        self.data = data if data else bytes()

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __str__(self):
        type_str = "REQUEST" if self.frame_type == 0 else "RESPONSE"
        return "<Frame[{}:{}({:#x})]: {}>".format(type_str, get_command_name(self.func), self.func,
                                                  hex_string(bytearray(self.data)))

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
            func = frame_bytes[3]
            data = bytes(frame_bytes[4:-1])
            return cls(frame_type, func, data)
        except IndexError:
            raise InvalidFrame('Frame too short')

    @staticmethod
    def calc_checksum(frame_bytes):
        # Update checksum (LRC using XOR)
        checksum = 0xFF
        for b in frame_bytes:
            checksum ^= b
        return checksum

    def as_bytes(self):
        # The first 0 will be replaced by length, the last 0 with checksum
        frame_bytes = bytearray([SOF, 0, self.frame_type, self.func] + list(self.data) + [0])
        # Update length (Don't count SOF and length byte)
        frame_bytes[1] = len(frame_bytes)-2
        # Update checksum (including length but excluding SOF)
        frame_bytes[-1] = self.calc_checksum(frame_bytes[1:])
        return bytes(frame_bytes)


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
    data = None

    class FakeTransport:
        def __init__(self, request):
            self.request = request
            self.data = None

        def write(self, data):
            self.request.sendall(data)

    def setup(self):
        transport = self.FakeTransport(self.request)
        self.server.protocol.connection_made(transport)

    def finish(self):
        self.server.protocol.connection_lost(None)

    def handle(self):
        while not self.server.stop_server:
            # self.request is the TCP socket connected to the client
            self.data = self.request.recv(1024)
            if self.data:
                self.server.protocol.data_received(self.data)


class ThreadedTCPServer(socketserver.TCPServer, socketserver.ThreadingMixIn):
    stop_server = False
    protocol = None

    def __init__(self, server_address, request_handler_class, protocol_type):
        super().__init__(server_address, request_handler_class)
        self.daemon_threads = True
        self.protocol = protocol_type()


class FakeSender:
    protocol = None
    server = None
    port = None

    HOST, PORT = "localhost", 10111

    def open(self, protocol_type=FrameProtocol):
        port = self.PORT
        self.server = None
        while not self.server:
            try:
                self.server = ThreadedTCPServer((self.HOST, port), FakeProtocolHandler, protocol_type)
            except OSError as e:
                if port < self.PORT + 10:
                    # Retry some times with next higher port
                    port = port + 1
                else:
                    raise e

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        self.port = "socket://{}:{}".format(self.HOST, port)

    def close(self):
        self.server.stop_server = True
        self.server.shutdown()

    def remote_protocol(self):
        return self.server.protocol


class SerialController:
    protocol = None
    transport = None
    serial_port = None

    def open(self, port, protocol_type=FrameProtocol):
        self.serial_port = serial.serial_for_url(port, baudrate=115200, timeout=3)
        t = serial.threaded.ReaderThread(self.serial_port, protocol_type)
        t.start()
        self.transport, self.protocol = t.connect()

    def close(self):
        self.transport.close()
        self.serial_port.close()
