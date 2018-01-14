import ctypes
import socketserver
import struct
import threading
from queue import Queue

from zwip.constants import *

import serial
import serial.tools.list_ports
import serial.threaded

def hex_string(obj):
    return ''.join('\\x{:02x}'.format(x) for x in obj).rstrip() if obj else ''

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
            if not frame_byte in frame_type_str:
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
        return "<Frame[{}:{}({:#x})]: {}>".format(type_str, get_command_name(self.func), self.func, hex_string(bytearray(self.data)))

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
            data = bytes(frame_bytes[4:-1])
            return cls(frame_type, function, data)
        except IndexError as e:
            raise InvalidFrame('Frame too short')

    @staticmethod
    def calc_checksum(frame_bytes):
        # Update checksum
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
    class FakeTransport:
        def __init__(self, request):
            self.request = request

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

    def __init__(self, server_address, RequestHandlerClass, ProtocolType):
        super().__init__(server_address, RequestHandlerClass)
        self.daemon_threads = True
        self.protocol = ProtocolType()


class FakeSender:
    protocol = None

    HOST, PORT = "localhost", 10111

    def open(self, ProtocolType=FrameProtocol):
        port = self.PORT
        self.server = None
        while not self.server:
            try:
                self.server = ThreadedTCPServer((self.HOST, port), FakeProtocolHandler, ProtocolType)
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

    def open(self, port, ProtocolType=FrameProtocol):
        self.serialport = serial.serial_for_url(port, baudrate=115200, timeout=3)
        t = serial.threaded.ReaderThread(self.serialport, ProtocolType)
        t.start()
        self.transport, self.protocol = t.connect()

    def close(self):
        self.transport.close()
        self.serialport.close()


class ControllerInfo:
    LibraryTypes = [
        "Unknown",
        "Static Controller",
        "Portable Controller",
        "Enhanced Slave",
        "Slave",
        "Installer",
        "Routing Slave",
        "Bridge Controller",
        "Device Under Test"
    ]

    library_version = None
    library_type = None
    home_id = None
    node_id = None


class PacketBits(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("secondary", ctypes.c_ubyte, 1),
        ("on_other_network", ctypes.c_ubyte, 1),
        ("sis", ctypes.c_ubyte, 1),
        ("real_primary", ctypes.c_ubyte, 1),
        ("suc", ctypes.c_ubyte, 1),
        ("unknown1", ctypes.c_ubyte, 1),
        ("unknown2", ctypes.c_ubyte, 1),
        ("unknown3", ctypes.c_ubyte, 1),
    ]


class ControllerCapabilitiesBitfield(ctypes.Union):
    _anonymous_ = ("bits",)
    _fields_ = [("bits", PacketBits),
                ("binary_data", ctypes.c_ubyte)]

class Node:
    pass

class ZWavePacket(object):
    def __init__(self, node_id, command_class, command_num, data=None):
        self.node_id = node_id
        self.command_class = command_class
        self.command_num = command_num
        self.data = data if data else []


    def __str__(self):
        return "<Packet @{} {}({:#x})/{:#x} [{}]>".format(self.node_id, get_command_class_name(self.command_class), self.command_class, self.command_num, hex_string(self.data))

    def as_bytes(self):
        # Length includes command_class, command_num and data, but not node_id.
        length = 2 + len(self.data)
        packet_bytes = bytearray([self.node_id, length, self.command_class, self.command_num] + self.data)
        return bytes(packet_bytes)

class IncomingSerialPacket(object):
    def __init__(self, type, func):
        self.type = type
        self.func = func

    @classmethod
    def from_frame(cls, frame):
        if frame.frame_type == RESPONSE:
            if frame.func == cmd.FUNC_ID_ZW_GET_VERSION:
                return GetVersionReplyPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_ZW_MEMORY_GET_ID:
                return GetControllerIdReplyPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES:
                return GetControllerCapabilitiesReplyPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES:
                return GetSerialApiCapabilitiesReplyPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_ZW_GET_SUC_NODE_ID:
                return GetSucNodeIdReplyPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_SERIAL_API_GET_INIT_DATA:
                return GetInitDataReplyPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO:
                return GetNodeProtocolInfoReplyPacket.from_frame(frame)
            elif frame.func in [cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, cmd.FUNC_ID_ZW_SEND_DATA, cmd.FUNC_ID_ZW_REQUEST_NETWORK_UPDATE]:
                return TransactionStartedReplyPacket.from_frame(frame)
        else:
            if frame.func == cmd.FUNC_ID_ZW_SEND_DATA:
                return AsyncSendDataPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION:
                return AsyncSendNodeInformationPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_ZW_APPLICATION_UPDATE:
                return AsyncUpdateNodeInformationPacket.from_frame(frame)
            elif frame.func == cmd.FUNC_ID_APPLICATION_COMMAND_HANDLER:
                return AsyncUpdateReceivedDataPacket.from_frame(frame)

        print("WARNING: UNHANDLED RESPONSE: {}".format(frame))
        return None

class GetVersionReplyPacket(IncomingSerialPacket):
    LibraryTypes = [
        "Unknown",
        "Static Controller",
        "Portable Controller",
        "Enhanced Slave",
        "Slave",
        "Installer",
        "Routing Slave",
        "Bridge Controller",
        "Device Under Test"
    ]

    def __init__(self, library_version, library_type):
        self.library_version = library_version
        self.library_type = library_type
        print("Created:", self)

    def __repr__(self):
        return "<GetVersionReplyPacket(library_version='{}', library_type={})>".format(self.library_version, self.library_type)

    @classmethod
    def from_frame(cls, frame):
        library_version = frame.data[0:12].decode('ascii').rstrip(' \0')
        library_type = frame.data[12]

        return cls(library_version, library_type)

class GetControllerIdReplyPacket(IncomingSerialPacket):
    def __init__(self, home_id, node_id):
        self.home_id = home_id
        self.node_id = node_id
        print("Created:", self)

    def __repr__(self):
        return "<GetControllerIdReplyPacket(home_id={}, node_id={})>".format(self.home_id, self.node_id)

    @classmethod
    def from_frame(cls, frame):
        home_id = int.from_bytes(frame.data[0:4], 'big')
        node_id = frame.data[4]

        return cls(home_id, node_id)


class PacketBits2(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("secondary", ctypes.c_ubyte, 1),
        ("on_other_network", ctypes.c_ubyte, 1),
        ("sis", ctypes.c_ubyte, 1),
        ("real_primary", ctypes.c_ubyte, 1),
        ("suc", ctypes.c_ubyte, 1),
        ("unknown1", ctypes.c_ubyte, 1),
        ("unknown2", ctypes.c_ubyte, 1),
        ("unknown3", ctypes.c_ubyte, 1),
    ]

class ControllerCapabilitiesBitfield2(ctypes.Union):
    _anonymous_ = ("bits",)
    _fields_ = [("bits", PacketBits2),
                ("binary_data", ctypes.c_ubyte)]

class GetControllerCapabilitiesReplyPacket(IncomingSerialPacket):
    def __init__(self, secondary, on_other_network, sis, real_primary, suc):
        self.secondary = secondary
        self.on_other_network = on_other_network
        self.sis = sis
        self.real_primary = real_primary
        self.suc = suc
        print("Created:", self)

    def __repr__(self):
        return "<GetControllerCapabilitiesReplyPacket(secondary={}, on_other_network={}, sis={}, real_primary={}, suc={})>".format(
            self.secondary, self.on_other_network, self.sis, self.real_primary, self.suc)

    @classmethod
    def from_frame(cls, frame):
        packet = ControllerCapabilitiesBitfield2()
        packet.binary_data = frame.data[0]

        return cls(packet.bits.secondary, packet.bits.on_other_network, packet.bits.sis, packet.bits.real_primary,
              packet.bits.suc)

class GetSerialApiCapabilitiesReplyPacket(IncomingSerialPacket):
    def __init__(self, serial_version_major, serial_version_minor, manufacturer_id, product_type, product_id, serial_api_funcs_bitmask):
        self.serial_version_major = serial_version_major
        self.serial_version_minor = serial_version_minor
        self.manufacturer_id = manufacturer_id
        self.product_type = product_type
        self.product_id = product_id
        self.serial_api_funcs_bitmask = serial_api_funcs_bitmask
        print("Created:", self)
        #self.print_it()

    def __repr__(self):
        return "<GetSerialApiCapabilitiesReplyPacket(serial_version_major={}, serial_version_minor={}, manufacturer_id={:#06x}, product_type={:#06x}, product_id={:#06x}, serial_api_funcs_bitmask={:#x})>".format(
            self.serial_version_major, self.serial_version_minor, self.manufacturer_id, self.product_type, self.product_id, self.serial_api_funcs_bitmask)

    def print_it(self):
        serial_version = "{}.{}".format(self.serial_version_major, self.serial_version_minor)
        print("Serial API Version {}".format(serial_version))

        for cmd_name in commands:
            cmd_num = commands.get(cmd_name)
            cmd_offset = cmd_num - 1
            is_cmd = self.serial_api_funcs_bitmask & (1 << cmd_offset) != 0
            if is_cmd:
                print("has {} ({})".format(cmd_name, cmd_num))
            else:
                print("NOT {} ({})".format(cmd_name, cmd_num))

        all_cmd_nums = commands.values()
        for i in range(0, 255):
            is_cmd = self.serial_api_funcs_bitmask & (1 << i) != 0
            if (i not in all_cmd_nums) and is_cmd:
                print("UNKNOWN cmd value {:#x}".format(i))

    @classmethod
    def from_frame(cls, frame):
        serial_version_major = frame.data[0]
        serial_version_minor = frame.data[1]

        manufacturer_id = int.from_bytes(frame.data[2:4], 'big')
        product_type = int.from_bytes(frame.data[4:6], 'big')
        product_id = int.from_bytes(frame.data[6:8], 'big')

        serial_api_funcs_bitmask = int.from_bytes(frame.data[8:40], 'little')

        return cls(serial_version_major, serial_version_minor, manufacturer_id, product_type, product_id, serial_api_funcs_bitmask)

class GetSucNodeIdReplyPacket(IncomingSerialPacket):
    def __init__(self, suc_node_id):
        self.suc_node_id = suc_node_id
        print("Created:", self)

    def __repr__(self):
        return "<GetSucNodeIdReplyPacket(suc_node_id={})>".format(self.suc_node_id)

    @classmethod
    def from_frame(cls, frame):
        suc_node_id = frame.data[0]

        return cls(suc_node_id)

class GetInitDataReplyPacket(IncomingSerialPacket):
    def __init__(self, init_version, init_caps, nodes_bitmask):
        self.init_version = init_version
        self.init_caps = init_caps
        self.nodes_bitmask = nodes_bitmask
        print("Created:", self)
        self.print_it()

    def __repr__(self):
        return "<GetInitDataReplyPacket(init_version={}, init_caps={:#x}, nodes_bitmask={:#x})>".format(
            self.init_version, self.init_caps, self.nodes_bitmask)

    def print_it(self):
        print("GetInitDataReplyPacket nodes: {}".format(self.nodes_bitmask))
        for i in range(0, 232):
            is_node = self.nodes_bitmask & (1 << i) != 0
            node_num = i + 1
            if is_node:
                print("Has node at {}".format(node_num))

    @classmethod
    def from_frame(cls, frame):
        init_version = frame.data[0]
        init_caps = frame.data[1]

        bitfield_len = frame.data[2]
        assert bitfield_len == 29  # 232 nodes / 8
        nodes_bitmask = int.from_bytes(frame.data[3:32], 'little')
        unknown_init_ver2 = frame.data[32]
        unknown_init_cap2 = frame.data[33]

        print("GetInitDataReplyPacket unknown, perhahps init_ver {}, init_cap {}".format(unknown_init_ver2,
                                                                  unknown_init_cap2))

        return cls(init_version, init_caps, nodes_bitmask)

class GetNodeProtocolInfoReplyPacket(IncomingSerialPacket):
    def __init__(self, basic_class, generic_class, specific_class, version, is_listening, is_routing, is_secure, max_baud):
        self.basic_class = basic_class
        self.generic_class = generic_class
        self.specific_class = specific_class
        self.version = version
        self.is_listening = is_listening
        self.is_routing = is_routing
        self.is_secure = is_secure
        self.max_baud = max_baud
        print("Created:", self)

    def __repr__(self):
        return "<GetNodeProtocolInfoReplyPacket(basic_class={:#04x}, generic_class={:#04x}, specific_class={:#04x}, version={}, is_listening={}, is_routing={}, is_secure={}, max_baud={})>".format(
            self.basic_class, self.generic_class, self.specific_class, self.version, self.is_listening, self.is_routing, self.is_secure, self.max_baud)

    @classmethod
    def from_frame(cls, frame):
        caps = frame.data[0]
        unknown = frame.data[2]
        security = frame.data[1]
        basic_class = frame.data[3]
        generic_class = frame.data[4]
        specific_class = frame.data[5]

        # NOTE: generic class == 0 ==> non-existant node.

        is_listening = caps & 0x80 != 0
        is_routing = caps & 0x40 != 0

        # 00111000 is baud rate mask (0x38)
        if caps & 0x38 == 0x10:
            max_baud = 40000
        else:
            max_baud = 9600

        # 00000111 is version mask
        version = (caps & 0x07) + 1

        # SecurityFlag_Security = 0x01
        # More data is available here when implementing security.
        is_secure = security & 0x01 != 0

        print("GetNodeProtocolInfoReplyPacket unknown {}, security {}".format(unknown, security))

        return cls(basic_class, generic_class, specific_class, version, is_listening, is_routing, is_secure, max_baud)

class TransactionStartedReplyPacket(IncomingSerialPacket):
    def __init__(self, func, request_successful):
        self.func = func
        self.request_successful = request_successful
        print("Created:", self)

    def __repr__(self):
        return "<TransactionStartedReplyPacket(func={:#0x}, request_successful={})>".format(self.func, self.request_successful)

    @classmethod
    def from_frame(cls, frame):
        func = frame.func
        request_successful = frame.data[0] != 0
        return cls(func, request_successful)

class AsyncSendDataPacket(IncomingSerialPacket):
    def __init__(self, callback_id, err_code):
        self.callback_id = callback_id
        self.err_code = err_code
        print("Created:", self)

    def __repr__(self):
        return "<AsyncSendDataPacket(callback_id={}, err_code={})>".format(self.callback_id, self.err_code)

    @classmethod
    def from_frame(cls, frame):
        callback_id = frame.data[0]
        err_code = frame.data[1]
        unknown1 = frame.data[2]
        unknown2 = frame.data[3]
        # error codes:
        # define TRANSMIT_COMPLETE_OK	  						0x00
        # define TRANSMIT_COMPLETE_NO_ACK	  					0x01
        # define TRANSMIT_COMPLETE_FAIL							0x02
        # define TRANSMIT_COMPLETE_NOT_IDLE						0x03
        # define TRANSMIT_COMPLETE_NOROUTE 						0x04

        print("AsyncSendDataPacket unknown1 {:#x}, unknown2 {:#x}".format(unknown1, unknown2))
        return cls(callback_id, err_code)

class AsyncSendNodeInformationPacket(IncomingSerialPacket):
    def __init__(self, callback_id, err_code):
        self.callback_id = callback_id
        self.err_code = err_code
        print("Created:", self)

    def __repr__(self):
        return "<AsyncSendNodeInformationPacket(callback_id={}, err_code={})>".format(self.callback_id, self.err_code)

    @classmethod
    def from_frame(cls, frame):
        callback_id = frame.data[0]
        err_code = frame.data[1]
        # error codes:
        # define TRANSMIT_COMPLETE_OK	  						0x00
        # define TRANSMIT_COMPLETE_NO_ACK	  					0x01
        # define TRANSMIT_COMPLETE_FAIL							0x02
        # define TRANSMIT_COMPLETE_NOT_IDLE						0x03
        # define TRANSMIT_COMPLETE_NOROUTE 						0x04

        return cls(callback_id, err_code)

class AsyncUpdateNodeInformationPacket(IncomingSerialPacket):
    def __init__(self, status, node_id, basic_class, generic_class, specific_class, cmd_classes):
        self.status = status
        self.node_id = node_id
        self.basic_class = basic_class
        self.generic_class = generic_class
        self.specific_class = specific_class
        self.cmd_classes = cmd_classes
        print("Created:", self)
        self.print_it()

    def __repr__(self):
        return "<AsyncUpdateNodeInformationPacket(status={:#04x}, node_id={}, basic_class={:#04x}, generic_class={:#04x}, specific_class={:#04x}, cmd_classes={})>".format(
            self.status, self.node_id, self.basic_class, self.generic_class, self.specific_class, hex_string(self.cmd_classes))

    def print_it(self):
        state_name = "UNKNOWN_STATE"
        for name, status in node_update_states.items():
            if status == self.status:
                state_name = name

        print("AsyncUpdateNodeInformationPacket status: {}({:#0x}, node {})".format(name, self.status, self.node_id))

    @classmethod
    def from_frame(cls, frame):
        status = frame.data[0]
        # NOTE: if status is failed, then we can't trust node id... or..?
        node_id = frame.data[1]
        msg_len = frame.data[2]

        if msg_len != len(frame.data) - 3:
            print("ERROR: incorrect length: {}, should be {}".format(msg_len, len(frame.data) - 3))

        if msg_len > 0:
            basic_class = frame.data[3]
            generic_class = frame.data[4]
            specific_class = frame.data[5]
            cmd_classes = frame.data[6:]
        else:
            basic_class = 0
            generic_class = 0
            specific_class = 0
            cmd_classes = None

        return cls(status, node_id, basic_class, generic_class, specific_class, cmd_classes)

class AsyncUpdateReceivedDataPacket(IncomingSerialPacket):
    def __init__(self, status, node_id, packet):
        self.status = status
        self.node_id = node_id
        self.packet = packet
        print("Created:", self)

    def __repr__(self):
        return "<AsyncUpdateReceivedDataPacket(status={:#04x}, node_id={}, packet={})>".format(
            self.status, self.node_id, self.packet)

    @classmethod
    def from_frame(cls, frame):
        status = frame.data[0]
        node_id = frame.data[1]
        msg_len = frame.data[2]
        if msg_len != len(frame.data) - 3:
            print("ERROR: incorrect length: {}, should be {}".format(msg_len, len(frame.data) - 3))

        if msg_len > 0:
            cmd_class = frame.data[3]
            cmd_num = frame.data[4]
            cmd_data = frame.data[5:]
            packet = ZWavePacket(node_id, cmd_class, cmd_num, cmd_data)
        else:
            packet= None

        return cls(status, node_id, packet)

def call_command(protocol, remote, command, expected_payload, command_data=None, extra_frame=None, has_response=True):
    frame = Frame(REQUEST, command, command_data)
    print("SEND:", frame)
    protocol.write_frame(frame)

    response_frame = Frame(RESPONSE, command, expected_payload)
    if remote:
        frame2 = remote.get_frame(block=True)
        assert frame2 == frame
        remote.write_frame(response_frame)

    if has_response:
        frame = protocol.get_frame(block=True)
        print("RECV:", frame)
        if command != cmd.FUNC_ID_ZW_GET_RANDOM and expected_payload != None:
            #assert frame == response_frame
            pass
        inc_packet = IncomingSerialPacket.from_frame(frame)
        print("RECV-parsed:", inc_packet)

    if extra_frame:
        frame = protocol.get_frame(block=True)
        print("RECV<extra>:", frame)
        print("exp RECV<extra>:", extra_frame)
        if frame != extra_frame:
            print("WARNING: diff!!!")
        #assert frame == extra_frame
        inc_packet = IncomingSerialPacket.from_frame(frame)
        print("RECV<extra>-parsed:", inc_packet)


def oldstuff(protocol, remote):
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_VERSION, bytearray(b'Z-Wave 4.05\x00\x01'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_MEMORY_GET_ID, bytearray(b'\xfb\xe3\x9b\xfd\x01'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES, bytearray(b'('))
    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES, bytearray(
        b'\x05\x06\x01\x15\x04\x00\x00\x01\xfe\x83\xff\x88\xcf\x1f\x00\x00\xfb\x9f}\xa0g\x00\x80\x80\x00\x80\x86\x00\x00\x00\xe8s\x00\x00\x0e\x00\x00@\x1a\x00'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_SUC_NODE_ID, bytearray(b'\x00'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_RANDOM, bytearray(b'\x01\x04\xca\xfe\xba\xbe'), bytes([4]))
    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_GET_INIT_DATA, bytearray(
        b'\x05\x00\x1d\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00'))

    # arg1: node_id
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x00\x00\x00\x03\x00\x00'),
                 bytes([0]))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x93\x16\x01\x02\x02\x01'),
                 bytes([1]))

DEFAULT_TRANSMIT_OPTIONS = 0x25

from enum import Enum

class ExpectedReply(Enum):
    none = 1
    response = 2
    type_request_callback = 3 # same type or other type
    id_request_callback = 4

def create_send_payload(zwpacket, callback_id, transmit_options=DEFAULT_TRANSMIT_OPTIONS):
    payload_bytes = zwpacket.as_bytes() + bytes([transmit_options, callback_id])
    return payload_bytes

def main():
    sender = FakeSender()
    sender.open()
    remote = sender.remote_protocol()
    remote = None

    port = sender.port
    port = locate_usb_controller()

    controller = SerialController()
    controller.open(port)

    protocol = controller.protocol

    # openzwave says requires a callback-id at the end, but i'm not sure..?
    call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NETWORK_UPDATE, bytearray(b'\x00'))

    oldstuff(protocol, remote)

    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_GET_INIT_DATA, bytearray(
        b'\x05\x00\x1d\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00'))

    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x93\x16\x01\x02\x02\x01'),
                 bytes([2]))

    # arg1: dest node
    # arg2: tx options 0x11
    # arg3: return handling, 0 = no reply, 0x03 = has reply (actually, callback id)
    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x03\x01'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x01'), bytearray(b'\x02\x25\x07'), extra_frame)

    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_VERSION, bytearray(b'Z-Wave 4.05\x00\x01'))

    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_APPLICATION_UPDATE, bytearray(b'\x81\x00\x00'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, bytearray(b'\x01'), bytes([2]), extra_frame)

    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_VERSION, bytearray(b'Z-Wave 4.05\x00\x01'))

    # noop/noop
    # arg1: node
    # arg2: 2 = len of package (cmdclass + command)
    # ---
    # arg3: cmd class id, 0x00 == NOOP.
    # arg4: 0 == NOOP
    # ---
    # arg5: transmit options, default  TRANSMIT_OPTION_ACK | TRANSMIT_OPTION_NO_ROUTE = 0x11
    # arg6: callback-id (start with 0x21)
    #call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), bytearray(b'\x01\x02\x00\x00\x11\x21'), Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'!\x01\x004')))


    # 01 = SOF (Start Of Frame)
    # 08 = 8 bytes length for this frame
    # 00 = request
    # 03 = FUNC_ID_SERIAL_API_APPL_NODE_INFORMATION
    # 01 = listening /** not moving */
    # 02 = node generic type, GENERIC_TYPE_STATIC_CONTROLLER
    # 01 = node specific type, SPECIFIC_TYPE_PORTABLE_REMOTE_CONTROLLER
    # 01 = param length
    # 21 = COMMAND_CLASS_CONTROLLER_REPLICATION
    # D6 = Checksum

    #call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_APPL_NODE_INFORMATION,  bytearray(b'\x01'), bytearray(b'\x01\x02\x01\x01\x21'), has_response=False)

    #call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x93\x16\x01\x02\x02\x01'),
    #             bytes([1]))


    # openzwave says the node in arg1 is "controller node"?

    # arg1: dest node
    # arg2: tx options 0x11
    # arg3: return handling, 0 = no reply, 0x03 = has reply (actually, callback id)
#    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x03\x01'))
#    call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x01'), bytearray(b'\x01\x11\x07'), extra_frame)


    # manufacturer_specific get
    # arg1: node
    # arg2: 2 = len of package (cmdclass + command)
    # ---
    # arg3: cmd class id, 0x72 = man specifc.
    # arg4: cmd get == 0x04
    # ---
    # arg5: transmit options, default  TRANSMIT_OPTION_ACK | TRANSMIT_OPTION_NO_ROUTE = 0x11
    # arg6: callback-id (start with 0x21)
    #extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x23\x01\x00\x56'))
    #call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), bytearray(b'\x01\x02\x72\x04\x11\x23'), extra_frame)


    # 01 = listening
    # 02 = node generic type, GENERIC_TYPE_STATIC_CONTROLLER
    # 01 = node specific type, SPECIFIC_TYPE_PC_CONTROLLER
    # 01 = param length
    # 21 = COMMAND_CLASS_CONTROLLER_REPLICATION

#    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES, bytearray(
#        b'\x05\x06\x01\x15\x04\x00\x00\x01\xfe\x83\xff\x88\xcf\x1f\x00\x00\xfb\x9f}\xa0g\x00\x80\x80\x00\x80\x86\x00\x00\x00\xe8s\x00\x00\x0e\x00\x00@\x1a\x00'))

    # openzwave says the node in arg1 is "controller node"?
#    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_APPL_NODE_INFORMATION,  bytearray(b'\x01'), bytearray(b'\x01\x02\x01\x00'))

#    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_VERSION, bytearray(b'Z-Wave 4.05\x00\x01'))

    # openzwave says the node in arg1 is "controller node"?
    # BROKEN, see above. call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x01'))

    #

    # define TRANSMIT_OPTION_ACK		 						0x01
    # define TRANSMIT_OPTION_LOW_POWER		   				0x02
    # define TRANSMIT_OPTION_AUTO_ROUTE  					0x04
    # define TRANSMIT_OPTION_NO_ROUTE 						0x10
    # define TRANSMIT_OPTION_EXPLORE							0x20


    # basic/get
    # cmdclass COMMAND_CLASS_BASIC = 0x20
    # BasicCmd_Get	= 0x02, BasicCmd_Report	= 0x03

#    call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), bytearray(b'\x01\x02\x20\x02\x11\x22'), Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'"\x01\x004')))

    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_APPLICATION_UPDATE, bytearray(b'\x81\x00\x00'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, bytearray(b'\x01'), bytes([1]), extra_frame)

    # extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_APPLICATION_UPDATE, bytearray(b'\x81\x00\x00'))
    # call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, bytearray(b'\x01'), bytes([0x01]), extra_frame)


    # manufacturer_specific get
    # arg1: node
    # arg2: 2 = len of package (cmdclass + command)
    # ---
    # arg3: cmd class id, 0x72 = man specifc.
    # arg4: cmd get == 0x04
    # ---
    # arg5: transmit options, default  TRANSMIT_OPTION_ACK | TRANSMIT_OPTION_NO_ROUTE = 0x11
    # arg6: callback-id (start with 0x21)
    #extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'#\x01\x00"'))
    #call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), bytearray(b'\x01\x02\x72\x04\x11\x23'), extra_frame)

    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x25\x01\x00\x56'))
    packet = ZWavePacket(2, 0x72, 0x04)
    send_payload = create_send_payload(packet, 0x23)
    call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), send_payload,
                 extra_frame)
    import time
    time.sleep(10)
    send_payload = create_send_payload(packet, 0x24)
    call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), send_payload,
                 extra_frame)
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_VERSION, bytearray(b'Z-Wave 4.05\x00\x01'))

    frame = protocol.get_frame(block=True)
    while frame:
        print("final RECV:", frame)
        inc_packet = IncomingSerialPacket.from_frame(frame)
        print("final RECV-parsed:", inc_packet)
        time.sleep(1)

        send_payload = create_send_payload(packet, 0x25)
        call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), send_payload, extra_frame)
        frame = protocol.get_frame(block=False)

    controller.close()
    sender.close()

if __name__ == '__main__':
    main()
