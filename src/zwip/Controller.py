import ctypes
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

node_update_states = {
    'UPDATE_STATE_SUC_ID': 0x10,
    'UPDATE_STATE_DELETE_DONE': 0x20,
    'UPDATE_STATE_NEW_ID_ASSIGNED': 0x40,
    'UPDATE_STATE_ROUTING_PENDING': 0x80,
    'UPDATE_STATE_NODE_INFO_REQ_FAILED': 0x81,
    'UPDATE_STATE_NODE_INFO_REQ_DONE': 0x82,
    'UPDATE_STATE_NODE_INFO_RECEIVED': 0x84
}


commands = {
    'FUNC_ID_SERIAL_API_GET_INIT_DATA': 0x02,
    'FUNC_ID_SERIAL_API_APPL_NODE_INFORMATION': 0x03,
    'FUNC_ID_APPLICATION_COMMAND_HANDLER': 0x04,
    'FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES': 0x05,
    'FUNC_ID_SERIAL_API_SET_TIMEOUTS ': 0x06,
    'FUNC_ID_SERIAL_API_GET_CAPABILITIES': 0x07,
    'FUNC_ID_SERIAL_API_SOFT_RESET': 0x08,
    'FUNC_ID_ZW_SEND_NODE_INFORMATION': 0x12,
    'FUNC_ID_ZW_SEND_DATA': 0x13,
    'FUNC_ID_ZW_GET_VERSION': 0x15,
    'FUNC_ID_ZW_R_F_POWER_LEVEL_SET': 0x17,
    'FUNC_ID_ZW_GET_RANDOM': 0x1c,
    'FUNC_ID_ZW_MEMORY_GET_ID': 0x20,
    'FUNC_ID_MEMORY_GET_BYTE': 0x21,
    'FUNC_ID_ZW_READ_MEMORY': 0x23,
    'FUNC_ID_ZW_SET_LEARN_NODE_STATE': 0x40,
    'FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO': 0x41,
    'FUNC_ID_ZW_SET_DEFAULT': 0x42,
    'FUNC_ID_ZW_NEW_CONTROLLER': 0x43,
    'FUNC_ID_ZW_REPLICATION_COMMAND_COMPLETE': 0x44,
    'FUNC_ID_ZW_REPLICATION_SEND_DATA': 0x45,
    'FUNC_ID_ZW_ASSIGN_RETURN_ROUTE': 0x46,
    'FUNC_ID_ZW_DELETE_RETURN_ROUTE': 0x47,
    'FUNC_ID_ZW_REQUEST_NODE_NEIGHBOR_UPDATE': 0x48,
    'FUNC_ID_ZW_APPLICATION_UPDATE': 0x49,
    'FUNC_ID_ZW_ADD_NODE_TO_NETWORK': 0x4a,
    'FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK': 0x4b,
    'FUNC_ID_ZW_CREATE_NEW_PRIMARY': 0x4c,
    'FUNC_ID_ZW_CONTROLLER_CHANGE': 0x4d,
    'FUNC_ID_ZW_SET_LEARN_MODE': 0x50,
    'FUNC_ID_ZW_ASSIGN_SUC_RETURN_ROUTE': 0x51,
    'FUNC_ID_ZW_ENABLE_SUC': 0x52,
    'FUNC_ID_ZW_REQUEST_NETWORK_UPDATE': 0x53,
    'FUNC_ID_ZW_SET_SUC_NODE_ID': 0x54,
    'FUNC_ID_ZW_DELETE_SUC_RETURN_ROUTE': 0x55,
    'FUNC_ID_ZW_GET_SUC_NODE_ID': 0x56,
    'FUNC_ID_ZW_REQUEST_NODE_NEIGHBOR_UPDATE_OPTIONS': 0x5a,
    'FUNC_ID_ZW_EXPLORE_REQUEST_INCLUSION': 0x5e,
    'FUNC_ID_ZW_REQUEST_NODE_INFO': 0x60,
    'FUNC_ID_ZW_REMOVE_FAILED_NODE_ID': 0x61,
    'FUNC_ID_ZW_IS_FAILED_NODE_ID': 0x62,
    'FUNC_ID_ZW_REPLACE_FAILED_NODE': 0x63,
    'FUNC_ID_ZW_GET_ROUTING_INFO': 0x80,
    'FUNC_ID_SERIAL_API_SLAVE_NODE_INFO': 0xa0,
    'FUNC_ID_APPLICATION_SLAVE_COMMAND_HANDLER': 0xa1,
    'FUNC_ID_ZW_SEND_SLAVE_NODE_INFO': 0xa2,
    'FUNC_ID_ZW_SEND_SLAVE_DATA': 0xa3,
    'FUNC_ID_ZW_SET_SLAVE_LEARN_MODE': 0xa4,
    'FUNC_ID_ZW_GET_VIRTUAL_NODES': 0xa5,
    'FUNC_ID_ZW_IS_VIRTUAL_NODE': 0xa6,
    'FUNC_ID_ZW_SET_PROMISCUOUS_MODE': 0xd0,
    'FUNC_ID_PROMISCUOUS_APPLICATION_COMMAND_HANDLER': 0xd1
}

cmd = Bunch(commands)


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
        except IndexError as e:
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
        return "<Frame[{}:{}]: {}>".format(type_str, self.func, bytearray(self.data))

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

controller_info = ControllerInfo()
class FrameHandler:
    def __init__(self):
        self.info = controller_info

    def handle_incoming_frame(self, frame):
        if frame.func == cmd.FUNC_ID_ZW_GET_VERSION:
            self.info.library_version = frame.data[0:12].decode('ascii').rstrip(' \0')
            self.info.library_type = frame.data[12]

            print("we got {} {}".format(self.info.library_version,
                                        self.info.LibraryTypes[self.info.library_type]))

        elif frame.func == cmd.FUNC_ID_ZW_MEMORY_GET_ID:
            self.info.home_id = int.from_bytes(frame.data[0:4], 'big')
            self.info.node_id = frame.data[4]

            print("we got ID {:#04x} {}".format(self.info.home_id, self.info.node_id))

        elif frame.func == cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES:
            packet = ControllerCapabilitiesBitfield()
            packet.binary_data = frame.data[0]

            print(packet.bits.secondary, packet.bits.on_other_network, packet.bits.sis, packet.bits.real_primary,
                  packet.bits.suc, packet.bits.unknown1)

        elif frame.func == cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES:
            self.info.serial_version_major = frame.data[0]
            self.info.serial_version_minor = frame.data[1]
            self.info.serial_version = "{}.{}".format(self.info.serial_version_major, self.info.serial_version_minor)

            self.info.manufacturer_id = int.from_bytes(frame.data[2:4], 'big')
            self.info.product_type = int.from_bytes(frame.data[4:6], 'big')
            self.info.product_id = int.from_bytes(frame.data[6:8], 'big')

            self.info.serial_api_funcs_bitmask = int.from_bytes(frame.data[8:40], 'little')

            print("Serial API Version {}".format(self.info.serial_version))
            print("Manufacturer ID {:#06x}".format(self.info.manufacturer_id))
            print("Product Type {:#06x}".format(self.info.product_type))
            print("Product ID {:#06x}".format(self.info.product_id))

            for cmd_name in commands:
                cmd_num = commands.get(cmd_name)
                cmd_offset = cmd_num - 1
                is_cmd = self.info.serial_api_funcs_bitmask & (1 << cmd_offset) != 0
                if is_cmd:
                    print("has {} ({})".format(cmd_name, cmd_num))
                else:
                    print("NOT {} ({})".format(cmd_name, cmd_num))

            all_cmd_nums = commands.values()
            for i in range(0, 255):
                is_cmd = self.info.serial_api_funcs_bitmask & (1 << i) != 0
                if (i not in all_cmd_nums) and is_cmd:
                    print("UNKNOWN cmd value {:#x}".format(i))

        elif frame.func == cmd.FUNC_ID_ZW_GET_SUC_NODE_ID:
            self.info.suc_node_id = frame.data[0]

            print("SUC node id {}".format(self.info.suc_node_id))

        elif frame.func == cmd.FUNC_ID_ZW_GET_VIRTUAL_NODES:
            self.info.virtual_nodes_bitmask = int.from_bytes(frame.data[0:29], 'little')

            #assert len(frame.data) == 29

            print("virtual nodes: {}".format(self.info.virtual_nodes_bitmask))
            for i in range(0, 232):
                is_node = self.info.virtual_nodes_bitmask & (1 << i) != 0
                if is_node:
                    print("Has virtual node at {}".format(i))

        elif frame.func == cmd.FUNC_ID_ZW_GET_RANDOM:
            unknown1 = frame.data[0] # random RESPONSE = 1 ?
            random_len = frame.data[1]

            self.info.random = frame.data[2:]
            assert random_len == len(self.info.random)

            print("Random returned {}, unkn1 {}".format(self.info.random, unknown1))

        elif frame.func == cmd.FUNC_ID_SERIAL_API_GET_INIT_DATA:
            self.info.init_version = frame.data[0]
            self.info.init_caps = frame.data[1]

            bitfield_len = frame.data[2]
            assert bitfield_len == 29 # 232 nodes / 8
            self.info.nodes_bitmask = int.from_bytes(frame.data[3:32], 'little')
            self.info.unknown_init_ver2 = frame.data[32]
            self.info.unknown_init_cap2 = frame.data[33]


            print("init_ver {}, init_cap {}".format(self.info.init_version, self.info.init_caps))
            print("unknown, perhahps init_ver {}, init_cap {}".format(self.info.unknown_init_ver2, self.info.unknown_init_cap2))
            print("nodes: {}".format(self.info.nodes_bitmask))
            for i in range(0, 232):
                is_node = self.info.nodes_bitmask & (1 << i) != 0
                node_num = i+1
                if is_node:
                    print("Has node at {}".format(node_num))

        elif frame.func == cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO:
            node = Node()
            node.generic_class = frame.data[4]
            caps = frame.data[0]

            node.is_listening = caps & 0x80 != 0
            node.is_routing = caps & 0x40 != 0

            # 00111000 is baud rate mask (0x38)
            if caps & 0x38 == 0x10:
                node.max_baud = 40000
            else:
                node.max_baud = 9600

            # 00000111 is version mask
            node.version = (caps & 0x07) + 1

            security = frame.data[1]
            # SecurityFlag_Security = 0x01
            node.is_secure = security & 0x01 != 0

            unknown = frame.data[2]
            node.basic_class = frame.data[3]
            node.generic_class = frame.data[4]
            node.specific_class =  frame.data[5]

            print("class: basic {}, generic {}, specific {}".format(node.basic_class, node.generic_class, node.specific_class))
            print("is listening {}, is routing {}, is_secure {}, baud {}, version {}".format(node.is_listening, node.is_routing, node.is_secure, node.max_baud, node.version))
            print("unknown {}, security {}".format(unknown, security))
            # generic class == 0 ==> non-existant node.
            print("node info returned {}, len {}".format(frame.data, len(frame.data)))

        elif frame.func == cmd.FUNC_ID_ZW_APPLICATION_UPDATE:
            node = Node()
            node.state = frame.data[0]
            node.node_id = frame.data[1]

            state_name = "UNKNOWN_STATE"
            for name, state in node_update_states.items():
                if state == node.state:
                    state_name = name

            print("application update, state {} ({}), node_id {}".format(state_name, node.state, node.node_id))

        elif frame.func == cmd.FUNC_ID_ZW_REQUEST_NETWORK_UPDATE:
            self.info.network_update_ok = frame.data[0] != 0

            print("network update state OK: {}".format(self.info.network_update_ok))
        else:
            print("unknown frame to handle: {}".format(frame))



def call_command(protocol, remote, command, expected_payload, command_data=None, extra_frame=None):
    handler = FrameHandler()

    frame = Frame(REQUEST, command, command_data)
    print("SEND:", frame)
    protocol.write_frame(frame)

    response_frame = Frame(RESPONSE, command, expected_payload)
    if remote:
        frame2 = remote.get_frame(block=True)
        assert frame2 == frame
        remote.write_frame(response_frame)

    frame = protocol.get_frame(block=True)
    print("RECV:", frame)
    if command != cmd.FUNC_ID_ZW_GET_RANDOM and expected_payload != None:
        assert frame == response_frame
    handler.handle_incoming_frame(frame)

    if extra_frame:
        frame = protocol.get_frame(block=True)
        print("RECV<extra>:", frame)
        assert frame == extra_frame
        handler.handle_incoming_frame(frame)


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

    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_VERSION, bytearray(b'Z-Wave 4.05\x00\x01'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_MEMORY_GET_ID, bytearray(b'\xfb\xe3\x9b\xfd\x01'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_CONTROLLER_CAPABILITIES, bytearray(b'('))
    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_GET_CAPABILITIES, bytearray(b'\x05\x06\x01\x15\x04\x00\x00\x01\xfe\x83\xff\x88\xcf\x1f\x00\x00\xfb\x9f}\xa0g\x00\x80\x80\x00\x80\x86\x00\x00\x00\xe8s\x00\x00\x0e\x00\x00@\x1a\x00'))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_SUC_NODE_ID, bytearray(b'\x00'))
    # Only do this if this is a bridge controller, i.e. library_type == 7
    #test_frame(protocol, remote, cmd.FUNC_ID_ZW_GET_VIRTUAL_NODES, bytearray(b'\x21\x00\x01'))
    # arg1: random length, MIN=1, MAX = 32, rounded up to nearest even number.
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_RANDOM, bytearray(b'\x01\x04\xca\xfe\xba\xbe'), bytes([4]))
    call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_GET_INIT_DATA, bytearray(b'\x05\x00\x1d\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00'))

    # arg1: node_id
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x00\x00\x00\x03\x00\x00'), bytes([0]))
    call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x93\x16\x01\x02\x02\x01'), bytes([1]))

    for i in range(0, 232):
        is_node = controller_info.nodes_bitmask & (1 << i) != 0
        if is_node:
            print("testing node at {}".format(i+1))
            expected = bytearray(b'\x00\x00\x00\x03\x00\x00') if remote else None
            call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, expected,
                         bytes([i+1]))

    call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NETWORK_UPDATE, bytearray(b'\x00'))

#    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_APPLICATION_UPDATE, bytearray(b'\x81\x00\x00'))
#    call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, bytearray(b'\x01'), bytes([1]), extra_frame)

#    extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_APPLICATION_UPDATE, bytearray(b'\x81\x00\x00'))
#    call_command(protocol, remote, cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, bytearray(b'\x01'), bytes([2]), extra_frame)

    controller.close()
    sender.close()

if __name__ == '__main__':
    main()
