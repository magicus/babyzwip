import ctypes

from zwip.constants import *
from zwip import hex_string


class ZWavePacket(object):
    def __init__(self, node_id, command_class, command_num, data=None):
        self.node_id = node_id
        self.command_class = command_class
        self.command_num = command_num
        self.data = data if data else []

    def __str__(self):
        return "<Packet @{} {}({:#x})/{:#x} [{}]>".format(
            self.node_id, get_command_class_name(self.command_class), self.command_class, self.command_num,
            hex_string(self.data))

    def as_bytes(self):
        # Length includes command_class, command_num and data, but not node_id.
        length = 2 + len(self.data)
        packet_bytes = bytearray([self.node_id, length, self.command_class, self.command_num] + self.data)
        return bytes(packet_bytes)


class IncomingSerialPacket(object):
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
            elif frame.func in [cmd.FUNC_ID_ZW_REQUEST_NODE_INFO, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION,
                                cmd.FUNC_ID_ZW_SEND_DATA, cmd.FUNC_ID_ZW_REQUEST_NETWORK_UPDATE]:
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
        return "<GetVersionReplyPacket(library_version='{}', library_type={})>".format(
            self.library_version, self.library_type)

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
    def __init__(self, serial_version_major, serial_version_minor, manufacturer_id, product_type, product_id,
                 serial_api_funcs_bitmask):
        self.serial_version_major = serial_version_major
        self.serial_version_minor = serial_version_minor
        self.manufacturer_id = manufacturer_id
        self.product_type = product_type
        self.product_id = product_id
        self.serial_api_funcs_bitmask = serial_api_funcs_bitmask
        print("Created:", self)
        # self.print_it()

    def __repr__(self):
        return "<GetSerialApiCapabilitiesReplyPacket(serial_version_major={}, serial_version_minor={}, manufacturer_id={:#06x}, product_type={:#06x}, product_id={:#06x}, serial_api_funcs_bitmask={:#x})>".format(
            self.serial_version_major, self.serial_version_minor, self.manufacturer_id, self.product_type,
            self.product_id, self.serial_api_funcs_bitmask)

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

        return cls(serial_version_major, serial_version_minor, manufacturer_id, product_type, product_id,
                   serial_api_funcs_bitmask)


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

        print("GetInitDataReplyPacket unknown, perhaps init_ver {}, init_cap {}".format(
            unknown_init_ver2, unknown_init_cap2))

        return cls(init_version, init_caps, nodes_bitmask)


class GetNodeProtocolInfoReplyPacket(IncomingSerialPacket):
    def __init__(self, basic_class, generic_class, specific_class, version, is_listening, is_routing, is_secure,
                 max_baud):
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
            self.basic_class, self.generic_class, self.specific_class, self.version, self.is_listening,
            self.is_routing, self.is_secure, self.max_baud)

    @classmethod
    def from_frame(cls, frame):
        caps = frame.data[0]
        security = frame.data[1]
        unknown = frame.data[2]
        basic_class = frame.data[3]
        generic_class = frame.data[4]
        specific_class = frame.data[5]

        # NOTE: generic class == 0 ==> non-existent node.

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
        return "<TransactionStartedReplyPacket(func={:#0x}, request_successful={})>".format(
            self.func, self.request_successful)

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
            self.status, self.node_id, self.basic_class, self.generic_class, self.specific_class,
            hex_string(self.cmd_classes))

    def print_it(self):
        status_name = "UNKNOWN_STATE"
        for name, status in node_update_states.items():
            if status == self.status:
                status_name = name

        print("AsyncUpdateNodeInformationPacket status: {}({:#0x}, node {})".format(
            status_name, self.status, self.node_id))

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
            packet = None

        return cls(status, node_id, packet)
