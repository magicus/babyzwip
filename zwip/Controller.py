import struct
import serial
import serial.tools.list_ports
import serial.threaded

SOF = 0x01
ACK = 0x06
NAK = 0x15
CAN = 0x18

REQUEST = 0x00
RESPONSE = 0x01

FUNC_ID_ZW_GET_VERSION = 0x15


class FrameProtocol(serial.threaded.Protocol):
    class State:
        Open, WantLength, WantData = range(3)

    def __init__(self):
        self.packet = bytearray()
        self.in_packet = False
        self.transport = None
        self.state = self.State.Open

    def connection_made(self, transport):
        """Store transport"""
        self.transport = transport

    def connection_lost(self, exc):
        """Forget transport"""
        self.transport = None
        self.in_packet = False
        del self.packet[:]
        self.state = self.State.Open
        super().connection_lost(exc)

    def data_received(self, data):
        """Find data enclosed in START/STOP, call handle_packet"""
        for byte in serial.iterbytes(data):
            if self.state == self.state.Open:
                if byte == ACK:
                    self.handle_packet([ACK])
                if byte == NAK:
                    self.handle_packet([ACK])
            if byte == self.START:
                self.in_packet = True
            elif byte == self.STOP:
                self.in_packet = False
                self.handle_packet(bytes(self.packet)) # make read-only copy
                del self.packet[:]
            elif self.in_packet:
                self.packet.extend(byte)
            else:
                self.handle_out_of_packet_data(byte)

    def handle_packet(self, packet):
        """Process packets - to be overridden by subclassing"""
        raise NotImplementedError('please implement functionality in handle_packet')

    def handle_out_of_packet_data(self, data):
        """Process data that is received outside of packets"""
        pass


class InvalidFrame(Exception):
    pass


class Frame:
    def __init__(self, frame_type, function, data=None):
        self.frame_type = frame_type
        self.function = function
        self.data = data if data else []

    @classmethod
    def parse(cls, frame_bytes):
        try:
            if frame_bytes[0] != SOF:
                raise InvalidFrame('No SOF at beginning')

            if frame_bytes[1] != len(frame_bytes)-2:
                raise
# wait max 5 seconds on reply to request.
# checksum: räkna ut: sätt till 0, gör xor över hela, skriv resultatet
# kolla: räkna xor över hela inkl checksum, då ska det bli 0. el 0xff?
#kallas LRC using XOR.

#dcb.fDtrControl = (byte) CommAPI.DTRControlFlows.ENABLE; // DTR flow control type



# eply=0x15) - FUNC_ID_ZW_GET_VERSION: 0x01, 0x03, 0x00, 0x15, 0xe9
# 2017-01-02 00:33:48.446 Detail, contrlr,   Received: 0x01, 0x10, 0x01, 0x15, 0x5a, 0x2d, 0x57, 0x61, 0x76, 0x65, 0x20, 0x34, 0x2e, 0x30, 0x35, 0x00, 0x01, 0x97
# version string + controller-type ("library")
#"Z-Wave 4.05\0" + 0x01



#define FUNC_ID_ZW_GET_VERSION							0x15

#define REQUEST											0x00
#define RESPONSE										0x01

#define SOF												0x01
#define ACK												0x06
#define NAK												0x15
#define CAN												0x18

#m_buffer[0] = SOF;
#m_buffer[1] = 0; // Length
#m_buffer[2] = _msgType;
#m_buffer[3] = _function;

#checksum = 0xff;
#for (uint32 i=1; i < m_length; ++i ){
#    checksum ^= m_buffer[i];
#}
#m_buffer[m_length + +] = checksum;

InvalidFrame('Length mismatch')

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


def main():
    interface = FakeController()
    controller = Controller(interface)
    msg = controller.next_msg()
    print("Message: %s" % msg)
    # frame = Frame.build_frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
    frame = Frame(REQUEST, FUNC_ID_ZW_GET_VERSION)
    print(frame.as_bytearray())
    frame2 = Frame.parse(frame.as_bytearray())
    ba2 = frame2.as_bytearray()
    print(ba2)
    frame3 = Frame.parse(bytearray([0x01, 0x03, 0x00, 0x15, 0xe9]))
    ba3 = frame3.as_bytearray()
    print(ba3)
    print(repr(frame3))
    #exit()
    port = locate_usb_controller()
    print("got port: {}".format(port))
    usb = UsbController(port)
    # initString = bytearray([0x01, 0x03, 0x00, 0x15, 0xe9])
    usb.write(frame.as_bytearray())
    data = usb.read()
    while data:
        print(data)
        data = usb.read()
    usb.close()

if __name__ == '__main__':
    main()
