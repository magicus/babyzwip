from zwip.packets import *
from zwip.transport import *


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
        if expected_payload and command != cmd.FUNC_ID_ZW_GET_RANDOM:
            # assert frame == response_frame
            pass
        inc_packet = IncomingSerialPacket.from_frame(frame)
        print("RECV-parsed:", inc_packet)

    if extra_frame:
        frame = protocol.get_frame(block=True)
        print("RECV<extra>:", frame)
        print("exp RECV<extra>:", extra_frame)
        if frame != extra_frame:
            print("WARNING: diff!!!")
        # assert frame == extra_frame
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


def create_send_payload(zwpacket, callback_id, transmit_options=DEFAULT_TRANSMIT_OPTIONS):
    payload_bytes = zwpacket.as_bytes() + bytes([transmit_options, callback_id])
    return payload_bytes


def main():
    sender = FakeSender()
    sender.open()
    # remote = sender.remote_protocol()
    remote = None

    # port = sender.port
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
    call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x01'), bytearray(b'\x02\x25\x07'),
                 extra_frame)

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
    # call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'\x01'), bytearray(b'\x01\x02\x00\x00\x11\x21'), Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_DATA, bytearray(b'!\x01\x004')))

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

    # call_command(protocol, remote, cmd.FUNC_ID_SERIAL_API_APPL_NODE_INFORMATION,  bytearray(b'\x01'),
    #              bytearray(b'\x01\x02\x01\x01\x21'), has_response=False)

    # call_command(protocol, remote, cmd.FUNC_ID_ZW_GET_NODE_PROTOCOL_INFO, bytearray(b'\x93\x16\x01\x02\x02\x01'),
    #             bytes([1]))

    # openzwave says the node in arg1 is "controller node"?

    # arg1: dest node
    # arg2: tx options 0x11
    # arg3: return handling, 0 = no reply, 0x03 = has reply (actually, callback id)
    # extra_frame = Frame(REQUEST, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x03\x01'))
    # call_command(protocol, remote, cmd.FUNC_ID_ZW_SEND_NODE_INFORMATION, bytearray(b'\x01'), bytearray(b'\x01\x11\x07'), extra_frame)

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
