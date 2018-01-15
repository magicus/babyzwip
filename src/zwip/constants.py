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

command_classes = {
    'ALARM': 0x71,
    'ALARM_V2': 0x71,
    'NOTIFICATION_V3': 0x71,
    'NOTIFICATION_V4': 0x71,
    'NOTIFICATION_V5': 0x71,
    'NOTIFICATION_V6': 0x71,
    'NOTIFICATION_V7': 0x71,
    'NOTIFICATION_V8': 0x71,
    'APPLICATION_STATUS': 0x22,
    'ASSOCIATION_COMMAND_CONFIGURATION': 0x9B,
    'ASSOCIATION': 0x85,
    'ASSOCIATION_V2': 0x85,
    'AV_CONTENT_DIRECTORY_MD': 0x95,
    'AV_CONTENT_SEARCH_MD': 0x97,
    'AV_RENDERER_STATUS': 0x96,
    'AV_TAGGING_MD': 0x99,
    'BASIC_TARIFF_INFO': 0x36,
    'BASIC_WINDOW_COVERING': 0x50,
    'BASIC': 0x20,
    'BASIC_V2': 0x20,
    'BATTERY': 0x80,
    'CHIMNEY_FAN': 0x2A,
    'CLIMATE_CONTROL_SCHEDULE': 0x46,
    'CLOCK': 0x81,
    'CONFIGURATION': 0x70,
    'CONFIGURATION_V2': 0x70,
    'CONFIGURATION_V3': 0x70,
    'CONFIGURATION_V4': 0x70,
    'CONTROLLER_REPLICATION': 0x21,
    'CRC_16_ENCAP': 0x56,
    'DCP_CONFIG': 0x3A,
    'DCP_MONITOR': 0x3B,
    'DOOR_LOCK_LOGGING': 0x4C,
    'DOOR_LOCK': 0x62,
    'DOOR_LOCK_V2': 0x62,
    'DOOR_LOCK_V3': 0x62,
    'ENERGY_PRODUCTION': 0x90,
    'FIRMWARE_UPDATE_MD': 0x7A,
    'FIRMWARE_UPDATE_MD_V2': 0x7A,
    'FIRMWARE_UPDATE_MD_V3': 0x7A,
    'FIRMWARE_UPDATE_MD_V4': 0x7A,
    'FIRMWARE_UPDATE_MD_V5': 0x7A,
    'GEOGRAPHIC_LOCATION': 0x8C,
    'GROUPING_NAME': 0x7B,
    'HAIL': 0x82,
    'HRV_CONTROL': 0x39,
    'HRV_STATUS': 0x37,
    'INDICATOR': 0x87,
    'INDICATOR_V2': 0x87,
    'IP_CONFIGURATION': 0x9A,
    'LANGUAGE': 0x89,
    'LOCK': 0x76,
    'MANUFACTURER_PROPRIETARY': 0x91,
    'MANUFACTURER_SPECIFIC': 0x72,
    'MANUFACTURER_SPECIFIC_V2': 0x72,
    'MARK': 0xEF,
    'METER_PULSE': 0x35,
    'METER_TBL_CONFIG': 0x3C,
    'METER_TBL_MONITOR': 0x3D,
    'METER_TBL_MONITOR_V2': 0x3D,
    'METER_TBL_PUSH': 0x3E,
    'METER': 0x32,
    'METER_V2': 0x32,
    'METER_V3': 0x32,
    'METER_V4': 0x32,
    'MTP_WINDOW_COVERING': 0x51,
    'MULTI_CHANNEL_ASSOCIATION_V2': 0x8E,
    'MULTI_CHANNEL_ASSOCIATION_V3': 0x8E,
    'MULTI_CHANNEL_V2': 0x60,
    'MULTI_CHANNEL_V3': 0x60,
    'MULTI_CHANNEL_V4': 0x60,
    'MULTI_CMD': 0x8F,
    'MULTI_INSTANCE_ASSOCIATION': 0x8E,
    'MULTI_INSTANCE': 0x60,
    'NETWORK_MANAGEMENT_PROXY': 0x52,
    'NETWORK_MANAGEMENT_PROXY_V2': 0x52,
    'NETWORK_MANAGEMENT_BASIC': 0x4D,
    'NETWORK_MANAGEMENT_BASIC_V2': 0x4D,
    'NETWORK_MANAGEMENT_INCLUSION': 0x34,
    'NETWORK_MANAGEMENT_INCLUSION_V2': 0x34,
    'NO_OPERATION': 0x00,
    'NODE_NAMING': 0x77,
    'NON_INTEROPERABLE': 0xF0,
    'POWERLEVEL': 0x73,
    'PREPAYMENT_ENCAPSULATION': 0x41,
    'PREPAYMENT': 0x3F,
    'PROPRIETARY': 0x88,
    'PROTECTION': 0x75,
    'PROTECTION_V2': 0x75,
    'RATE_TBL_CONFIG': 0x48,
    'RATE_TBL_MONITOR': 0x49,
    'REMOTE_ASSOCIATION_ACTIVATE': 0x7C,
    'REMOTE_ASSOCIATION': 0x7D,
    'SCENE_ACTIVATION': 0x2B,
    'SCENE_ACTUATOR_CONF': 0x2C,
    'SCENE_CONTROLLER_CONF': 0x2D,
    'SCHEDULE_ENTRY_LOCK': 0x4E,
    'SCHEDULE_ENTRY_LOCK_V2': 0x4E,
    'SCHEDULE_ENTRY_LOCK_V3': 0x4E,
    'SCREEN_ATTRIBUTES': 0x93,
    'SCREEN_ATTRIBUTES_V2': 0x93,
    'SCREEN_MD': 0x92,
    'SCREEN_MD_V2': 0x92,
    'SECURITY_PANEL_MODE': 0x24,
    'SECURITY_PANEL_ZONE_SENSOR': 0x2F,
    'SECURITY_PANEL_ZONE': 0x2E,
    'SECURITY': 0x98,
    'SENSOR_ALARM': 0x9C,
    'SENSOR_BINARY': 0x30,
    'SENSOR_BINARY_V2': 0x30,
    'SENSOR_CONFIGURATION': 0x9E,
    'SENSOR_MULTILEVEL': 0x31,
    'SENSOR_MULTILEVEL_V2': 0x31,
    'SENSOR_MULTILEVEL_V3': 0x31,
    'SENSOR_MULTILEVEL_V4': 0x31,
    'SENSOR_MULTILEVEL_V5': 0x31,
    'SENSOR_MULTILEVEL_V6': 0x31,
    'SENSOR_MULTILEVEL_V7': 0x31,
    'SENSOR_MULTILEVEL_V8': 0x31,
    'SENSOR_MULTILEVEL_V9': 0x31,
    'SENSOR_MULTILEVEL_V10': 0x31,
    'SILENCE_ALARM': 0x9D,
    'SIMPLE_AV_CONTROL': 0x94,
    'SWITCH_ALL': 0x27,
    'SWITCH_BINARY': 0x25,
    'SWITCH_BINARY_V2': 0x25,
    'SWITCH_MULTILEVEL': 0x26,
    'SWITCH_MULTILEVEL_V2': 0x26,
    'SWITCH_MULTILEVEL_V3': 0x26,
    'SWITCH_MULTILEVEL_V4': 0x26,
    'SWITCH_TOGGLE_BINARY': 0x28,
    'SWITCH_TOGGLE_MULTILEVEL': 0x29,
    'TARIFF_CONFIG': 0x4A,
    'TARIFF_TBL_MONITOR': 0x4B,
    'THERMOSTAT_FAN_MODE': 0x44,
    'THERMOSTAT_FAN_MODE_V2': 0x44,
    'THERMOSTAT_FAN_MODE_V3': 0x44,
    'THERMOSTAT_FAN_MODE_V4': 0x44,
    'THERMOSTAT_FAN_STATE': 0x45,
    'THERMOSTAT_FAN_STATE_V2': 0x45,
    'THERMOSTAT_HEATING': 0x38,
    'THERMOSTAT_MODE': 0x40,
    'THERMOSTAT_MODE_V2': 0x40,
    'THERMOSTAT_MODE_V3': 0x40,
    'THERMOSTAT_OPERATING_STATE': 0x42,
    'THERMOSTAT_OPERATING_STATE_V2': 0x42,
    'THERMOSTAT_SETBACK': 0x47,
    'THERMOSTAT_SETPOINT': 0x43,
    'THERMOSTAT_SETPOINT_V2': 0x43,
    'THERMOSTAT_SETPOINT_V3': 0x43,
    'TIME_PARAMETERS': 0x8B,
    'TIME': 0x8A,
    'TIME_V2': 0x8A,
    'TRANSPORT_SERVICE_V2': 0x55,
    'TRANSPORT_SERVICE': 0x55,
    'USER_CODE': 0x63,
    'VERSION': 0x86,
    'VERSION_V2': 0x86,
    'WAKE_UP': 0x84,
    'WAKE_UP_V2': 0x84,
    'ZIP_6LOWPAN': 0x4F,
    'ZIP': 0x23,
    'ZIP_V2': 0x23,
    'ZIP_V3': 0x23,
    'APPLICATION_CAPABILITY': 0x57,
    'SWITCH_COLOR': 0x33,
    'SWITCH_COLOR_V2': 0x33,
    'SWITCH_COLOR_V3': 0x33,
    'SCHEDULE': 0x53,
    'SCHEDULE_V2': 0x53,
    'SCHEDULE_V3': 0x53,
    'NETWORK_MANAGEMENT_PRIMARY': 0x54,
    'ZIP_ND': 0x58,
    'ASSOCIATION_GRP_INFO': 0x59,
    'ASSOCIATION_GRP_INFO_V2': 0x59,
    'ASSOCIATION_GRP_INFO_V3': 0x59,
    'DEVICE_RESET_LOCALLY': 0x5A,
    'CENTRAL_SCENE': 0x5B,
    'CENTRAL_SCENE_V2': 0x5B,
    'CENTRAL_SCENE_V3': 0x5B,
    'IP_ASSOCIATION': 0x5C,
    'ANTITHEFT': 0x5D,
    'ANTITHEFT_V2': 0x5D,
    'ZWAVEPLUS_INFO': 0x5E,
    'ZWAVEPLUS_INFO_V2': 0x5E,
    'ZIP_GATEWAY': 0x5F,
    'ZIP_PORTAL': 0x61,
    'DMX': 0x65,
    'BARRIER_OPERATOR': 0x66,
    'NETWORK_MANAGEMENT_INSTALLATION_MAINTENANCE': 0x67,
    'ZIP_NAMING': 0x68,
    'MAILBOX': 0x69,
    'WINDOW_COVERING': 0x6A,
    'SECURITY_2': 0x9F,
    'IRRIGATION': 0x6B,
    'SUPERVISION': 0x6C,
    'HUMIDITY_CONTROL_SETPOINT': 0x64,
    'HUMIDITY_CONTROL_MODE': 0x6D,
    'HUMIDITY_CONTROL_OPERATING_STATE': 0x6E,
    'ENTRY_CONTROL': 0x6F,
    'INCLUSION_CONTROLLER': 0x74,
}

cmd = Bunch(commands)


def get_command_name(cmd_num):
    for command in commands:
        if commands.get(command) == cmd_num:
            return command


def get_command_class_name(cmd_class):
    for command in command_classes:
        if command_classes.get(command) == cmd_class:
            return command
