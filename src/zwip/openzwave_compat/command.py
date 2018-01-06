"""
Compatibility layer with python-openzwave
"""

from zwip.openzwave_compat.object import ZWaveNodeInterface

# Set default logging handler to avoid "No handler found" warnings.
import logging

class ZWaveNodeBasic(ZWaveNodeInterface):

    def get_battery_level(self, value_id=None):
        return None

    def get_battery_levels(self):
        return None

    def get_power_level(self, value_id=None):
        return None

    def get_power_levels(self):
        return None

    def can_wake_up(self):
        return None

    def get_configs(self, readonly='All', writeonly='All'):
        return None

    def set_config(self, value_id, value):
        return None

    def get_config(self, value_id=None):
        return None

    def can_set_indicator(self):
        return None


class ZWaveNodeSwitch(ZWaveNodeInterface):

    def get_switches_all(self):
        return None

    def set_switch_all(self, value_id, value):
        return None

    def get_switch_all_state(self, value_id):
        return None

    def get_switch_all_item(self, value_id):
        return None

    def get_switch_all_items(self, value_id):
        return None

    def get_switches(self):
        return None

    def set_switch(self, value_id, value):
        return None

    def get_switch_state(self, value_id):
        return None

    def get_dimmers(self):
        return None

    def set_dimmer(self, value_id, value):
        return None

    def get_dimmer_level(self, value_id):
        return None

    def get_rgbbulbs(self):
        return None

    def set_rgbw(self, value_id, value):
        return None

    def get_rgbw(self, value_id):
        return None


class ZWaveNodeSensor(ZWaveNodeInterface):

    def get_sensors(self, type='All'):
        return None

    def get_sensor_value(self, value_id):
        return None


class ZWaveNodeThermostat(ZWaveNodeInterface):

    def get_thermostats(self, type='All'):
        return None

    def get_thermostat_value(self, value_id):
        return None

    def set_thermostat_mode(self, value):
        return None

    def set_thermostat_fan_mode(self, value):
        return None

    def set_thermostat_heating(self, value):
        return None

    def set_thermostat_cooling(self, value):
        return None

    def get_thermostat_state(self):
        return None

    def get_thermostat_fan_state(self):
        return None


class ZWaveNodeSecurity(ZWaveNodeInterface):

    def get_protections(self):
        return None

    def set_protection(self, value_id, value):
        return None

    def get_protection_item(self, value_id):
        return None

    def get_protection_items(self, value_id):
        return None


class ZWaveNodeDoorLock(ZWaveNodeInterface):

    def get_doorlocks(self):
        return None

    def set_doorlock(self, value_id, value):
        return None

    def get_usercode(self, index):
        return None

    def get_usercodes(self, index='All'):
        return None

    def set_usercode(self, value_id, value):
        return None

    def set_usercode_at_index(self, index, value):
        return None

    def get_doorlock_logs(self):
        return None
