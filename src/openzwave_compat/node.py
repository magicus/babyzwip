"""
Compatibility layer with python-openzwave
"""

from openzwave_compat import ZWaveObject
from openzwave_compat import ZWaveNodeBasic, ZWaveNodeSwitch
from openzwave_compat import ZWaveNodeSensor, ZWaveNodeThermostat
from openzwave_compat import ZWaveNodeSecurity, ZWaveNodeDoorLock

class ZWaveNode(ZWaveObject,
                ZWaveNodeBasic, ZWaveNodeSwitch,
                ZWaveNodeSensor, ZWaveNodeThermostat,
                ZWaveNodeSecurity, ZWaveNodeDoorLock):

    def __init__(self, node_id, network):
        ZWaveObject.__init__(self, node_id, network)

    @property
    def node_id(self):
        return None

    @property
    def name(self):
        return None

    @name.setter
    def name(self, value):
        pass

    @property
    def location(self):
        return None

    @location.setter
    def location(self, value):
        pass

    @property
    def product_name(self):
        return None

    @product_name.setter
    def product_name(self, value):
        pass

    @property
    def product_type(self):
        return None

    @property
    def product_id(self):
        return None

    @property
    def device_type(self):
        return None

    @property
    def role(self):
        return None

    def to_dict(self, extras=['all']):
        return None

    @property
    def capabilities(self):
        return None

    @property
    def neighbors(self):
        return None

    @property
    def num_groups(self):
        return None

    def get_max_associations(self, groupidx):
        return None

    @property
    def groups(self):
        return None

    def groups_to_dict(self, extras=['all']):
        return None

    @property
    def command_classes(self):
        return None

    @property
    def command_classes_as_string(self):
        return None

    def get_command_class_as_string(self, class_id):
        return None

    def get_command_class_genres(self):
        return None

    def get_values_by_command_classes(self, genre='All', \
        type='All', readonly='All', writeonly='All'):
        return None

    def get_values_for_command_class(self, class_id):
        return None

    def get_values(self, class_id='All', genre='All', type='All', \
        readonly='All', writeonly='All', index='All', label='All'):
        return None

    def values_to_dict(self, extras=['all']):
        return None

    def add_value(self, value_id):
        pass

    def change_value(self, value_id):
        pass

    def refresh_value(self, value_id):
        return None

    def remove_value(self, value_id):
        return None

    def set_field(self, field, value):
        pass

    def has_command_class(self, class_id):
        return None

    @property
    def manufacturer_id(self):
        return None

    @property
    def manufacturer_name(self):
        return None

    @manufacturer_name.setter
    def manufacturer_name(self, value):
        return None

    @property
    def generic(self):
        return None

    @property
    def basic(self):
        return None

    @property
    def specific(self):
        return None

    @property
    def security(self):
        return None

    @property
    def version(self):
        return None

    @property
    def is_listening_device(self):
        return None

    @property
    def is_beaming_device(self):
        return None

    @property
    def is_frequent_listening_device(self):
        return None

    @property
    def is_security_device(self):
        return None

    @property
    def is_routing_device(self):
        return None

    @property
    def is_zwave_plus(self):
        return None

    @property
    def is_locked(self):
        return None

    @property
    def is_sleeping(self):
        return None

    @property
    def max_baud_rate(self):
        return None

    def heal(self, upNodeRoute=False):
        return None

    def test(self, count=1):
        pass

    def assign_return_route(self):
        return None

    def refresh_info(self):
        return None

    def request_state(self):
        return None

    def send_information(self):
        return None

    def network_update(self):
        return None

    def neighbor_update(self):
        return None

    def create_button(self, buttonid):
        return None

    def delete_button(self, buttonid):
        return None

    def request_all_config_params(self):
        pass

    def request_config_param(self, param):
        pass

    def set_config_param(self, param, value, size=2):
        return None

    @property
    def is_awake(self):
        return None

    @property
    def is_failed(self):
        return None

    @property
    def query_stage(self):
        return None

    @property
    def is_ready(self):
        return None

    @is_ready.setter
    def is_ready(self, value):
        pass

    @property
    def is_info_received(self):
        return None

    @property
    def type(self):
        return None
