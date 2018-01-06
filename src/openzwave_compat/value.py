"""
Compatibility layer with python-openzwave
"""

from openzwave_compat import ZWaveObject

class ZWaveValue(ZWaveObject):
    def __init__(self, value_id, network=None, parent=None):
        ZWaveObject.__init__(self, value_id, network)

    @property
    def parent_id(self):
        return None

    @property
    def value_id(self):
        return None

    @property
    def id_on_network(self):
        return None

    @property
    def node(self):
        return None

    @property
    def label(self):
        return None

    @label.setter
    def label(self, value):
        pass

    @property
    def help(self):
        return None

    @help.setter
    def help(self, value):
        pass

    @property
    def units(self):
        return None

    @units.setter
    def units(self, value):
        pass

    @property
    def max(self):
        return None

    @property
    def min(self):
        return None

    @property
    def type(self):
        return None

    @property
    def genre(self):
        return None

    @property
    def index(self):
        return None

    @property
    def instance(self):
        return None

    @property
    def data(self):
        return None

    @data.setter
    def data(self, value):
        pass

    @property
    def data_as_string(self):
        return None

    @property
    def data_items(self):
        return None

    def check_data(self, data):
        return None

    @property
    def is_set(self):
        return None

    @property
    def is_read_only(self):
        return None

    @property
    def is_write_only(self):
        return None

    def enable_poll(self, intensity=1):
        return None

    def disable_poll(self):
        return None

    @property
    def poll_intensity(self):
        return None

    @property
    def is_polled(self):
        return None

    @property
    def command_class(self):
        return None

    def refresh(self):
        return None

    @property
    def precision(self):
        return None

    def is_change_verified(self):
        return None

    def set_change_verified(self, verify):
        pass

    def to_dict(self, extras=['all']):
        return None
