"""
Compatibility layer with python-openzwave
"""

from zwip.openzwave_compat.object import ZWaveObject

# Set default logging handler to avoid "No handler found" warnings.
import logging

class ZWaveScene(ZWaveObject):

    def __init__(self, scene_id, network=None):
        ZWaveObject.__init__(self, scene_id, network)

    @property
    def scene_id(self):
        return None

    @property
    def label(self):
        return None

    @label.setter
    def label(self, value):
        pass

    def create(self, label=None):
        return None

    def add_value(self, value_id, value_data):
        return None

    def set_value(self, value_id, value_data):
        return None

    def get_values(self):
        return None

    def get_values_by_node(self):
        return None

    def remove_value(self, value_id):
        return None

    def activate(self):
        return None

    def to_dict(self, extras=['kvals']):
        return None
