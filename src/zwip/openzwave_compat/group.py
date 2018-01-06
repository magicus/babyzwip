"""
Compatibility layer with python-openzwave
"""

from zwip.openzwave_compat.object import ZWaveObject

class ZWaveGroup(ZWaveObject):

    def __init__(self, group_index, network=None, node_id=None):
        ZWaveObject.__init__(self, group_index, network)
        self._group_index = group_index

    @property
    def index(self):
        return self._group_index

    @property
    def label(self):
        return None

    @property
    def max_associations(self):
        return None

    @property
    def associations(self):
        return None

    @property
    def associations_instances(self):
        return None

    def add_association(self, target_node_id, instance=0x00):
        pass

    def remove_association(self, target_node_id, instance=0x00):
        pass

    def to_dict(self, extras=['all']):
        return None
