"""
Compatibility layer with python-openzwave
"""

from openzwave_compat import ZWaveObject
from openzwave_compat import Singleton

class ZWaveNetwork(ZWaveObject):

    SIGNAL_NETWORK_FAILED = 'NetworkFailed'
    SIGNAL_NETWORK_STARTED = 'NetworkStarted'
    SIGNAL_NETWORK_READY = 'NetworkReady'
    SIGNAL_NETWORK_STOPPED = 'NetworkStopped'
    SIGNAL_NETWORK_RESETTED = 'DriverResetted'
    SIGNAL_NETWORK_AWAKED = 'DriverAwaked'
    SIGNAL_DRIVER_FAILED = 'DriverFailed'
    SIGNAL_DRIVER_READY = 'DriverReady'
    SIGNAL_DRIVER_RESET = 'DriverReset'
    SIGNAL_DRIVER_REMOVED = 'DriverRemoved'
    SIGNAL_GROUP = 'Group'
    SIGNAL_NODE = 'Node'
    SIGNAL_NODE_ADDED = 'NodeAdded'
    SIGNAL_NODE_EVENT = 'NodeEvent'
    SIGNAL_NODE_NAMING = 'NodeNaming'
    SIGNAL_NODE_NEW = 'NodeNew'
    SIGNAL_NODE_PROTOCOL_INFO = 'NodeProtocolInfo'
    SIGNAL_NODE_READY = 'NodeReady'
    SIGNAL_NODE_REMOVED = 'NodeRemoved'
    SIGNAL_SCENE_EVENT = 'SceneEvent'
    SIGNAL_VALUE = 'Value'
    SIGNAL_VALUE_ADDED = 'ValueAdded'
    SIGNAL_VALUE_CHANGED = 'ValueChanged'
    SIGNAL_VALUE_REFRESHED = 'ValueRefreshed'
    SIGNAL_VALUE_REMOVED = 'ValueRemoved'
    SIGNAL_POLLING_ENABLED = 'PollingEnabled'
    SIGNAL_POLLING_DISABLED = 'PollingDisabled'
    SIGNAL_CREATE_BUTTON = 'CreateButton'
    SIGNAL_DELETE_BUTTON = 'DeleteButton'
    SIGNAL_BUTTON_ON = 'ButtonOn'
    SIGNAL_BUTTON_OFF = 'ButtonOff'
    SIGNAL_ESSENTIAL_NODE_QUERIES_COMPLETE = 'EssentialNodeQueriesComplete'
    SIGNAL_NODE_QUERIES_COMPLETE = 'NodeQueriesComplete'
    SIGNAL_AWAKE_NODES_QUERIED = 'AwakeNodesQueried'
    SIGNAL_ALL_NODES_QUERIED = 'AllNodesQueried'
    SIGNAL_ALL_NODES_QUERIED_SOME_DEAD = 'AllNodesQueriedSomeDead'
    SIGNAL_MSG_COMPLETE = 'MsgComplete'
    SIGNAL_NOTIFICATION = 'Notification'
    SIGNAL_CONTROLLER_COMMAND = 'ControllerCommand'
    SIGNAL_CONTROLLER_WAITING = 'ControllerWaiting'

    STATE_STOPPED = 0
    STATE_FAILED = 1
    STATE_RESETTED = 3
    STATE_STARTED = 5
    STATE_AWAKED = 7
    STATE_READY = 10

    def __init__(self, options, log=None, autostart=True, kvals=True):
        pass

    def start(self):
        pass

    def stop(self, fire=True):
        pass

    def destroy(self):
        pass

    @property
    def home_id(self):
        return None

    @home_id.setter
    def home_id(self, value):
        pass

    @property
    def home_id_str(self):
        return None

    @property
    def is_ready(self):
        return None

    @property
    def state(self):
        return None

    @state.setter
    def state(self, value):
        pass

    @property
    def state_str(self):
        return None

    @property
    def manager(self):
        return None

    @property
    def controller(self):
        return None

    @property
    def nodes(self):
        return None

    def nodes_to_dict(self, extras=['all']):
        return None

    def to_dict(self, extras=['kvals']):
        return None

    @nodes.setter
    def nodes(self, value):
        pass

    def switch_all(self, state):
        pass

    def test(self, count=1):
        pass

    def heal(self, upNodeRoute=False):
        return None

    def get_value(self, value_id):
        return None

    @property
    def id_separator(self):
        return None

    @id_separator.setter
    def id_separator(self, value):
        pass

    def get_value_from_id_on_network(self, id_on_network):
        return None

    def get_scenes(self):
        return None

    def scenes_to_dict(self, extras=['all']):
        return None

    def create_scene(self, label=None):
        return None

    def scene_exists(self, scene_id):
        return None

    @property
    def scenes_count(self):
        return None

    def remove_scene(self, scene_id):
        return None

    @property
    def nodes_count(self):
        return None

    @property
    def sleeping_nodes_count(self):
        return None

    def get_poll_interval(self):
        return None

    def set_poll_interval(self, milliseconds=500, bIntervalBetweenPolls=True):
        pass

    def zwcallback(self, args):
        pass

    def write_config(self):
        pass


class ZWaveNetworkSingleton(ZWaveNetwork):
    __metaclass__ = Singleton
