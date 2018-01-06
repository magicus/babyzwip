"""
Compatibility layer with python-openzwave
"""

from openzwave_compat import ZWaveObject, deprecated

class ZWaveController(ZWaveObject):
    #@deprecated
    SIGNAL_CTRL_NORMAL = 'Normal'
    #@deprecated
    SIGNAL_CTRL_STARTING = 'Starting'
    #@deprecated
    SIGNAL_CTRL_CANCEL = 'Cancel'
    #@deprecated
    SIGNAL_CTRL_ERROR = 'Error'
    #@deprecated
    SIGNAL_CTRL_WAITING = 'Waiting'
    #@deprecated
    SIGNAL_CTRL_SLEEPING = 'Sleeping'
    #@deprecated
    SIGNAL_CTRL_INPROGRESS = 'InProgress'
    #@deprecated
    SIGNAL_CTRL_COMPLETED = 'Completed'
    #@deprecated
    SIGNAL_CTRL_FAILED = 'Failed'
    #@deprecated
    SIGNAL_CTRL_NODEOK = 'NodeOK'
    #@deprecated
    SIGNAL_CTRL_NODEFAILED = 'NodeFailed'

    STATE_NORMAL = 'Normal'
    STATE_STARTING = 'Starting'
    STATE_CANCEL = 'Cancel'
    STATE_ERROR = 'Error'
    STATE_WAITING = 'Waiting'
    STATE_SLEEPING = 'Sleeping'
    STATE_INPROGRESS = 'InProgress'
    STATE_COMPLETED = 'Completed'
    STATE_FAILED = 'Failed'
    STATE_NODEOK = 'NodeOK'
    STATE_NODEFAILED = 'NodeFailed'

    INT_NORMAL = 0
    INT_STARTING = 1
    INT_CANCEL = 2
    INT_ERROR = 3
    INT_WAITING = 4
    INT_SLEEPING = 5
    INT_INPROGRESS = 6
    INT_COMPLETED = 7
    INT_FAILED = 8
    INT_NODEOK = 9
    INT_NODEFAILED = 10

    #@deprecated
    SIGNAL_CONTROLLER = 'Message'

    SIGNAL_CONTROLLER_STATS = 'ControllerStats'

    #@deprecated
    CMD_NONE = 0
    #@deprecated
    CMD_ADDDEVICE = 1
    #@deprecated
    CMD_CREATENEWPRIMARY = 2
    #@deprecated
    CMD_RECEIVECONFIGURATION = 3
    #@deprecated
    CMD_REMOVEDEVICE = 4
    #@deprecated
    CMD_REMOVEFAILEDNODE = 5
    #@deprecated
    CMD_HASNODEFAILED = 6
    #@deprecated
    CMD_REPLACEFAILEDNODE = 7
    #@deprecated
    CMD_TRANSFERPRIMARYROLE = 8
    #@deprecated
    CMD_REQUESTNETWORKUPDATE = 9
    #@deprecated
    CMD_REQUESTNODENEIGHBORUPDATE = 10
    #@deprecated
    CMD_ASSIGNRETURNROUTE = 11
    #@deprecated
    CMD_DELETEALLRETURNROUTES = 12
    #@deprecated
    CMD_SENDNODEINFORMATION = 13
    #@deprecated
    CMD_REPLICATIONSEND = 14
    #@deprecated
    CMD_CREATEBUTTON = 15
    #@deprecated
    CMD_DELETEBUTTON = 16

    def __init__(self, controller_id, network, options=None):
        ZWaveObject.__init__(self, controller_id, network)

    def stop(self):
        pass

    @property
    def node(self):
        return None

    @node.setter
    def node(self, value):
        pass

    @property
    def node_id(self):
        return None

    @property
    def name(self):
        return None

    @property
    def library_type_name(self):
        return None

    @property
    def library_description(self):
        return None

    @property
    def library_version(self):
        return None

    @property
    def python_library_version(self):
        return None

    @property
    def ozw_library_version(self):
        return None

    @property
    def library_config_path(self):
        return None

    @property
    def library_user_path(self):
        return None

    @property
    def device(self):
        return None

    @property
    def options(self):
        return None

    @property
    def stats(self):
        return None

    def get_stats_label(self, stat):
        return None

    def do_poll_statistics(self):
        pass

    @property
    def poll_stats(self):
        return None

    @poll_stats.setter
    def poll_stats(self, value):
        pass

    @property
    def capabilities(self):
        return None

    @property
    def is_primary_controller(self):
        return None

    @property
    def is_static_update_controller(self):
        return None

    @property
    def is_bridge_controller(self):
        return None

    @property
    def send_queue_count(self):
        return None

    def hard_reset(self):
        pass

    def soft_reset(self):
        pass

    def create_new_primary(self):
        return None

    def transfer_primary_role(self):
        return None

    def receive_configuration(self):
        return None

    def add_node(self, doSecurity=False):
        return None

    def remove_node(self):
        return None

    def remove_failed_node(self, nodeid):
        return None

    def has_node_failed(self, nodeid):
        return None

    def request_node_neighbor_update(self, nodeid):
        return None

    def assign_return_route(self, nodeid):
        return None

    def delete_all_return_routes(self, nodeid):
        return None

    def send_node_information(self, nodeid):
        return None

    def replace_failed_node(self, nodeid):
        return None

    def request_network_update(self, nodeid):
        return None

    def replication_send(self, nodeid):
        return None

    def create_button(self, nodeid, buttonid):
        return None

    def delete_button(self, nodeid, buttonid):
        return None

    def request_controller_status(self):
        return None

    @property
    def is_locked(self):
        return None

    def cancel_command(self):
        return None

    def kill_command(self):
        return None

    def to_dict(self, extras=['all']):
        return None

    @deprecated
    def begin_command_send_node_information(self, node_id):
        return None

    @deprecated
    def begin_command_replication_send(self, high_power=False):
        return None

    @deprecated
    def begin_command_request_network_update(self):
        return None

    @deprecated
    def begin_command_add_device(self, high_power=False):
        return None

    @deprecated
    def begin_command_remove_device(self, high_power=False):
        return None

    @deprecated
    def begin_command_remove_failed_node(self, node_id):
        return None

    @deprecated
    def begin_command_has_node_failed(self, node_id):
        return None

    @deprecated
    def begin_command_replace_failed_node(self, node_id):
        return None

    @deprecated
    def begin_command_request_node_neigbhor_update(self, node_id):
        return None

    @deprecated
    def begin_command_create_new_primary(self):
        return None

    @deprecated
    def begin_command_transfer_primary_role(self, high_power=False):
        return None

    @deprecated
    def begin_command_receive_configuration(self):
        return None

    @deprecated
    def begin_command_assign_return_route(self, from_node_id, to_node_id):
        return None

    @deprecated
    def begin_command_delete_all_return_routes(self, node_id):
        return None

    @deprecated
    def begin_command_create_button(self, node_id, arg=0):
        return None

    @deprecated
    def begin_command_delete_button(self, node_id, arg=0):
        return None

    @deprecated
    def zwcallback(self, args):
        pass
