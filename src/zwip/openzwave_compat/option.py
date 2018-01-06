"""
Compatibility layer with python-openzwave
"""

from zwip.openzwave_compat.singleton import Singleton

class ZWaveOption(object):
    def __init__(self, device=None, config_path=None, user_path=None, cmd_line=None):
        self._device = device
        self._config_path = config_path
        self._user_path = user_path

    def set_log_file(self, logfile):
        return None

    def set_logging(self, status):
        return None

    def set_append_log_file(self, status):
        return None

    def set_console_output(self, status):
        return None

    def set_save_log_level(self, level):
        return None

    def set_queue_log_level(self, level):
        return None

    def set_dump_trigger_level(self, level):
        return None

    def set_associate(self, status):
        return None

    def set_exclude(self, commandClass):
        return None

    def set_include(self, commandClass):
        return None

    def set_notify_transactions(self, status):
        return None

    def set_interface(self, port):
        return None

    def set_save_configuration(self, status):
        return None

    def set_driver_max_attempts(self, attempts):
        return None

    def set_poll_interval(self, interval):
        return None

    def set_interval_between_polls(self, status):
        return None

    def set_suppress_value_refresh(self, status):
        return None

    def set_security_strategy(self, strategy='SUPPORTED'):
        return None

    def set_custom_secured_cc(self, custom_cc='0x62,0x4c,0x63'):
        return None

    @property
    def device(self):
        return self._device

    @property
    def config_path(self):
        return self._config_path

    @property
    def user_path(self):
        return self._user_path


class ZWaveOptionSingleton(ZWaveOption):
    __metaclass__ = Singleton
