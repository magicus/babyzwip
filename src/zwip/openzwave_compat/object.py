"""
Compatibility layer with python-openzwave
"""

def deprecated(func):
    def new_func(*args, **kwargs):
        return func(*args, **kwargs)
    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    new_func.__dict__.update(func.__dict__)
    return new_func

class ZWaveException(Exception):
    def __init__(self, value):
        Exception.__init__(self)
        self.value = value


class ZWaveCacheException(ZWaveException):
    def __init__(self, value):
        ZWaveException.__init__(self, value)

class ZWaveTypeException(ZWaveException):
    def __init__(self, value):
        ZWaveException.__init__(self, value)

class ZWaveCommandClassException(ZWaveException):
    def __init__(self, value):
        ZWaveException.__init__(self, value)

class ZWaveObject(object):

    def __init__(self, object_id, network=None, use_cache=True):
        self._object_id = object_id
        self._network = network
        self._use_cache = use_cache

    @property
    def home_id(self):
        return None

    @property
    def network(self):
        return self._network

    @property
    def use_cache(self):
        return self._use_cache

    @property
    def last_update(self):
        return None

    @last_update.setter
    def last_update(self, value):
        pass

    @property
    def outdated(self):
        return None

    @outdated.setter
    def outdated(self, value):
        pass

    def is_outdated(self, prop):
        return None

    def outdate(self, prop):
        pass

    def update(self, prop):
        pass

    def cache_property(self, prop):
        pass

    @property
    def object_id(self):
        return self._object_id

    @property
    def kvals(self):
        return None

    @kvals.setter
    def kvals(self, kvs):
        return None

class ZWaveNodeInterface(object):

    def __init__(self):
        pass
