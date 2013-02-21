import datetime
from time import mktime
import json


__all__ = ['CountersStorage', 'SessionStorage']


class CountersStorage(object):
    """
    This class represents the storage used to store counters and can be used to configure storage parameters.

    :param storage_client: Object used to actually access the storage.

        At a minimum, the storage should have two methods, ``get(key)`` and ``set(key, value)``,
        where both ``key`` and ``value`` are strings.

        A typical example is an :class:`memcache.Client` instance.
    :type storage_client: :class:`object`

    :param config: A dictionary containing storage parameters (dictionary keys are the parameter name
        and dictionary values are the parameter value).
        Allows defining the format of the storage keys, and the expiration times for each type of counter.

        You can ommit the whole dictionary or some of its keys as the values
        for the missing keys will be taken from the default configuration.

            *Structure*:

            +------------------------------+----------------------------------+----------------------------------------------------------------------------------------------------+
            | Key                          | Type                             | Description                                                                                        |
            +==============================+==================================+====================================================================================================+
            | ``keys_prefix``              | *string*                         | Prefix for all storage keys.                                                                       |
            +------------------------------+----------------------------------+----------------------------------------------------------------------------------------------------+
            | ``counter_keys_formats``     | *dictionary with string values*  | Formats for each type of counter.                                                                  |
            +------------------------------+----------------------------------+----------------------------------------------------------------------------------------------------+
            | ``total_format``             | *string*                         | Total format of the storage keys, including the prefix,                                            |
            |                              |                                  | the context and the specific counter key.                                                          |
            +------------------------------+----------------------------------+----------------------------------------------------------------------------------------------------+
            | ``expiration_times``         | *dictionary with integer values* | Expiration time for each type of counter, in seconds.                                              |
            |                              |                                  |                                                                                                    |
            +------------------------------+----------------------------------+----------------------------------------------------------------------------------------------------+

            *Default configuration*::

                {
                    'keys_prefix': '',
                    'counter_keys_formats': {
                        'ip': 'ip:{ip}',
                        'user': 'user:{user}',
                        'pwd': 'pwd:{pwd}',
                        'ip_user': 'ip_user:{ip}{user}',
                        'ip_pwd': 'ip_pwd:{ip}{pwd}',
                    },
                    'total_format': '{keys_prefix}:{ctx}:{counter_key}',
                    'expiration_times': {
                        'ip': 3600,
                        'user': 3 * 3600,
                        'pwd': 3 * 3600,
                        'ip_user': 3 * 3600,
                        'ip_pwd': 3 * 3600,
                    },
                }

    :type config: :class:`dict`

    """

    DEFAULT_CONFIG = {
        'keys_prefix': '',
        'counter_keys_formats': {
            'ip': 'ip:{ip}',
            'user': 'user:{user}',
            'pwd': 'pwd:{pwd}',
            'ip_user': 'ip_user:{ip}{user}',
            'ip_pwd': 'ip_pwd:{ip}{pwd}',
        },
        'total_format': '{keys_prefix}:{ctx}:{counter_key}',
        'expiration_times': {
            'ip': 3600,
            'user': 3 * 3600,
            'pwd': 3 * 3600,
            'ip_user': 3 * 3600,
            'ip_pwd': 3 * 3600,
        },
    }

    def __init__(self, storage_client, config=None):
        self.storage_client = storage_client
        if not config:
            config = {}
        self.keys_prefix = config.get('keys_prefix', self.DEFAULT_CONFIG['keys_prefix'])
        self.counter_keys_formats = config.get('counter_keys_formats', self.DEFAULT_CONFIG['counter_keys_formats'])
        self.total_format = config.get('total_format', self.DEFAULT_CONFIG['total_format'])
        self.expiration_times = config.get('expiration_times', self.DEFAULT_CONFIG['expiration_times'])

    def get_storage_keys(self, ip, user=None, pwd=None, ctx=None):
        storage_keys = {}
        if ctx is None:
            ctx = ''

        def get_storage_key(counter_key):
            return self.total_format.format(keys_prefix=self.keys_prefix, ctx=ctx, counter_key=counter_key)

        storage_keys['ip'] = get_storage_key(self.counter_keys_formats['ip'].format(ip=ip))
        if user:
            storage_keys['user'] = get_storage_key(self.counter_keys_formats['user'].format(user=user))
            storage_keys['ip_user'] = get_storage_key(self.counter_keys_formats['ip_user'].format(ip=ip, user=user))
        if pwd:
            storage_keys['pwd'] = get_storage_key(self.counter_keys_formats['pwd'].format(pwd=pwd))
            storage_keys['ip_pwd'] = get_storage_key(self.counter_keys_formats['ip_pwd'].format(ip=ip, pwd=pwd))
        return storage_keys

    def get(self, ip, user=None, pwd=None, ctx=None):
        storage_keys = self.get_storage_keys(ip, user, pwd, ctx)

        counters = Counters()
        for counter_name, storage_key in storage_keys.iteritems():
            counter_serialized = self.storage_client.get(storage_key)
            if counter_serialized is not None:
                counters[counter_name] = Counter.deserialize(counter_serialized)
            else:
                counters[counter_name] = Counter()
        return counters

    def set(self, ip, user, pwd, counters, ctx=None):
        storage_keys = self.get_storage_keys(ip, user, pwd, ctx)

        for counter_name, storage_key in storage_keys.iteritems():
            counter_serialized = Counter.serialize(counters[counter_name])
            self.storage_client.set(storage_key, counter_serialized, self.expiration_times[counter_name])


class Counters(dict):
    def __init__(self, *args, **kwargs):
        super(Counters, self).__init__(*args, **kwargs)

    def get_info(self):
        return (self._get_block_info() or
                self._get_captcha_info() or
                {'state': 'ok'})

    def _get_block_info(self):
        now_timestamp = int(mktime(datetime.datetime.now().timetuple()))
        blocked = False
        # Maximum of all block times
        max_unblock_timestamp = 0
        for counter in self.itervalues():
            if counter.state == 'block':
                unblock_timestamp = counter.attributes['unblock_timestamp']
                if unblock_timestamp > now_timestamp:
                    blocked = True
                    max_unblock_timestamp = max(unblock_timestamp, max_unblock_timestamp)
        if blocked:
            return {'state': 'block', 'unblock_timestamp': max_unblock_timestamp}
        return None

    def _get_captcha_info(self):
        for counter in self.itervalues():
            if counter.state == 'captcha':
                return {'state': 'captcha'}
        return None


class Counter(object):
    def __init__(self, value=0, state='ok', attributes=None):
        self.value = value
        self.state = state
        if not attributes:
            attributes = {}
        self.attributes = attributes

    def __repr__(self):
        return Counter.serialize(self)

    @staticmethod
    def serialize(counter):
        counter_as_dict = {'value': counter.value, 'state': counter.state, 'attributes': counter.attributes}
        return json.dumps(counter_as_dict)

    @staticmethod
    def deserialize(counter_serialized):
        counter_as_dict = json.loads(counter_serialized)
        return Counter(counter_as_dict['value'], counter_as_dict['state'], counter_as_dict['attributes'])


class SessionStorage(object):
    """
    This class represents the storage used to store the throttling session and can be used to configure storage parameters.

    :param storage_client: Object used to actually access the storage.

        At a minimum, the storage should have two methods, ``get(key)`` and ``set(key, value)``,
        where both ``key`` and ``value`` are strings.

        A typical example is an :class:`memcache.Client` instance.
    :type storage_client: :class:`object`

    :param config: A dictionary containing storage parameters (dictionary keys are the parameter name
        and dictionary values are the parameter value).
        Allows defining the format of the storage key, and its expiration time.

        You can ommit the whole dictionary or some of its keys as the values
        for the missing keys will be taken from the default configuration.

            *Structure*:

            +------------------------+-----------+-------------------------------------------------------+
            | Key                    | Type      | Description                                           |
            +========================+===========+=======================================================+
            | ``key_prefix``         | *string*  | Prefix for all storage keys.                          |
            +------------------------+-----------+-------------------------------------------------------+
            | ``session_key_format`` | *string*  | Format of the storage key.                            |
            +------------------------+-----------+-------------------------------------------------------+
            | ``total_format``       | *string*  | Total format of the storage key, including the prefix |
            |                        |           | and the session storage key.                          |
            +------------------------+-----------+-------------------------------------------------------+
            | ``expiration_time``    | *integer* | Expiration time for the session, in seconds.          |
            |                        |           |                                                       |
            +------------------------+-----------+-------------------------------------------------------+

            *Default configuration*::

                {
                    'key_prefix': '',
                    'session_key_format': 'throttling_session:{session_id}',
                    'total_format': '{key_prefix}:{session_key}',
                    'expiration_time': 3600 * 24 * 30,  # one month
                }
    :type config: :class:`dict`
    """

    DEFAULT_CONFIG = {
        'key_prefix': '',
        'session_key_format': 'throttling_session:{session_id}',
        'total_format': '{key_prefix}:{session_key}',
        'expiration_time': 3600 * 24 * 30,  # one month
    }

    def __init__(self, storage_client, config=None):
        self.storage_client = storage_client
        if not config:
            config = {}
        self.key_prefix = config.get('key_prefix', self.DEFAULT_CONFIG['key_prefix'])
        self.session_key_format = config.get('session_key_format', self.DEFAULT_CONFIG['session_key_format'])
        self.total_format = config.get('total_format', self.DEFAULT_CONFIG['total_format'])
        self.expiration_time = config.get('expiration_time', self.DEFAULT_CONFIG['expiration_time'])

    def get_storage_key(self, session_id):
        session_key = self.session_key_format.format(session_id=session_id)
        return self.total_format.format(key_prefix=self.key_prefix, session_key=session_key)

    def get(self, session_id):
        if not session_id:
            return None
        storage_key = self.get_storage_key(session_id)
        session_serialized = self.storage_client.get(storage_key)
        if session_serialized is not None:
            return Session.deserialize(session_serialized)
        return None

    def set(self, session_id, session):
        storage_key = self.get_storage_key(session_id)
        session_serialized = Session.serialize(session)
        self.storage_client.set(storage_key, session_serialized, self.expiration_time)


class Session(object):

    def __init__(self, previous_logins=None):
        if not previous_logins:
            previous_logins = {}
        self.previous_logins = previous_logins

    def has_valid_login(self, user):
        return user in self.previous_logins

    def add_valid_login(self, user):
        self.previous_logins[user] = 0

    def remove_valid_login(self, user):
        if self.has_valid_login(user):
            del self.previous_logins[user]

    def add_failed_attempt(self, user):
        self.previous_logins[user] += 1
        return self.previous_logins[user]

    @staticmethod
    def serialize(session):
        session_as_dict = {'previous_logins': session.previous_logins}
        return json.dumps(session_as_dict)

    @staticmethod
    def deserialize(session_serialized):
        session_as_dict = json.loads(session_serialized)
        return Session(session_as_dict['previous_logins'])
