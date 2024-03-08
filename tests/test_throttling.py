from securitylib import throttling
from securitylib.random_utils import get_random_token
from securitylib.crypto import generate_authenticator_key
from test_utils import setup_fake_datetime, teardown_fake_datetime, fake_sleep
import mockcache
import unittest
import json


### TESTS ###

class TestThrottling(unittest.TestCase):

    def setUp(self):
        storage_client = mockcache.Client(["127.0.0.1:11211"])
        config = {'authenticator_key': generate_authenticator_key()}
        self.counters_storage = throttling.CountersStorage(storage_client, config)
        self.session_storage = throttling.SessionStorage(storage_client)

        # client
        self.state_checker = throttling.StateChecker(self.counters_storage, self.session_storage)

        # server
        self.state_updater = throttling.StateUpdater(self.counters_storage, self.session_storage)
        setup_fake_datetime()

    def tearDown(self):
        teardown_fake_datetime()

    ### HELPER METHODS"""

    def _test_response(self, response, ip, user=None, pwd=None, ctx=None, session_id=None,
            expected_state='ok', expected_throttling_session=False):
        assert response['state'] == expected_state
        if expected_state == 'block':
            assert 'unblock_timestamp' in response
        throttling_session = self.session_storage.get(session_id)
        assert (throttling_session is not None) == expected_throttling_session

    def _test_login_attempt(self, ip=None, user=None, pwd=None, ctx=None, expected_state_before='ok', expected_state_after='ok', success=False, use_session=True):
        # test login attempt with ip, user and pwd
        # some of these parameters might be fixed and the rest are generated randomly
        if ip is None:
            ip = get_random_token()
        if user is None:
            user = get_random_token()
        if pwd is None:
            pwd = get_random_token()
        session_id = 'ef0c812b00128a8255613efdb1cde34052d450d1' if use_session else None
        response = self.state_checker.check_state(ip, user, pwd, session_id, ctx=ctx)
        self._test_response(response, ip, user, pwd, expected_state=expected_state_before, ctx=ctx)
        self.state_updater.add_request(ip, user, pwd, session_id, ctx=ctx, success=success)
        response = self.state_checker.check_state(ip, user, pwd, session_id, ctx=ctx)
        self._test_response(response, ip, user, pwd, expected_state=expected_state_after, ctx=ctx)

    def _test_request_attempt(self, ip, expected_state_before='ok', expected_state_after='ok', success=False, use_session=True):
        # test simple request attempt with only ip
        response = self.state_checker.check_state(ip)
        self._test_response(response, ip, expected_state=expected_state_before)
        self.state_updater.add_request(ip, success=success)
        response = self.state_checker.check_state(ip)
        self._test_response(response, ip, expected_state=expected_state_after)

    def _test_throttling_by_generic(self, key, fixed_ip=False, fixed_user=False, fixed_pwd=False):
        ip = get_random_token() if fixed_ip else None
        user = get_random_token() if fixed_user else None
        pwd = get_random_token() if fixed_pwd else None
        captcha_limit = self.state_updater.DEFAULT_CONFIG['limits']['captcha'][key]
        block_limit = self.state_updater.DEFAULT_CONFIG['limits']['block'][key]

        for i in range(captcha_limit - 1):
            self._test_login_attempt(ip=ip, user=user, pwd=pwd)

        self._test_login_attempt(ip=ip, user=user, pwd=pwd, expected_state_after='captcha')

        if not block_limit:
            for i in range(200):
                self._test_login_attempt(ip=ip, user=user, pwd=pwd, expected_state_before='captcha', expected_state_after='captcha')
        else:
            for i in range(block_limit - captcha_limit - 1):
                self._test_login_attempt(ip=ip, user=user, pwd=pwd, expected_state_before='captcha', expected_state_after='captcha')
            self._test_login_attempt(ip=ip, user=user, pwd=pwd, expected_state_before='captcha', expected_state_after='block')
            for i in range(10):
                self._test_login_attempt(ip=ip, user=user, pwd=pwd, expected_state_before='block', expected_state_after='block')

    def _test_expiration_time_counter_generic(self, key, fixed_ip=False, fixed_user=False, fixed_pwd=False):
        ip = get_random_token() if fixed_ip else None
        user = get_random_token() if fixed_user else None
        pwd = get_random_token() if fixed_pwd else None
        captcha_limit = self.state_updater.DEFAULT_CONFIG['limits']['captcha'][key]
        expiration_time = self.counters_storage.DEFAULT_CONFIG['expiration_times'][key]

        for i in range(captcha_limit - 1):
            self._test_login_attempt(ip=ip, user=user, pwd=pwd)

        self._test_login_attempt(ip=ip, user=user, pwd=pwd, expected_state_after='captcha')

        response = self.state_checker.check_state(ip=ip, user=user, pwd=pwd)
        self._test_response(response, ip=ip, user=user, pwd=pwd, expected_state='captcha')

        fake_sleep(expiration_time)

        response = self.state_checker.check_state(ip=ip, user=user, pwd=pwd)
        self._test_response(response, ip=ip, user=user, pwd=pwd, expected_state='captcha')

        fake_sleep(0.01)

        response = self.state_checker.check_state(ip=ip, user=user, pwd=pwd)
        self._test_response(response, ip=ip, user=user, pwd=pwd)

    ### ACTUAL TESTS ###

    def test_throttling_by_ip_heavily_commented(self):
        ip = get_random_token()
        session_id = None

        # assume user requests the login page
        response = self.state_checker.check_state(ip)
        self._test_response(response, ip)
        # show login page
        # set session_id as soon as possible
        session_id = 'ef0c812b00128a8255613efdb1cde34052d450d1'

        for i in range(19):
            user = get_random_token()
            pwd = get_random_token()
            # assume user attempts to login
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd)
            # assume invalid credentials
            self.state_updater.add_request(ip, user, pwd, session_id, success=False)
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd)
            # show login page

        user = get_random_token()
        pwd = get_random_token()
        # assume user attempts to login
        response = self.state_checker.check_state(ip, user, pwd, session_id)
        self._test_response(response, ip, user, pwd)
        self.state_updater.add_request(ip, user, pwd, session_id, success=False)
        # assume invalid credentials
        response = self.state_checker.check_state(ip, user, pwd, session_id)
        self._test_response(response, ip, user, pwd, expected_state='captcha')
        # show login page with captcha

        for i in range(79):
            user = get_random_token()
            pwd = get_random_token()
            # assume user attempts to login
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd, expected_state='captcha')
            # assume correct captcha
            self.state_updater.add_request(ip, user, pwd, session_id, success=False)
            # assume invalid credentials
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd, expected_state='captcha')
            # show login page with captcha

        user = get_random_token()
        pwd = get_random_token()
        # assume user attempts to login
        response = self.state_checker.check_state(ip, user, pwd, session_id)
        self._test_response(response, ip, user, pwd, expected_state='captcha')
        # assume correct captcha
        self.state_updater.add_request(ip, user, pwd, session_id, success=False)
        # assume invalid credentials
        response = self.state_checker.check_state(ip, user, pwd, session_id)
        self._test_response(response, ip, user, pwd, expected_state='block')
        # show login page with blocked message

        user = get_random_token()
        pwd = get_random_token()
        # assume user attempts to login
        response = self.state_checker.check_state(ip, user, pwd, session_id)
        self._test_response(response, ip, user, pwd, expected_state='block')
        # assume correct captcha
        # cannot proceed, show login page with blocked message

    def test_throttling_by_ip(self):
        self._test_throttling_by_generic('ip', fixed_ip=True)

    def test_throttling_by_user(self):
        self._test_throttling_by_generic('user', fixed_user=True)

    def test_throttling_by_pwd(self):
        self._test_throttling_by_generic('pwd', fixed_pwd=True)

    def test_throttling_by_ip_user(self):
        self._test_throttling_by_generic('ip_user', fixed_ip=True, fixed_user=True)

    def test_throttling_by_ip_pwd(self):
        self._test_throttling_by_generic('ip_pwd', fixed_ip=True, fixed_pwd=True)

    def test_counters_cleaning(self):
        ip = get_random_token()
        user = get_random_token()
        captcha_limit = self.state_updater.DEFAULT_CONFIG['limits']['captcha']['ip_user']

        for i in range(captcha_limit - 1):
            self._test_login_attempt(ip=ip, user=user, use_session=False)

        self._test_login_attempt(ip=ip, user=user, use_session=False, expected_state_after='captcha')

        counters = self.counters_storage.get(ip, user)
        assert counters['ip_user'].value == 3
        assert counters['ip'].value == 3
        assert counters['user'].value == 1

        self._test_login_attempt(ip=ip, user=user, success=True, use_session=False, expected_state_before='captcha')

        counters = self.counters_storage.get(ip, user)
        assert counters['ip_user'].value == 0
        assert counters['ip'].value == 3
        assert counters['user'].value == 1

        self._test_login_attempt(ip=ip, user=user, use_session=False)

        counters = self.counters_storage.get(ip, user)
        assert counters['ip_user'].value == 1
        assert counters['ip'].value == 4
        # Weird behaviour. User is counted twice due to counter ip_user having been cleared.
        # Still, wouldn't happen if the session was being used since the user
        # would have a free pass and wouldn't update the counters.
        assert counters['user'].value == 2

    def test_free_pass(self):
        user = get_random_token()
        captcha_limit = self.state_updater.DEFAULT_CONFIG['limits']['captcha']['user']
        free_pass_limit = self.state_updater.FREE_PASS_LIMIT

        for i in range(captcha_limit - 1):
            self._test_login_attempt(user=user)

        self._test_login_attempt(user=user, expected_state_after='captcha')

        self._test_login_attempt(user=user, success=True, expected_state_before='captcha')

        for i in range(100):
            self._test_login_attempt(user=user, success=True)

        for i in range(free_pass_limit - 1):
            self._test_login_attempt(user=user, success=False)

        self._test_login_attempt(user=user, success=False, expected_state_after='captcha')

        self._test_login_attempt(user=user, success=True, expected_state_before='captcha')

        for i in range(100):
            self._test_login_attempt(user=user, success=True)

        for i in range(100):
            self._test_login_attempt(user=user, success=True, use_session=False, expected_state_before='captcha', expected_state_after='captcha')

        for i in range(100):
            self._test_login_attempt(user=user, success=True)

    def test_exponential_block_times(self):
        ip = '123.123.123.123'
        session_id = 'ef0c812b00128a8255613efdb1cde34052d450d1'
        initial_blocking_time = self.state_updater.DEFAULT_CONFIG['initial_blocking_time']

        # tests start here
        for i in range(100):
            user = get_random_token()
            pwd = get_random_token()
            # assume user attempts to login
            # assume invalid credentials
            self.state_updater.add_request(ip, user, pwd, session_id, success=False)
            # show login page, possibly with captcha

        def test_still_blocked():
            user = get_random_token()
            pwd = get_random_token()
            # assume user attempts to login
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd, expected_state='block')
            # cannot proceed, show login page with blocked message

        def test_unblocked():
            user = get_random_token()
            pwd = get_random_token()
            # assume user attempts to login
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd)
            # block has expired, proceed to evaluate credentials
            # assume invalid credentials
            self.state_updater.add_request(ip, user, pwd, session_id, success=False)
            response = self.state_checker.check_state(ip, user, pwd, session_id)
            self._test_response(response, ip, user, pwd, expected_state='block')
            # show login page with blocked message

        def test_blocked_during_time(seconds):
            now = 0
            while now < seconds:
                test_still_blocked()
                fake_sleep(0.5)
                now += 0.5

        test_blocked_during_time(initial_blocking_time)
        test_unblocked()
        test_blocked_during_time(initial_blocking_time * 2)
        test_unblocked()
        test_blocked_during_time(initial_blocking_time * 4)
        test_unblocked()
        test_blocked_during_time(initial_blocking_time * 8)
        test_unblocked()

    def test_expiration_time_counter_ip(self):
        self._test_expiration_time_counter_generic('ip', fixed_ip=True)

    def test_expiration_time_counter_user(self):
        self._test_expiration_time_counter_generic('user', fixed_user=True)

    def test_expiration_time_counter_pwd(self):
        self._test_expiration_time_counter_generic('pwd', fixed_pwd=True)

    def test_expiration_time_counter_ip_user(self):
        self._test_expiration_time_counter_generic('ip_user', fixed_ip=True, fixed_user=True)

    def test_expiration_time_counter_ip_pwd(self):
        self._test_expiration_time_counter_generic('ip_pwd', fixed_ip=True, fixed_pwd=True)

    def test_expiration_time_session(self):
        user = get_random_token()
        session_id = 'ef0c812b00128a8255613efdb1cde34052d450d1'
        expiration_time = self.session_storage.DEFAULT_CONFIG['expiration_time']

        self._test_login_attempt(user=user, success=True)

        throttling_session = self.session_storage.get(session_id)
        assert throttling_session.has_valid_login(user)

        fake_sleep(expiration_time)

        throttling_session = self.session_storage.get(session_id)
        assert throttling_session.has_valid_login(user)

        fake_sleep(0.01)

        throttling_session = self.session_storage.get(session_id)
        assert throttling_session is None

    def test_updating_counters_if_using_only_ip(self):
        ip = get_random_token()
        captcha_limit = self.state_updater.DEFAULT_CONFIG['limits']['captcha']['ip']
        block_limit = self.state_updater.DEFAULT_CONFIG['limits']['block']['ip']

        for i in range(captcha_limit - 1):
            self._test_request_attempt(ip=ip)

        self._test_request_attempt(ip=ip, expected_state_after='captcha')

        if not block_limit:
            for i in range(200):
                self._test_request_attempt(ip=ip, expected_state_before='captcha', expected_state_after='captcha')
        else:
            for i in range(block_limit - captcha_limit - 1):
                self._test_request_attempt(ip=ip, expected_state_before='captcha', expected_state_after='captcha')
            self._test_request_attempt(ip=ip, expected_state_before='captcha', expected_state_after='block')
            for i in range(10):
                self._test_request_attempt(ip=ip, expected_state_before='block', expected_state_after='block')

    def test_multiple_contexts(self):
        ip = get_random_token()
        captcha_limit = self.state_updater.DEFAULT_CONFIG['limits']['captcha']['ip']
        block_limit = self.state_updater.DEFAULT_CONFIG['limits']['block']['ip']

        # Context 1
        for i in range(captcha_limit - 1):
            self._test_login_attempt(ip=ip, ctx='1')

        self._test_login_attempt(ip=ip, ctx='1', expected_state_after='captcha')

        # Context 2
        for i in range(captcha_limit - 1):
            self._test_login_attempt(ip=ip, ctx='2')

        self._test_login_attempt(ip=ip, ctx='2', expected_state_after='captcha')

        # Context 1
        for i in range(block_limit - captcha_limit - 1):
            self._test_login_attempt(ip=ip, ctx='1', expected_state_before='captcha', expected_state_after='captcha')
        self._test_login_attempt(ip=ip, ctx='1', expected_state_before='captcha', expected_state_after='block')
        for i in range(10):
            self._test_login_attempt(ip=ip, ctx='1', expected_state_before='block', expected_state_after='block')

        # Context 2
        for i in range(block_limit - captcha_limit - 1):
            self._test_login_attempt(ip=ip, ctx='2', expected_state_before='captcha', expected_state_after='captcha')
        self._test_login_attempt(ip=ip, ctx='2', expected_state_before='captcha', expected_state_after='block')
        for i in range(10):
            self._test_login_attempt(ip=ip, ctx='2', expected_state_before='block', expected_state_after='block')

    def test_no_captcha(self):
        self.state_updater.limits = {
            'block': {
                'ip': 100,
            },
        }
        ip = get_random_token()
        block_limit = self.state_updater.limits['block']['ip']

        for i in range(block_limit - 1):
            self._test_login_attempt(ip=ip)
        self._test_login_attempt(ip=ip, expected_state_after='block')
        for i in range(10):
            self._test_login_attempt(ip=ip, expected_state_before='block', expected_state_after='block')

    def test_no_block(self):
        self.state_updater.limits = {
            'captcha': {
                'ip': 20,
            },
        }
        ip = get_random_token()
        captcha_limit = self.state_updater.limits['captcha']['ip']

        for i in range(captcha_limit - 1):
            self._test_login_attempt(ip=ip)
        self._test_login_attempt(ip=ip, expected_state_after='captcha')
        for i in range(100):
            self._test_login_attempt(ip=ip, expected_state_before='captcha', expected_state_after='captcha')


def test_counter_repr():
    counter_dict = {'value': 3, 'state': 'block', 'attributes': {'unblock_timestamp': 9999}}
    counter = throttling.common.Counter(counter_dict['value'], counter_dict['state'], counter_dict['attributes'])
    new_counter_dict = json.loads(repr(counter))
    assert counter_dict == new_counter_dict
