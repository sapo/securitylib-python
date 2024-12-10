from random import Random, SystemRandom
from securitylib import random_utils
import functools
import os
import datetime
import re
import pytest

old_urandom = os.urandom
old_datetime = datetime.datetime

RANDOM_BYTES = bytearray.fromhex('10790832727821f6ff615d45d373f27f2a48210f332e1c20c67984387397deb5e\
6fcd0051c2cb3e4dfd9a965d0470d5fdefdd86dcf4548a70cd0d954435c26b9e9e6df3ee8cc28acb6840d78528820b812bf\
9b73f5f8ddaef597fb99712bbb787577af743df7a1813973ded417b0c3a86c8b0d56d6587d383cb3e4f97ade60820bcfaad\
3eaa45854f50be70d658be4982a2556e78f0e699efb044e57ce3187d40f95f19a7079ec64a1cb94323b29396580f87cf6cf\
919d8024175dbd698efb2dd19806ef3c743f226b104b170a23e6b5d5d09ec68a1d0b46641b89151b92158384dc20875a74d\
d2f43a5a470d382957ddbf16b1f6002ec3a8838b2ad215a560d47e8489bfb1ab6a4ebd62911e8cb0a13165c770b114b0f4b\
ce50477fdeedbc78a3de4179f614ec51441d05452a295f1b2f2d114dfc1c3c422081a4563d3f577cc1cc09df55c049eb6f2\
1299a487c1a71976cfdba08bb7c53a896a1ed40604401ddb2ad26d57ce61d8efd34676683a7b68421d75cf425cd5fd0fb83\
56f1ef3f82ad15582a83d57ec9d33bbd2f43171d057676dd45e7f998d1efe09930c48328094c7fb9791b7c627ff391038fe\
ea549c8fe50e96354c325164a40d1bf1164563938666c945fed073124e8e5a25ce2bacb227d3b1abe5c337069bf1bab8408\
b9dbe39ee9ce21d11404140149560deebdab7cd8df19a36ba4e7e5bfcd5cfc22ad776df1da138adf7f4c7d316e3f4aa71d4\
70755819fa14e80ecbb6332e354d55377daa482c8ab6871ca8173b38812b39ea4e7e45cc6a4d7da5df08c8882391ca35039\
5a201a005ab647dc306404c8fbba99b1877bcc7a82ded4b676cea2ea7fdfec6aab919fcce3abfce60dc420c61557f5e054d\
f94968377c02f696fb92c6c4e625ffb44bfa1a17af4014c75c80f195a236f4d2af0c3243f88fdadff8c58e85e558e3967bc\
df98e803e087b54eddd48919f74d53aec1e3c2bdd09e86ffc873359c9bf8f6155e21a291f87f0cfc11d45443d96f439ec3d\
71a31225b47cd01c6ec8f11a6a268cff551b48a73d322d8faafa8fb9c0443d4ca377adf9b8ff7d6bc468d9fd67b28c9098e\
12ffbefcacfb94bbd116b0c834253cc49610ee82f64cc5f64e8f03aaaeeada7cc426eff01f1a5ba43442b12c756520650ae\
cee041a626f44a95cbb9bf3102364f2dccbfbb71d615f874186f4b100234953399226255a5d8dc517a3a5db994d54209bf8\
44309fa92aef9ea9a426f72223552f72d1f78689f28374d310558d51235765df717eb92bc2d24128abc9c4775a119f0d264\
ffa79cdd778e6af4d8054f2e65be7d0c96b9c5a41c7a968c96fd93fe96edc2121191bc574810c8cf928290b50bdb4b6e8d7\
92e4c973c0039c8d4f59a79a45076e45211648b857327311a73c1b')


class URandom(object):
    def __init__(self):
        self.bytes_left = RANDOM_BYTES

    def new_urandom(self, length):
        result = self.bytes_left[-length:]
        self.bytes_left = self.bytes_left[:-length]
        return result


def setup_seeded_random():
    random_utils.random = Random()
    random_utils.random.seed(1311883828)
    os.urandom = URandom().new_urandom


def teardown_seeded_random():
    random_utils.random = SystemRandom()
    os.urandom = old_urandom


def assert_raises_with_message(exception, message, callable, *args, **kwargs):
    with pytest.raises(exception, match=message) as cm:
        callable(*args, **kwargs)
    if len(cm.value.args) > 0:
        arg = cm.value.args[0]
    else:
        arg = b''
    assert arg == message

def assert_raises_with_message_bytes(exception, message, callable, *args, **kwargs):
    with pytest.raises(exception) as cm:
        callable(*args, **kwargs)
    if len(cm.value.args) > 0:
        arg = cm.value.args[0]
    else:
        arg = b''

    assert re.search(message, str(arg))


def with_setup(setup_method, teardown_method):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            setup_method()
            f(*args, **kwargs)
            teardown_method()
        return wrapper
    return decorator

class FakeDatetimeNow(object):
    def __init__(self):
        self.time_passed = 0

    def __call__(self):
        result = datetime.datetime.fromtimestamp(self.time_passed)
        return result

    def advance_time(self, seconds):
        self.time_passed += seconds


class FakeDatetime(datetime.datetime):
    pass


def setup_fake_datetime():
    FakeDatetime.now = FakeDatetimeNow()
    datetime.datetime = FakeDatetime


def teardown_fake_datetime():
    datetime.datetime = old_datetime


def fake_sleep(seconds):
    datetime.datetime.now.advance_time(seconds)
