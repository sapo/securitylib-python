from securitylib.random_utils import *
from securitylib.random_utils import random
from random import SystemRandom
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message, with_setup

import collections
try:
    import collections.abc
except ImportError:
    # Python 3.10+ replaces attribute 'abc' by a module. This is to work with Python < 3.9
    pass

try:
    collections.Callable = collections.abc.Callable
except AttributeError:
    # Python 2.x supports collections.Callable directly
    pass

def test_system_random():
    assert type(random) == SystemRandom


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_integer():
    assert get_random_integer() == 9038
    assert get_random_integer(1234, 1234) == 1234
    assert get_random_integer(100, 200) == 177
    assert get_random_integer(0, 4294967296) == 2370787751


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_token():
    assert get_random_token() == '8d4f59a79a45076e45211648b857327311a73c1b'
    assert get_random_token(1) == '9c'
    assert (get_random_token(100) == 'ef9ea9a426f72223552f72d1f78689f28374d310558d5123'\
            '5765df717eb92bc2d24128abc9c4775a119f0d264ffa79cdd778e6af4d8054f2e65be7d0c96b9c5a'\
            '41c7a968c96fd93fe96edc2121191bc574810c8cf928290b50bdb4b6e8d792e4c973c003')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_boolean():
    assert get_random_boolean() == False
    assert get_random_boolean() == True
    assert get_random_boolean() == False
    assert get_random_boolean() == True
    assert get_random_boolean() == True


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_string():
    assert get_random_string(10) == b'eUrMJC1VkG'
    assert get_random_string(10) == b'gBBXAwGENX'
    assert get_random_string(20) == b'qUzJDHl9NNMMfwoaqh3e'
    assert get_random_string(100) == b'xy7zqgj6JtejfYN1312IZeaiW2exMY0W9343JwWBdaOxllL4X5ZA6TESY3aoo8P5eGQ2vUObsFIB5OFdfi4HAVixjxoesv78gtX7'
    assert get_random_string(100, charset='0123456789') == b'7488684094653222411428645816806362837082607361337715401732711906194622853766912880841338568132725452'
    assert_raises_with_message(ValueError, 'Parameter length must be at least 1.', get_random_string, 0)
    assert_raises_with_message(ValueError, 'Parameter charset must have length at least 2.', get_random_string, 100, charset='a')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_filename():
    assert get_random_filename() == b'er92k6g110w6'
    assert get_random_filename(20) == b'4qz937lfwoaqhexyzqgj'
    assert get_random_filename(20, 'xpto') == b'9tejf8eaiex9w1daxll0.xpto'
    assert get_random_filename(100, 'txt', charset='abc') == b'cbcaaacaccbccabbcbcbaaacbcababaabbabbbcccbcbcacbbbaaaabcaabacbbbcabcababacacbacabababaaabbabcbaabaab.txt'


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_GUID():
    assert get_random_GUID() == b'9A45076E-4521-1648-B857-327311A73C1B'
    assert get_random_GUID() == b'BDB4B6E8-D792-E4C9-73C0-039C8D4F59A7'

    # assert get_random_GUID() == '9A45076E-4521-1648-B857-327311A73C1B'
    # assert get_random_GUID() == 'BDB4B6E8-D792-E4C9-73C0-039C8D4F59A7'
