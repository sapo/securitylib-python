from securitylib.random import *
from securitylib.random import random
from nose.tools import eq_, with_setup
from random import SystemRandom
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message


def test_system_random():
    eq_(type(random), SystemRandom)


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_integer():
    eq_(get_random_integer(), 4519)
    eq_(get_random_integer(1234, 1234), 1234)
    eq_(get_random_integer(100, 200), 155)
    eq_(get_random_integer(0, 4294967296), 3616728280)


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_token():
    eq_(get_random_token(), '8d4f59a79a45076e45211648b857327311a73c1b')
    eq_(get_random_token(1), '9c')
    eq_(get_random_token(100), 'ef9ea9a426f72223552f72d1f78689f28374d310558d5123'\
            '5765df717eb92bc2d24128abc9c4775a119f0d264ffa79cdd778e6af4d8054f2e65be7d0c96b9c5a'\
            '41c7a968c96fd93fe96edc2121191bc574810c8cf928290b50bdb4b6e8d792e4c973c003')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_boolean():
    eq_(get_random_boolean(), False)
    eq_(get_random_boolean(), True)
    eq_(get_random_boolean(), False)
    eq_(get_random_boolean(), True)
    eq_(get_random_boolean(), True)


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_string():
    eq_(get_random_string(10), 'eqI0jgBAF8')
    eq_(get_random_string(10), 'VSIG7MLvah')
    eq_(get_random_string(20), 'dxyg4sj8W0Z0YaVewWU1')
    eq_(get_random_string(100), '2vVdNkKVX4DWanNePuNsH9NdiFUwxeu5gV4qF67yZpcruo9k71e48'\
            'ixZvgHcozYoBXIy4DZfpB7t4qYYgBmZB38SQOdUfLPXiFQn')
    eq_(get_random_string(100, charset='0123456789'), '4851602692358116196796338914255'\
            '293938066618853608843555587989316342565398784424491233303475538091072')
    assert_raises_with_message(ValueError, 'Parameter length must be at least 1.', get_random_string, 0)
    assert_raises_with_message(ValueError, 'Parameter charset must have length at least 2.', get_random_string, 100, charset='a')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_filename():
    eq_(get_random_filename(), 'cjt4fdpps910')
    eq_(get_random_filename(20), 'ts8wvmaecnod7kf92434')
    eq_(get_random_filename(20, 'xpto'), '3a1cn2155m1cwgv126r2.xpto')
    eq_(get_random_filename(100, 'txt', charset='abc'), 'aabacababcbaabcbbaacaccabccbc'\
            'aaabacaccaccabcbabaabcabcbbcbcaabcacaccabacbccccbacabbcabcabcbacaabcabb.txt')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_get_random_GUID():
    eq_(get_random_GUID(), '9A45076E-4521-1648-B857-327311A73C1B')
    eq_(get_random_GUID(), 'BDB4B6E8-D792-E4C9-73C0-039C8D4F59A7')
