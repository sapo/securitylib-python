from securitylib.crypto import *
from nose.tools import ok_, eq_, with_setup
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message


def test_generate_authenticator():
    eq_(generate_authenticator('KJxyKJaV06', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'.decode('hex')), 'aee1a8fc5443bbaf982b074c755b4e4faee028cc54ecb83868ec3e1a64f45e6f'.decode('hex'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', generate_authenticator, 'KJxyKJaV06', 'cf9021efdfec6a4e3fd8'.encode('hex'))


def test_validate_authenticator():
    ok_(validate_authenticator('KJxyKJaV06', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'.decode('hex'), 'aee1a8fc5443bbaf982b074c755b4e4faee028cc54ecb83868ec3e1a64f45e6f'.decode('hex')))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', validate_authenticator, 'KJxyKJaV06', 'cf9021efdfec6a4e3fd8', '')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_encryption_key():
    eq_(generate_encryption_key(), '9a45076e45211648b857327311a73c1b'.decode('hex'))


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_authenticator_key():
    eq_(generate_authenticator_key(), 'bdb4b6e8d792e4c973c0039c8d4f59a79a45076e45211648b857327311a73c1b'.decode('hex'))


def test_generate_encryption_key_from_password():
    eq_(generate_encryption_key_from_password('password', 'salt'), '5c3d0b075ebf4e11b346cf18512e8dda'.decode('hex'))


def test_generate_authenticator_key_from_password():
    eq_(generate_authenticator_key_from_password('password', 'salt'), '5c3d0b075ebf4e11b346cf18512e8ddaf29f70d67e67a94e6defe076d461e042'.decode('hex'))


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_encrypt():
    eq_(encrypt('The quick brown fox was not quick enough and is now an UNFOX!', 'aa79a8ab43636644d77f2b6b34842b98'.decode('hex'), '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'.decode('hex')),
            '0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1'.decode('hex'))
    assert_raises_with_message(ValueError, 'Parameter key must have length 16 bytes.', encrypt, '', 'ababab'.decode('hex'), 'abcdef'.decode('hex'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', encrypt, '', 'aa79a8ab43636644d77f2b6b34842b98'.decode('hex'), 'abcdef'.decode('hex'))


def test_decrypt():
    eq_(decrypt('0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1'.decode('hex'),
            'aa79a8ab43636644d77f2b6b34842b98'.decode('hex'), '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'.decode('hex')), 'The quick brown fox was not quick enough and is now an UNFOX!')
    assert_raises_with_message(ValueError, 'Parameter key must have length 16 bytes.', decrypt, '', 'ababab'.decode('hex'), 'abcdef'.decode('hex'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', decrypt, '', 'aa79a8ab43636644d77f2b6b34842b98'.decode('hex'), 'abcdef'.decode('hex'))
