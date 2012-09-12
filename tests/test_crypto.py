from securitylib.crypto import *
from nose.tools import ok_, eq_, with_setup
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message


def test_generate_authenticator():
    eq_(generate_authenticator('KJxyKJaV06', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'), 'aee1a8fc5443bbaf982b074c755b4e4faee028cc54ecb83868ec3e1a64f45e6f')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', generate_authenticator, 'KJxyKJaV06', 'cf9021efdfec6a4e3fd8')


def test_validate_authenticator():
    ok_(validate_authenticator('KJxyKJaV06', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1', 'aee1a8fc5443bbaf982b074c755b4e4faee028cc54ecb83868ec3e1a64f45e6f'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', validate_authenticator, 'KJxyKJaV06', 'cf9021efdfec6a4e3fd8', '')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_prepare_password_for_storage():
    eq_(prepare_password_for_storage('EmY5uff2OS', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'), '01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96ea')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key is not correct hex.', prepare_password_for_storage, 'EmY5uff2OS', 'This is not hex!')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', prepare_password_for_storage, 'EmY5uff2OS', 'cf9021efdfec6a4e3fd8')


def test_compare_stored_password():
    ok_(compare_stored_password('EmY5uff2OS', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1', '01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96ea'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key is not correct hex.', compare_stored_password, 'EmY5uff2OS', 'This is not hex!', '01b857327311a73c1b2ad7b3322ba9bc2f47b327b68309468a1be93b420367f34e175d3059146efcea')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', compare_stored_password, 'EmY5uff2OS', 'cf9021efdfec6a4e3fd8', '')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_encryption_key():
    eq_(generate_encryption_key(), '9a45076e45211648b857327311a73c1b')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_authenticator_key():
    eq_(generate_authenticator_key(), 'bdb4b6e8d792e4c973c0039c8d4f59a79a45076e45211648b857327311a73c1b')


def test_generate_encryption_key_from_password():
    eq_(generate_encryption_key_from_password('password', 'salt'.encode('hex')), '5c3d0b075ebf4e11b346cf18512e8dda')


def test_generate_authenticator_key_from_password():
    eq_(generate_authenticator_key_from_password('password', 'salt'.encode('hex')), '5c3d0b075ebf4e11b346cf18512e8ddaf29f70d67e67a94e6defe076d461e042')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_encrypt():
    eq_(encrypt('The quick brown fox was not quick enough and is now an UNFOX!', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'),
            '0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key is not correct hex.', encrypt, '', 'aa79a8ab43636644d77f2b6b34842b98', 'This is not hex!')
    assert_raises_with_message(ValueError, 'Parameter key must have length 16 bytes.', encrypt, '', 'ababab', 'abcdef')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', encrypt, '', 'aa79a8ab43636644d77f2b6b34842b98', 'abcdef')


def test_decrypt():
    eq_(decrypt('0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'), 'The quick brown fox was not quick enough and is now an UNFOX!')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key is not correct hex.', decrypt, '', 'aa79a8ab43636644d77f2b6b34842b98', 'This is not hex!')
    assert_raises_with_message(ValueError, 'Parameter key must have length 16 bytes.', decrypt, '', 'ababab', 'abcdef')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', decrypt, '', 'aa79a8ab43636644d77f2b6b34842b98', 'abcdef')
