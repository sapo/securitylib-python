from securitylib.crypto import *
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message, with_setup


def test_generate_authenticator():
    assert generate_authenticator('KJxyKJaV06', bytearray.fromhex('5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1')) == bytearray.fromhex('aee1a8fc5443bbaf982b074c755b4e4faee028cc54ecb83868ec3e1a64f45e6f')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', generate_authenticator, 'KJxyKJaV06', bytes('cf9021efdfec6a4e3fd8', 'utf8').hex())


def test_validate_authenticator():
    assert validate_authenticator('KJxyKJaV06', bytearray.fromhex('5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'), bytearray.fromhex('aee1a8fc5443bbaf982b074c755b4e4faee028cc54ecb83868ec3e1a64f45e6f'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', validate_authenticator, 'KJxyKJaV06', 'cf9021efdfec6a4e3fd8', '')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_encryption_key():
    assert generate_encryption_key() == bytearray.fromhex('9a45076e45211648b857327311a73c1b')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_authenticator_key():
    assert generate_authenticator_key() == bytearray.fromhex('bdb4b6e8d792e4c973c0039c8d4f59a79a45076e45211648b857327311a73c1b')


def test_generate_encryption_key_from_password():
    assert generate_encryption_key_from_password('password', 'salt') == bytearray.fromhex('5c3d0b075ebf4e11b346cf18512e8dda')


def test_generate_authenticator_key_from_password():
    assert generate_authenticator_key_from_password('password', 'salt') == bytearray.fromhex('5c3d0b075ebf4e11b346cf18512e8ddaf29f70d67e67a94e6defe076d461e042')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_encrypt():
    assert (encrypt(b'The quick brown fox was not quick enough and is now an UNFOX!', bytearray.fromhex('aa79a8ab43636644d77f2b6b34842b98'), bytearray.fromhex('61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')) ==
            bytearray.fromhex('0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1'))
    assert_raises_with_message(ValueError, 'Parameter key must have length 16 bytes.', encrypt, '', bytearray.fromhex('ababab'), bytearray.fromhex('abcdef'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', encrypt, '', bytearray.fromhex('aa79a8ab43636644d77f2b6b34842b98'), bytearray.fromhex('abcdef'))


def test_decrypt():
    assert decrypt(bytearray.fromhex('0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1'),
            bytearray.fromhex('aa79a8ab43636644d77f2b6b34842b98'), bytearray.fromhex('61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')) == b'The quick brown fox was not quick enough and is now an UNFOX!'
    assert_raises_with_message(ValueError, 'Parameter key must have length 16 bytes.', decrypt, '', bytes('ababab', 'utf8').hex(), bytes('abcdef', 'utf8').hex())
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', decrypt, '', bytearray.fromhex('aa79a8ab43636644d77f2b6b34842b98'), bytes('abcdef', 'utf8').hex())
