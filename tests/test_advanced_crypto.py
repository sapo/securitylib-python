from securitylib.advanced_crypto import *
from securitylib.advanced_crypto import pad_pkcs5, unpad_pkcs5
from securitylib.random import get_random_string
from nose.tools import ok_, eq_, with_setup
from timeit import timeit
from hashlib import sha1
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message


def test_hash():
    eq_(hash('KJxyKJaV06'), '2141e801b418f9e0674c2f9e763fdd804b7870d37d3fd7f35847d6752c2b3991')
    eq_(hash('n2nOfM0ySH', length=16), '460bc2745ee86dfd12ad7b0dc722d28e')
    eq_(hash('Rr3PMRiOCb', length=20), '9be4eeba596ac36712643286c315abf659c163e8')
    eq_(hash('caJvfKyUid', length=32), '408c3c737c4d7b2ebbdfe15e69e9945e2d1dfe0d3aacfe1d4c57232686a8b340')
    eq_(hash('X3fXGg8mGP', length=64), '8b0462ce8599d22c106c836cd2b82708676a64cc87e409518e8c0e24920c6535ca8ec209e99894c668c8a685cd5790fd410c43d1e63b2f3c3f1336c57d1e3189')
    eq_(hash('vzWP6drfab', length=32, iterations=10), 'fc51d0355682e7dafe0eda4e8af17cf1fb2497a87d39a56da1bc97e281a810f7')
    eq_(hash('QzEEI5DPD5', length=32, iterations=1000), '832a9e022b899046d36f256d60f02c7b481495e79eb9d3170c94115b04647efd')
    eq_(hash('DemNHA0UuR', length=32, iterations=1, raw_output=True), '\xf1\xcc\xf7\x89\x8e\xd6wa\x8a_\xb8\xeb\xf6\xa6\x8c_\x86{\x00\x7f\xcb\x12\xb3\xf1\x83\xb6\xa4\xda\x00\xadG6')
    eq_(hash('UlDyaLMUg6', length=20, iterations=20, raw_output=True), '|\xa1\xd4\xbb\x1fG\x9d\xfc\x0b\x11\xdc\x7f\xe7C\xf4\xa5\xd6\xe5&"')
    assert_raises_with_message(ValueError, 'The number of iterations cannot be lower than 1.', hash, '', length=32, iterations=0)
    assert_raises_with_message(ValueError, 'You must choose one of the supported sizes: 16, 20, 32 or 64 bytes.', hash, '', length=99)


def test_hmac():
    eq_(hmac('KJxyKJaV06', 'cf9021efdfec6a4e3fd8'), 'e00215a0cbffe24b9a9681a6a7234cf23be6a38f00160fd8cff4b8d6feadb67d')
    eq_(hmac('n2nOfM0ySH', 'cf9021efdfec6a4e3fd8', length=16), '20df35fd7b3d2b7b04bbb0e85f27f51c')
    eq_(hmac('Rr3PMRiOCb', 'cf9021efdfec6a4e3fd8', length=20), '934a4c67558392325d052f9c703c9a21e1c3760b')
    eq_(hmac('caJvfKyUid', 'cf9021efdfec6a4e3fd8', length=32), 'f7277afb9ae303f0814fda725c9464390e0724a25b5d5af1317c89e910b6e50e')
    eq_(hmac('X3fXGg8mGP', 'cf9021efdfec6a4e3fd8', length=64), 'e1ce11fc70fc299b7af301e050785a196bcb9ff9d4eb505b534bf315d7c686c0bc33ec7f319050965b4592061637e0a16df1bf4c6aff3ff300a86235aca6118a')
    eq_(hmac('vzWP6drfab', 'cf9021efdfec6a4e3fd8', length=32, iterations=10), '282659e94f7b2ce3d4a5244a490b3ff93b2a02c13b1d1359d7d27f816115c316')
    eq_(hmac('QzEEI5DPD5', 'cf9021efdfec6a4e3fd8', length=32, iterations=1000), '52d94925edd1870ee6e0c0141767a19d9a00698e64d0f98036bd2c27edcdf8f9')
    eq_(hmac('DemNHA0UuR', 'cf9021efdfec6a4e3fd8', length=32, iterations=1, raw_output=True), '\\1\xaa\xcd8\x8a\x0e\xaaD%|_\xc6\x98t\xd5\x96\xae\xb5\xe5\xb5-\x031\x10\xe9}\x02Z=\xfdA')
    eq_(hmac('UlDyaLMUg6', 'cf9021efdfec6a4e3fd8', length=20, iterations=20, raw_output=True), '\r<\t\xf2\x9b\xee\xb7z\x06^ \xb2\x00\x16\xa3\xfe;\x03k\xd6')
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', hmac, '', 'This is not hex!')
    assert_raises_with_message(ValueError, 'The number of iterations cannot be lower than 1.', hmac, '', '', length=32, iterations=0)
    assert_raises_with_message(ValueError, 'You must choose one of the supported sizes: 16, 20, 32 or 64 bytes.', hmac, '', '', length=99)
    # test generate_authenticator alias
    eq_(generate_authenticator('UlDyaLMUg6', 'cf9021efdfec6a4e3fd8', length=20, iterations=20, raw_output=True), '\r<\t\xf2\x9b\xee\xb7z\x06^ \xb2\x00\x16\xa3\xfe;\x03k\xd6')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key is not correct hex.', generate_authenticator, '', 'This is not hex!')


def test_validate_hmac():
    ok_(validate_hmac('KJxyKJaV06', 'cf9021efdfec6a4e3fd8', 'e00215a0cbffe24b9a9681a6a7234cf23be6a38f00160fd8cff4b8d6feadb67d'))
    # Test comparison to upper case authenticator
    ok_(validate_hmac('KJxyKJaV06', 'cf9021efdfec6a4e3fd8', 'E00215A0CBFFE24B9A9681A6A7234CF23BE6A38F00160FD8CFF4B8D6FEADB67D'))
    ok_(validate_hmac('UlDyaLMUg6', 'cf9021efdfec6a4e3fd8', '0d3c09f29beeb77a065e20b20016a3fe3b036bd6', length=20, iterations=20))
    ok_(not validate_hmac('KJxyKJaV06', 'cf9021efdfec6a4e3fd8', 'e00215a0cbffe24b9a9681a6a7234cf23be6a38f00160fd8cff4b8d6feadb67c'))
    ok_(not validate_hmac('KJxyKJaV06', 'cf9021efdfec6a4e3fd9', 'e00215a0cbffe24b9a9681a6a7234cf23be6a38f00160fd8cff4b8d6feadb67d'))
    ok_(not validate_hmac('KJxyKJaV07', 'cf9021efdfec6a4e3fd8', 'e00215a0cbffe24b9a9681a6a7234cf23be6a38f00160fd8cff4b8d6feadb67d'))
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', validate_hmac, '', 'This is not hex!', '')
    # test validate_authenticator alias
    ok_(validate_authenticator('UlDyaLMUg6', 'cf9021efdfec6a4e3fd8', '0d3c09f29beeb77a065e20b20016a3fe3b036bd6', length=20, iterations=20))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key is not correct hex.', validate_authenticator, '', 'This is not hex!', '')


def test_safe_compare():
    ok_(safe_compare('KJxyKJaV06', 'KJxyKJaV06'))
    ok_(not safe_compare('KJxyKJaV06', 'KJxyKJaV07'))
    ok_(not safe_compare('KJxyKJaV06', 'LJxyKJaV06'))
    ok_(not safe_compare('KJxyKJaV06', 'KJxyKJaV0'))
    strings_size = 10000
    s1 = get_random_string(strings_size)
    s2 = get_random_string(strings_size)
    times = []
    for i in xrange(0, len(s1) + 1, (int)(strings_size / 10)):
        new_s2 = s1[:i] + s2[i:]
        times.append(timeit('safe_compare("{0}", "{1}")'.format(s1, new_s2), 'from securitylib.advanced_crypto import safe_compare', number=100))
    ok_(max(times) / min(times) <= 1.2, 'safe_compare is having a difference in the time taken to compute that is too big: max ({0}) - min ({1})'.format(max(times), min(times)))


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_prepare_password_for_storage():
    eq_(prepare_password_for_storage('EmY5uff2OS', '5fbf0ef570691bd5345b'), '01b857327311a73c1b2ad7b3322ba9bc2f47b327b68309468a1be93b420367f34e175d3059146efcea')
    eq_(prepare_password_for_storage('EmY5uff2OS', '5fbf0ef570691bd5345b'), '019a45076e45211648b5d34f9f4ae490b4f72a14b2304921b4cc88b3bee19751ea6248b294e91ec112')
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', prepare_password_for_storage, 'EmY5uff2OS', 'This is not hex!')


def test_compare_stored_password():
    ok_(compare_stored_password('EmY5uff2OS', '5fbf0ef570691bd5345b', '01b857327311a73c1b2ad7b3322ba9bc2f47b327b68309468a1be93b420367f34e175d3059146efcea'))
    # Test comparison to upper case stored password
    ok_(compare_stored_password('EmY5uff2OS', '5fbf0ef570691bd5345b', '01B857327311A73C1B2AD7B3322BA9BC2F47B327B68309468A1BE93B420367F34E175D3059146EFCEA'))
    ok_(compare_stored_password('EmY5uff2OS', '5fbf0ef570691bd5345b', '019a45076e45211648b5d34f9f4ae490b4f72a14b2304921b4cc88b3bee19751ea6248b294e91ec112'))
    ok_(not compare_stored_password('EmY5uff2OS', '5fbf0ef570691bd5345b', '019a45076e45211648b5d34f9f4ae490b4f72a14b2304921b4cc88b3bee19751ea6248b294e91ec113'))
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', compare_stored_password, 'EmY5uff2OS', 'This is not hex!', '01b857327311a73c1b2ad7b3322ba9bc2f47b327b68309468a1be93b420367f34e175d3059146efcea')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_encryption_key():
    eq_(generate_encryption_key(), '9a45076e45211648b857327311a73c1b')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_secret_key():
    eq_(generate_secret_key(), '9a45076e45211648b857327311a73c1b')
    eq_(generate_secret_key(5), '9c8d4f59a7')
    eq_(generate_secret_key(100), 'ef9ea9a426f72223552f72d1f78689f28374d310558d51235765df717eb92bc2d24128abc9c477'\
            '5a119f0d264ffa79cdd778e6af4d8054f2e65be7d0c96b9c5a41c7a968c96fd93fe96edc2121191bc574810c8cf928290b50bdb4b6e8d792e4c973c003')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_hmac_key():
    eq_(generate_hmac_key(), 'bdb4b6e8d792e4c973c0039c8d4f59a79a45076e45211648b857327311a73c1b')
    eq_(generate_hmac_key(), '5be7d0c96b9c5a41c7a968c96fd93fe96edc2121191bc574810c8cf928290b50')
    eq_(generate_hmac_key(), '65df717eb92bc2d24128abc9c4775a119f0d264ffa79cdd778e6af4d8054f2e6')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_authenticator_key():
    # Test generate_authenticator_key alias
    eq_(generate_authenticator_key(), 'bdb4b6e8d792e4c973c0039c8d4f59a79a45076e45211648b857327311a73c1b')


def test_generate_key_from_password():
    # SHA-256
    eq_(generate_key_from_password('password', 'salt'.encode('hex'), 1, 32), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
    eq_(generate_key_from_password('password', 'salt'.encode('hex'), 2, 32), 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43')
    eq_(generate_key_from_password('password', 'salt'.encode('hex'), 4096, 32), 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a')
    # This test takes forever to run
    #eq_(generate_key_from_password('password', 'salt'.encode('hex'), 16777216, 32), 'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46')
    eq_(generate_key_from_password('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt'.encode('hex'), 4096, 40), '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9')
    eq_(generate_key_from_password('pass\x00word', 'sa\x00lt'.encode('hex'), 4096, 16), '89b69d0516f829893c696226650a8687')

    # SHA-1
    eq_(generate_key_from_password('password', 'salt'.encode('hex'), 1, 20, sha1), '0c60c80f961f0e71f3a9b524af6012062fe037a6')
    eq_(generate_key_from_password('password', 'salt'.encode('hex'), 2, 20, sha1), 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
    eq_(generate_key_from_password('password', 'salt'.encode('hex'), 4096, 20, sha1), '4b007901b765489abead49d926f721d065a429c1')
    # This test takes forever to run
    #eq_(generate_key_from_password('password', 'salt'.encode('hex'), 16777216, 20, sha1), 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984')
    eq_(generate_key_from_password('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt'.encode('hex'), 4096, 25, sha1), '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038')
    eq_(generate_key_from_password('pass\x00word', 'sa\x00lt'.encode('hex'), 4096, 16, sha1), '56fa6aa75548099dcc37d7f03425e0c3')
    eq_(generate_key_from_password('\xe7v\xe0\xff\xae\xf3Q\x83\x15.', '\x85D\xe8\x87\xa5\x8e\xcf\x1a\xf0\xdd'.encode('hex'), 10000, 32, sha1), '8aaefbf7cebf9eca651e7dc4af689a21538eabe8583fcc4b549d3c7b0d9f2956')
    eq_(generate_key_from_password('password', 'ATHENA.MIT.EDUraeburn'.encode('hex'), 1, 16, sha1), 'cdedb5281bb2f801565a1122b2563515')
    eq_(generate_key_from_password('password', 'ATHENA.MIT.EDUraeburn'.encode('hex'), 1, 32, sha1), 'cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837')
    eq_(generate_key_from_password('password', 'ATHENA.MIT.EDUraeburn'.encode('hex'), 2, 16, sha1), '01dbee7f4a9e243e988b62c73cda935d')
    eq_(generate_key_from_password('password', 'ATHENA.MIT.EDUraeburn'.encode('hex'), 2, 32, sha1), '01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86')
    eq_(generate_key_from_password('password', 'ATHENA.MIT.EDUraeburn'.encode('hex'), 1200, 32, sha1), '5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13')
    eq_(generate_key_from_password('X' * 64, 'pass phrase equals block size'.encode('hex'), 1200, 32, sha1), '139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1')
    eq_(generate_key_from_password('X' * 65, 'pass phrase exceeds block size'.encode('hex'), 1200, 32, sha1), '9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a')

    assert_raises_with_message(OverflowError, 'derived key too long', generate_key_from_password, '', '', 1, (2 ** 31 - 2) * 32 + 1)

    # Test generate_encryption_key_from_password alias
    eq_(generate_encryption_key_from_password('password', 'salt'.encode('hex')), '5c3d0b075ebf4e11b346cf18512e8dda')

    # Test generate_authenticator_key_from_password alias
    eq_(generate_authenticator_key_from_password('password', 'salt'.encode('hex')), '5c3d0b075ebf4e11b346cf18512e8ddaf29f70d67e67a94e6defe076d461e042')


def test_encrypt_and_decrypt():
    key = 'aa79a8ab43636644d77f2b6b34842b98'
    hmac_key = '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'
    plaintext = 'The quick brown fox was not quick enough and is now an UNFOX!'
    associated_data = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
    ciphertext = encrypt(plaintext, key, hmac_key)
    decrypt_dict = decrypt(ciphertext, key, hmac_key)
    eq_(decrypt_dict['data'], plaintext)
    eq_(decrypt_dict['associated_data'], '')

    ciphertext = encrypt(plaintext, key, hmac_key, associated_data)
    decrypt_dict = decrypt(ciphertext, key, hmac_key)
    eq_(decrypt_dict['data'], plaintext)
    eq_(decrypt_dict['associated_data'], associated_data)


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_encrypt():
    ### Normal cases
    eq_(encrypt('The quick brown fox was not quick enough and is now an UNFOX!', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'),
            '0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1')
    eq_(encrypt('This is exactly 32 bytes long!!!', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'),
            '01d39a92eb0a00a2549aff9ae78d09f04b48be0e32445acf1228952e37f90ba595bdb4b6e8d792e4c973c0039c8d4f59a700000000e5fd17720207938452370c1e205a203b6a3f8c61978c8db0de674da7819767744dab9b9a2a04d2ca1d22226a36319293')
    eq_(encrypt('This one is only 31 bytes long.', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'),
            '015ce50162357471d8ae8d5a65e7b9999fa3f6a9186e0f374cb5e870ff3414736c6edc2121191bc574810c8cf928290b50000000003a316b50825a24b2b62fc0f8ddf19fc8d2a195b63ed0301eb2340be5a07b3910')
    eq_(encrypt('', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'),
            '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398')
    # Same input but different IV from previous test, thus different output
    eq_(encrypt('', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8'),
            '01a639bb35437616ed263a155082f8b9162805e39beeff36dc131455a80e2ed87f9f0d264ffa79cdd778e6af4d8054f2e600000000f84c4b4f7dd825e8a911eb055da76c2a')
    # Raw output
    eq_(encrypt('The quick brown fox was not quick enough and is now an UNFOX!', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8', raw_output=True),
            '\x01_\x05\xec\xe7\xba\x0c\xa6qe\x99\xc3\tvM7#6\xd1\x07\x92{\x15\xbf\xf4\xdc>\xfdU\xa1\xf9\x02\xf6e\xdfq~\xb9+\xc2\xd2A(\xab\xc9\xc4wZ\x11\x00\x00\x00\x00[\x9d\x87\xa3\xc6\x04\x0c\xe3#~\xc5\xc5'\
            '\xa0\xb2P1\xfb\x8cf\xa0p\xc8\xff\x8c\xb2\xc4\xba\xdd\xed\x905\xea\x8e\xea\xa1\x14\xa9D\xd2\x1dIr"\x8e\xe3\xac\xddC\x044\xef\x08\xeb\x12=v5\xb8\xa2\x85\xa5\x01\xc0\xfc')
    # Using associated data
    eq_(encrypt('The quick brown fox was not quick enough and is now an UNFOX!', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.', raw_output=True),
            '\x01\x01\x81s\x0c\xcc\xf0_\x1e\xd2t\x8d\xc3\xeb\xcc\x04\xfc\xf8\x9e\xa7\xc8j#0n\xb5CZ\xd6\t<\xed`/r\xd1\xf7\x86\x89\xf2\x83t\xd3\x10U\x8dQ#W\x00\x00\x008Lorem ipsum dolor sit amet, consectetur adipiscing elit.'\
            '\xac\x7f\x91\x06\xb0\xd6\xfdW\\\xc5\x94\x98\x7fp4\x9e\xbfx\xb2\xf0sg\xa4\xf3\xfa\x9e\\\x8b\xce\xdb\xb9o`\x15\x8e3\x9d\x1a\x14\xda\xbd\xbaj@\x81m\xbb\x8bX;LsR\xba\xe1\xcc\x16%\x8d\xb2\xbaG?`')

    ### Test exceptions
    assert_raises_with_message(ValueError, 'Parameter key is not correct hex.', encrypt, '', 'This is not hex!', '')
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', encrypt, '', 'ababab', 'This is not hex!')
    assert_raises_with_message(ValueError, 'Please provide different keys for encryption and authentication.', encrypt, '', 'ababab', 'ababab')
    assert_raises_with_message(ValueError, 'Parameter key must have length 16, 24 or 32 bytes.', encrypt, '', 'ababab', 'abcdef')
    assert_raises_with_message(ValueError, 'Parameter hmac_key must have at least 32 bytes.', encrypt, '', 'aa79a8ab43636644d77f2b6b34842b98', 'abcdef')


def test_decrypt():
    ### Normal cases
    eq_(decrypt('0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')['data'], 'The quick brown fox was not quick enough and is now an UNFOX!')
    eq_(decrypt('01d39a92eb0a00a2549aff9ae78d09f04b48be0e32445acf1228952e37f90ba595bdb4b6e8d792e4c973c0039c8d4f59a700000000e5fd17720207938452370c1e205a203b6a3f8c61978c8db0de674da7819767744dab9b9a2a04d2ca1d22226a36319293',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')['data'], 'This is exactly 32 bytes long!!!')
    eq_(decrypt('015ce50162357471d8ae8d5a65e7b9999fa3f6a9186e0f374cb5e870ff3414736c6edc2121191bc574810c8cf928290b50000000003a316b50825a24b2b62fc0f8ddf19fc8d2a195b63ed0301eb2340be5a07b3910',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')['data'], 'This one is only 31 bytes long.')
    eq_(decrypt('0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')['data'], '')
    # Originally same input as previous test but with different IV, thus same output
    eq_(decrypt('01a639bb35437616ed263a155082f8b9162805e39beeff36dc131455a80e2ed87f9f0d264ffa79cdd778e6af4d8054f2e600000000f84c4b4f7dd825e8a911eb055da76c2a',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')['data'], '')
    # Raw input
    eq_(decrypt('\x01_\x05\xec\xe7\xba\x0c\xa6qe\x99\xc3\tvM7#6\xd1\x07\x92{\x15\xbf\xf4\xdc>\xfdU\xa1\xf9\x02\xf6e\xdfq~\xb9+\xc2\xd2A(\xab\xc9\xc4wZ\x11\x00\x00\x00\x00[\x9d\x87\xa3\xc6\x04\x0c\xe3#~\xc5\xc5'\
            '\xa0\xb2P1\xfb\x8cf\xa0p\xc8\xff\x8c\xb2\xc4\xba\xdd\xed\x905\xea\x8e\xea\xa1\x14\xa9D\xd2\x1dIr"\x8e\xe3\xac\xddC\x044\xef\x08\xeb\x12=v5\xb8\xa2\x85\xa5\x01\xc0\xfc',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8', raw_input=True)['data'], 'The quick brown fox was not quick enough and is now an UNFOX!')
    # Using associated data
    eq_(decrypt('\x01\x01\x81s\x0c\xcc\xf0_\x1e\xd2t\x8d\xc3\xeb\xcc\x04\xfc\xf8\x9e\xa7\xc8j#0n\xb5CZ\xd6\t<\xed`/r\xd1\xf7\x86\x89\xf2\x83t\xd3\x10U\x8dQ#W\x00\x00\x008Lorem ipsum dolor sit amet, consectetur adipiscing elit.'\
            '\xac\x7f\x91\x06\xb0\xd6\xfdW\\\xc5\x94\x98\x7fp4\x9e\xbfx\xb2\xf0sg\xa4\xf3\xfa\x9e\\\x8b\xce\xdb\xb9o`\x15\x8e3\x9d\x1a\x14\xda\xbd\xbaj@\x81m\xbb\x8bX;LsR\xba\xe1\xcc\x16%\x8d\xb2\xbaG?`',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8', raw_input=True),
            {'data': 'The quick brown fox was not quick enough and is now an UNFOX!', 'associated_data': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'})

    ### Test exceptions
    assert_raises_with_message(ValueError, 'Parameter key is not correct hex.', decrypt, '', 'This is not hex!', '')
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', decrypt, '', 'ababab', 'This is not hex!')
    assert_raises_with_message(ValueError, 'Parameter key must have length 16, 24 or 32 bytes.', decrypt, '', 'ababab', 'abcdef')
    assert_raises_with_message(ValueError, 'Parameter hmac_key must have at least 32 bytes.', decrypt, '', 'aa79a8ab43636644d77f2b6b34842b98', 'abcdef')
    assert_raises_with_message(ValueError, 'Parameter ciphertext is too short to have been generated with encrypt.',
            decrypt, '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede53', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')
    # Version does not exists
    assert_raises_with_message(ValueError, 'Failed to decrypt ciphertext.', decrypt, 'ff93e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398',
            'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')
    # Slightly wrong key
    assert_raises_with_message(ValueError, 'Failed to decrypt ciphertext.', decrypt, '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398', 'aa79a8ab43636644d77f2b6b34842b99', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')
    # Completely wrong key
    assert_raises_with_message(ValueError, 'Failed to decrypt ciphertext.', decrypt, '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398', '615604ea6a7330468c6a55baf2cdb222', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')
    # Wrong HMAC key
    assert_raises_with_message(ValueError, 'Failed to decrypt ciphertext.', decrypt, '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf9')
    # Wrong IV
    assert_raises_with_message(ValueError, 'Failed to decrypt ciphertext.', decrypt, '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe8000000001caa648e9bc98eb9d920ba849ede5398', 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')


def test_BlockCipher_constructor():
    assert_raises_with_message(ValueError, 'Parameter key is not correct hex.', BlockCipher, 'This is not hex!', '')
    assert_raises_with_message(ValueError, 'Parameter hmac_key is not correct hex.', BlockCipher, 'ababab', 'This is not hex!')
    assert_raises_with_message(ValueError, 'Please provide different keys for encryption and authentication.', BlockCipher, 'aa79a8ab43636644d77f2b6b34842b98', 'aa79a8ab43636644d77f2b6b34842b98')
    assert_raises_with_message(ValueError, 'Parameter key must have length 16, 24 or 32 bytes.', BlockCipher, 'aa79a8ab43636644d77f2b6b34842b', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')
    assert_raises_with_message(ValueError, 'Parameter hmac_key must have at least 32 bytes.', BlockCipher, 'aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8fa')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_BlockCipher():
    block_cipher = BlockCipher('aa79a8ab43636644d77f2b6b34842b98', '61d1a03428fd560ddf93734869ad951cb11d643e69ac19301427f16407d8faf8')

    eq_(block_cipher.encrypt('The quick brown fox was not quick enough and is now an UNFOX!'),
            '0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1')
    eq_(block_cipher.encrypt('This is exactly 32 bytes long!!!'),
            '01d39a92eb0a00a2549aff9ae78d09f04b48be0e32445acf1228952e37f90ba595bdb4b6e8d792e4c973c0039c8d4f59a700000000e5fd17720207938452370c1e205a203b6a3f8c61978c8db0de674da7819767744dab9b9a2a04d2ca1d22226a36319293')
    eq_(block_cipher.encrypt('This one is only 31 bytes long.'),
            '015ce50162357471d8ae8d5a65e7b9999fa3f6a9186e0f374cb5e870ff3414736c6edc2121191bc574810c8cf928290b50000000003a316b50825a24b2b62fc0f8ddf19fc8d2a195b63ed0301eb2340be5a07b3910')
    eq_(block_cipher.encrypt(''),
            '0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398')
    # Different IV from previous test, thus different output
    eq_(block_cipher.encrypt(''),
            '01a639bb35437616ed263a155082f8b9162805e39beeff36dc131455a80e2ed87f9f0d264ffa79cdd778e6af4d8054f2e600000000f84c4b4f7dd825e8a911eb055da76c2a')
    # Raw output
    eq_(block_cipher.encrypt('The quick brown fox was not quick enough and is now an UNFOX!', raw_output=True),
            '\x01_\x05\xec\xe7\xba\x0c\xa6qe\x99\xc3\tvM7#6\xd1\x07\x92{\x15\xbf\xf4\xdc>\xfdU\xa1\xf9\x02\xf6e\xdfq~\xb9+\xc2\xd2A(\xab\xc9\xc4wZ\x11\x00\x00\x00\x00[\x9d\x87\xa3\xc6\x04\x0c\xe3#~\xc5\xc5'\
            '\xa0\xb2P1\xfb\x8cf\xa0p\xc8\xff\x8c\xb2\xc4\xba\xdd\xed\x905\xea\x8e\xea\xa1\x14\xa9D\xd2\x1dIr"\x8e\xe3\xac\xddC\x044\xef\x08\xeb\x12=v5\xb8\xa2\x85\xa5\x01\xc0\xfc')
    # Using associated data
    eq_(block_cipher.encrypt('The quick brown fox was not quick enough and is now an UNFOX!', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.', raw_output=True),
            '\x01\x01\x81s\x0c\xcc\xf0_\x1e\xd2t\x8d\xc3\xeb\xcc\x04\xfc\xf8\x9e\xa7\xc8j#0n\xb5CZ\xd6\t<\xed`/r\xd1\xf7\x86\x89\xf2\x83t\xd3\x10U\x8dQ#W\x00\x00\x008Lorem ipsum dolor sit amet, consectetur adipiscing elit.'\
            '\xac\x7f\x91\x06\xb0\xd6\xfdW\\\xc5\x94\x98\x7fp4\x9e\xbfx\xb2\xf0sg\xa4\xf3\xfa\x9e\\\x8b\xce\xdb\xb9o`\x15\x8e3\x9d\x1a\x14\xda\xbd\xbaj@\x81m\xbb\x8bX;LsR\xba\xe1\xcc\x16%\x8d\xb2\xbaG?`')
    eq_(block_cipher.decrypt('0128153d5614aebc47fc2b69331aa1895d70e45fdffa94f04bae7ecef12f9dd4729a45076e45211648b857327311a73c1b00000000eff464a6b51411e7997787049fb0424faecff0786f213652116b4a50022e04cf24ff607d6366b9e3771486f396f8a3dd3d77f5c07bac8d2e0758454e511157e1')['data'],
            'The quick brown fox was not quick enough and is now an UNFOX!')
    eq_(block_cipher.decrypt('01d39a92eb0a00a2549aff9ae78d09f04b48be0e32445acf1228952e37f90ba595bdb4b6e8d792e4c973c0039c8d4f59a700000000e5fd17720207938452370c1e205a203b6a3f8c61978c8db0de674da7819767744dab9b9a2a04d2ca1d22226a36319293')['data'],
            'This is exactly 32 bytes long!!!')
    eq_(block_cipher.decrypt('015ce50162357471d8ae8d5a65e7b9999fa3f6a9186e0f374cb5e870ff3414736c6edc2121191bc574810c8cf928290b50000000003a316b50825a24b2b62fc0f8ddf19fc8d2a195b63ed0301eb2340be5a07b3910')['data'],
            'This one is only 31 bytes long.')
    eq_(block_cipher.decrypt('0193e285fd1720d2caa472029dce4c7185cf83cbfbbb38387ff7b81c89059b536a5be7d0c96b9c5a41c7a968c96fd93fe9000000001caa648e9bc98eb9d920ba849ede5398')['data'], '')
    # Originally same input as previous test but with different IV, thus same output
    eq_(block_cipher.decrypt('01a639bb35437616ed263a155082f8b9162805e39beeff36dc131455a80e2ed87f9f0d264ffa79cdd778e6af4d8054f2e600000000f84c4b4f7dd825e8a911eb055da76c2a')['data'], '')
    # Raw input
    eq_(block_cipher.decrypt('\x01_\x05\xec\xe7\xba\x0c\xa6qe\x99\xc3\tvM7#6\xd1\x07\x92{\x15\xbf\xf4\xdc>\xfdU\xa1\xf9\x02\xf6e\xdfq~\xb9+\xc2\xd2A(\xab\xc9\xc4wZ\x11\x00\x00\x00\x00[\x9d\x87\xa3\xc6\x04\x0c\xe3#~\xc5\xc5'\
            '\xa0\xb2P1\xfb\x8cf\xa0p\xc8\xff\x8c\xb2\xc4\xba\xdd\xed\x905\xea\x8e\xea\xa1\x14\xa9D\xd2\x1dIr"\x8e\xe3\xac\xddC\x044\xef\x08\xeb\x12=v5\xb8\xa2\x85\xa5\x01\xc0\xfc', raw_input=True)['data'],
            'The quick brown fox was not quick enough and is now an UNFOX!')
    # Using associated data
    eq_(block_cipher.decrypt('\x01\x01\x81s\x0c\xcc\xf0_\x1e\xd2t\x8d\xc3\xeb\xcc\x04\xfc\xf8\x9e\xa7\xc8j#0n\xb5CZ\xd6\t<\xed`/r\xd1\xf7\x86\x89\xf2\x83t\xd3\x10U\x8dQ#W\x00\x00\x008Lorem ipsum dolor sit amet, consectetur adipiscing elit.'\
            '\xac\x7f\x91\x06\xb0\xd6\xfdW\\\xc5\x94\x98\x7fp4\x9e\xbfx\xb2\xf0sg\xa4\xf3\xfa\x9e\\\x8b\xce\xdb\xb9o`\x15\x8e3\x9d\x1a\x14\xda\xbd\xbaj@\x81m\xbb\x8bX;LsR\xba\xe1\xcc\x16%\x8d\xb2\xbaG?`', raw_input=True),
            {'data': 'The quick brown fox was not quick enough and is now an UNFOX!', 'associated_data': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'})


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_StreamCipher():
    sc = StreamCipher('aa79a8ab43636644d77f2b6b34842b98')

    eq_(sc.encrypt('The quick brown fox was not quick enough and is now an UNFOX!'),
            '0145211648b857327311a73c1bb88687a3264d0f0570de123f9351a29ffe229fb21ee7a31276ddf25a124c7eb8550c37be4c3a99568969ffb7811c241fb0aab130227b0487db607576a4')

    sc2 = StreamCipher('aa79a8ab43636644d77f2b6b34842b98')
    eq_(sc2.decrypt('0145211648b857327311a73c1bb88687a3264d0f0570de123f9351a29ffe229fb21ee7a31276ddf25a124c7eb8550c37be4c3a99568969ffb7811c241fb0aab130227b0487db607576a4'),
            'The quick brown fox was not quick enough and is now an UNFOX!')

    assert_raises_with_message(ValueError, 'You tried to call the decrypt method after calling encrypt. Please use each StreamCipher object either to encrypt or to decrypt.', sc.decrypt, '')
    assert_raises_with_message(ValueError, 'You tried to call the encrypt method after calling decrypt. Please use each StreamCipher object either to encrypt or to decrypt.', sc2.encrypt, '')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_StreamCipher_broken_up():
    # Same test as test_StreamCipher but encrypting in chunks
    sc = StreamCipher('aa79a8ab43636644d77f2b6b34842b98')

    eq_(sc.encrypt('The quick '),
            '0145211648b857327311a73c1bb88687a3264d0f0570de')
    eq_(sc.encrypt('brown fox w'),
            '123f9351a29ffe229fb21e')
    eq_(sc.encrypt('as not quick enough and is no'),
            'e7a31276ddf25a124c7eb8550c37be4c3a99568969ffb7811c241fb0aa')
    eq_(sc.encrypt('w an UNFOX!'),
            'b130227b0487db607576a4')

    sc2 = StreamCipher('aa79a8ab43636644d77f2b6b34842b98')

    eq_(sc2.decrypt('0145211648b857327311a73c1bb88687a3264d0f0570de'),
            'The quick ')
    eq_(sc2.decrypt('123f9351a29ffe229fb21e'),
            'brown fox w')
    eq_(sc2.decrypt('e7a31276ddf25a124c7eb8550c37be4c3a99568969ffb7811c241fb0aa'),
            'as not quick enough and is no')
    eq_(sc2.decrypt('b130227b0487db607576a4'),
            'w an UNFOX!')


def test_pad_pkcs5():
    eq_(pad_pkcs5('', 16), '\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10')
    eq_(pad_pkcs5('x' * 13, 16), 'xxxxxxxxxxxxx\x03\x03\x03')
    eq_(pad_pkcs5('x' * 15, 16), 'xxxxxxxxxxxxxxx\x01')
    eq_(pad_pkcs5('x' * 16, 16), 'xxxxxxxxxxxxxxxx\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10')
    eq_(pad_pkcs5('x' * 18, 16), 'xxxxxxxxxxxxxxxxxx\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e')
    eq_(pad_pkcs5('\x10' * 16, 16), '\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10')


def test_unpad_pkcs5():
    eq_(unpad_pkcs5('xxxxxxxxxxxxx\x03\x03\x03', 16), 'x' * 13)
    eq_(unpad_pkcs5('xxxxxxxxxxxxxxx\x01', 16), 'x' * 15)
    eq_(unpad_pkcs5('xxxxxxxxxxxxxxxx\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10', 16), 'x' * 16)
    eq_(unpad_pkcs5('xxxxxxxxxxxxxxxxxx\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e', 16), 'x' * 18)
    eq_(unpad_pkcs5('\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10', 16), '\x10' * 16)
    assert_raises_with_message(AssertionError, '', unpad_pkcs5, '', 16)
    assert_raises_with_message(AssertionError, '', unpad_pkcs5, '\x0f' * 15, 16)
    assert_raises_with_message(AssertionError, '', unpad_pkcs5, 'x' * 16 + '\x01', 16)
    assert_raises_with_message(AssertionError, '', unpad_pkcs5, 'x' * 16, 16)
    assert_raises_with_message(AssertionError, '', unpad_pkcs5, 'xxxxxxxxxxxxx\x02\x03\x03', 16)
    assert_raises_with_message(AssertionError, '', unpad_pkcs5, 'xxxxxxxxxxxxxxxxx\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10', 16)
