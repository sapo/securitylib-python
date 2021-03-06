from securitylib.passwords import *
from nose.tools import ok_, eq_, with_setup
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_prepare_password_for_storage():
    eq_(prepare_password_for_storage('EmY5uff2OS', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'.decode('hex')), '01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96ea')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', prepare_password_for_storage, 'EmY5uff2OS', 'cf9021efdfec6a4e3fd8'.decode('hex'))


def test_compare_stored_password():
    ok_(compare_stored_password('EmY5uff2OS', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'.decode('hex'), '01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96ea'))
    # Test comparison to upper case stored password
    ok_(compare_stored_password('EmY5uff2OS', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'.decode('hex'), '01B857327311A73C1BB3792CC1581F2F679A719CFA83EA9EDB396FD5BEE285909C97B769893FAD96EA'))
    ok_(not compare_stored_password('EmY5uff2OS', '5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'.decode('hex'), '01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96eb'))
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', compare_stored_password, 'EmY5uff2OS', 'cf9021efdfec6a4e3fd8'.decode('hex'), '')


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_password():
    eq_(generate_password(), 'L&HDKb7m3&gE')
    eq_(generate_password(16), 'a14o*3e683H9i384')
    eq_(generate_password(12, False), 'CSZ^54*8FPUI')
    eq_(generate_password(12, True, False), 'm&cr*#y!hp4%')
    eq_(generate_password(12, True, True, False), 'ALwC#Xinfr%^')
    eq_(generate_password(12, True, True, True, False), 'I2SfXTuFUqjN')
    eq_(generate_password(50, True, True, True, True, False), '9@Vna73Q#E$p5Q^^RezXB4PUKwUU^z^5!KwpD9mND#A8Wz%sAW')
    eq_(generate_password(8), '!R4D@L#o')
    assert_raises_with_message(ValueError, 'Parameter length must be at least 8.', generate_password, 7)
    assert_raises_with_message(ValueError, 'At least one of upper, lower, digits or special must be True.', generate_password, 12, False, False, False, False)


def test_validate_password():
    eq_(validate_password(''), ['min_length', 'min_lower', 'min_upper', 'min_digits', 'min_special', 'min_strength'])
    eq_(validate_password('a'), ['min_length', 'min_upper', 'min_digits', 'min_special', 'min_strength'])
    eq_(validate_password('aaaaaa'), ['min_length', 'min_upper', 'min_digits', 'min_special', 'min_strength'])
    eq_(validate_password('aaaaaaaaaaaa'), ['min_upper', 'min_digits', 'min_special', 'min_strength'])
    eq_(validate_password('Aaaaaaaaaaaa'), ['min_digits', 'min_special', 'min_strength'])
    eq_(validate_password('A1aaaaaaaaaa'), ['min_special'])
    eq_(validate_password('A1!aaaaaaaaa'), [])
    eq_(validate_password('A1!aaaaaaaaa', min_length=14), ['min_length'])
    eq_(validate_password('A1!aaaaaaaaaaa', min_length=14), [])
    eq_(validate_password('A1!aaaaaaaaaaa', min_length=14, min_lower=5), [])
    eq_(validate_password('A1!aaaaaaaaaaa', min_length=14, min_lower=5, min_upper=3), ['min_upper'])
    eq_(validate_password('AAA1!aaaaaaaaa', min_length=14, min_lower=5, min_upper=3), [])
    eq_(validate_password('AAA1!aaaaaaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4), ['min_digits'])
    eq_(validate_password('AAA1111!aaaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4), [])
    eq_(validate_password('AAA1111!aaaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4, min_special=3), ['min_special'])
    eq_(validate_password('AAA1111!!!aaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4, min_special=3), ['min_lower'])
    eq_(validate_password('AAA1111!!!aaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4, min_special=3), [])
    eq_(validate_password('5^yhx8xuutn5x9g', min_length=12, min_lower=1, min_upper=0), [])
    eq_(validate_password('#X9hT', min_length=5), ['min_strength'])
    eq_(validate_password('#X9hT', min_length=5, min_lower=1, min_upper=1, min_digits=1, min_special=1, min_strength=0), [])
    eq_(validate_password('7O81k2w6', min_length=8, min_lower=1, min_upper=1, min_digits=1, min_special=0), ['min_strength'])
    eq_(validate_password('$78jxATr', min_length=8), [])


def test_get_password_strength():
    eq_(get_password_strength(''), 0)
    eq_(get_password_strength('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 22)
    eq_(get_password_strength('aaaabaaaaaaaaaabaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaabaaaaaaaa'), 100)
    eq_(get_password_strength('awL@hd5$c7cp'), 78)
    eq_(get_password_strength('Pac7#FC^'), 47)
    eq_(get_password_strength('cNxTHFgb#%e@'), 77)
    eq_(get_password_strength('3nYgj9JN'), 58)
    eq_(get_password_strength('pZm8uRk0HwBK'), 73)
    eq_(get_password_strength('nqgwxv9n93op'), 61)
    eq_(get_password_strength('4u%2U'), 47)
    eq_(get_password_strength('pacfwldj7wlx'), 61)
    eq_(get_password_strength('asdf'), 11)
    eq_(get_password_strength('2wsxploxsw2'), 52)
    eq_(get_password_strength('23-df-48'), 43)
    eq_(get_password_strength('23-DF-48'), 43)
    eq_(get_password_strength('aa.66.99'), 40)
    eq_(get_password_strength('12/12/12'), 21)
    eq_(get_password_strength('01081996'), 13)
    eq_(get_password_strength('01 8 1996'), 15)
    eq_(get_password_strength('01.8.1996'), 15)
    eq_(get_password_strength('18.1.2020'), 15)
    eq_(get_password_strength('1900.01.29'), 15)
    eq_(get_password_strength('96.30.01'), 15)

    eq_(get_password_strength('sYuj^gkCro*DBRj$'), 92)
    eq_(get_password_strength('aiCJvvjeQAWq!SKD'), 91)
    eq_(get_password_strength('$v$yc1U5zLUF&%n'), 89)
    eq_(get_password_strength('x3m4@xukebowq3$d'), 86)
    eq_(get_password_strength('CgvqM3$gDZ3rQX'), 85)
    eq_(get_password_strength('QH8RbHEipy7bYoOY'), 84)
    eq_(get_password_strength('heZ4SjLPH7MhCXc'), 83)
    eq_(get_password_strength('YLr^sDGrzwkKKn'), 83)
    eq_(get_password_strength('^B8*75H%6$YXAE*'), 83)
    eq_(get_password_strength('LI@S9Fnu1a*in'), 82)
    eq_(get_password_strength('5^yhx8xuutn5x9g'), 80)
    eq_(get_password_strength('7g6XcyCFBd89Fq'), 79)
    eq_(get_password_strength('*b&^b&s@ytiv%b&@'), 78)
    eq_(get_password_strength('ePMvy2*5u&z5'), 78)
    eq_(get_password_strength('dIJwYEYlJkMUXzV'), 78)
    eq_(get_password_strength('wzkfDUssqCxmefK'), 78)
    eq_(get_password_strength('$x!trx!j%j#xdb^'), 76)
    eq_(get_password_strength('1%QZYDO6#8XNQ'), 76)
    eq_(get_password_strength('9rom6seypl03ficn'), 76)
    eq_(get_password_strength('CO1W!$TT@^$JA'), 75)
    eq_(get_password_strength('AB!OZ^LMWVMC@'), 73)
    eq_(get_password_strength('rga67YHtbbfq'), 72)
    eq_(get_password_strength('b5mF4x%lHu'), 71)
    eq_(get_password_strength('!$246YDtMSu'), 71)
    eq_(get_password_strength('@egx9^s3%3^9'), 70)
    eq_(get_password_strength('BN3NH1A5WGLEKN'), 67)
    eq_(get_password_strength('77746@17$5*39@9'), 67)
    eq_(get_password_strength('7!4@^%ju!b'), 65)
    eq_(get_password_strength('*NF$@^J$GB^'), 65)
    eq_(get_password_strength('TI%JKU#JR#Y'), 65)
    eq_(get_password_strength('juduMB2OV1'), 64)
    eq_(get_password_strength('4CS2HWL7ES23W'), 64)
    eq_(get_password_strength('$78jxATr'), 63)
    eq_(get_password_strength('F!CBM&W!GV'), 62)
    eq_(get_password_strength('h%hq@jrdsg'), 62)
    eq_(get_password_strength('ayjnngzzwtfbsx'), 61)
    eq_(get_password_strength('IxsHOSRIjV'), 61)
    eq_(get_password_strength('%#^#!*&$@**^^%&'), 61)
    eq_(get_password_strength('YT#I$KEDX'), 60)
    eq_(get_password_strength('KFWS@YRVY'), 59)
    eq_(get_password_strength('^521@5*8!^6'), 59)
    eq_(get_password_strength('!$HAltUxLF0'), 59)
    eq_(get_password_strength('b74dg9AE'), 58)
    eq_(get_password_strength('ox90ZV^'), 58)
    eq_(get_password_strength('SqEZ0nvb'), 58)
    eq_(get_password_strength('8r&O2JR'), 58)
    eq_(get_password_strength('&NFE#!PEO'), 58)
    eq_(get_password_strength('RQYSSJJMQDLEB'), 57)
    eq_(get_password_strength('vxu6r0kmyg'), 57)
    eq_(get_password_strength('^%$%@##!@^*^##'), 57)
    eq_(get_password_strength('B&U323$2'), 56)
    eq_(get_password_strength('OY%BUPZ^'), 56)
    eq_(get_password_strength('*@7w^%*@'), 56)
    eq_(get_password_strength('%&^*%!%%!&@^**'), 55)
    eq_(get_password_strength('tXqxNpJa'), 55)
    eq_(get_password_strength('V49WL458ZV'), 55)
    eq_(get_password_strength('*@%^*^!$$$%$%'), 54)
    eq_(get_password_strength('#X9hTQ'), 53)
    eq_(get_password_strength('QMR7UWMKO'), 52)
    eq_(get_password_strength('oEmpYSR'), 51)
    eq_(get_password_strength('3USDG501'), 50)
    eq_(get_password_strength('R4XUSL9I'), 50)
    eq_(get_password_strength('VYYFDLPCLF'), 49)
    eq_(get_password_strength('0#4^7272'), 49)
    eq_(get_password_strength('2k&5%m'), 49)
    eq_(get_password_strength('6#hp&c'), 49)
    eq_(get_password_strength('DFBBTHCBTO'), 48)
    eq_(get_password_strength('yzg@!x'), 47)
    eq_(get_password_strength('xELCgY'), 46)
    eq_(get_password_strength('7O81k2w6'), 46)
    eq_(get_password_strength('6^987#%'), 45)
    eq_(get_password_strength('0*!UY'), 44)
    eq_(get_password_strength('fv@gk'), 42)
    eq_(get_password_strength('Mv&4'), 42)
    eq_(get_password_strength('E%#VD'), 42)
    eq_(get_password_strength('0s^p'), 39)
    eq_(get_password_strength('81661417624564'), 38)
    eq_(get_password_strength('%9QQ'), 38)
    eq_(get_password_strength('k@zo'), 37)
    eq_(get_password_strength('X!MJ'), 37)
    eq_(get_password_strength('#Ii'), 36)
    eq_(get_password_strength('!9m'), 34)
    eq_(get_password_strength('%1i'), 34)
    eq_(get_password_strength('Z9l'), 34)
    eq_(get_password_strength('*u6'), 34)
    eq_(get_password_strength('1H*'), 34)
    eq_(get_password_strength('0%$&'), 34)
    eq_(get_password_strength('K4z'), 34)
    eq_(get_password_strength('IF9R'), 33)
    eq_(get_password_strength('cgP'), 32)
    eq_(get_password_strength('5%4$32'), 32)
    eq_(get_password_strength('j$!'), 32)
    eq_(get_password_strength('2495839'), 27)
    eq_(get_password_strength('$$&'), 26)
    eq_(get_password_strength('90d'), 19)
    eq_(get_password_strength('D^'), 14)
    eq_(get_password_strength('%L'), 14)
    eq_(get_password_strength('7p'), 12)
    eq_(get_password_strength('6Y'), 12)
    eq_(get_password_strength('1p'), 12)

    # Using username parameter
    eq_(get_password_strength('2wsxploxsw2', 'piox'), 52)  # no match
    eq_(get_password_strength('2wsxploxsw2', 'plox'), 46)  # simple match
    eq_(get_password_strength('x3m4@xukebowq3$d', 'kebow'), 74)  # simple match
    eq_(get_password_strength('x3m4@xukebowq3$d', 'wobek'), 74)  # reversed match
    eq_(get_password_strength('QH8RbHEipy7bYoOY', 'HEipy7'), 69)  # simple match
    eq_(get_password_strength('QH8RbHEipy7bYoOY', 'hEiPy7'), 69)  # case insensitive match
    eq_(get_password_strength('abab', 'a'), 19)  # username too small
    eq_(get_password_strength('xkebow@kebowq3$d', 'kebow'), 60)  # double match
    eq_(get_password_strength('xwobekukebowq3$d', 'wobek'), 60)  # double match, one simple another reversed
    eq_(get_password_strength('xkeBow@kEbowq3$d', 'kebow'), 64)  # double case insensitive match
    eq_(get_password_strength('xkebow@kebowq3$d', 'kebow@sapo.pt'), 60)  # double match, email username
    eq_(get_password_strength('xkebow@kebowq3$d', 'kebow@sapo.pt@sapo.pt'), 60)  # double match, email username, two @
    eq_(get_password_strength('2wsxplox@sapo.ptsw2', 'plox@sapo.pt'), 54)  # simple match
    eq_(get_password_strength('2wsxtp.opas@xolpsw2', 'plox@sapo.pt'), 54)  # reversed match
    eq_(get_password_strength('2plox@sapo.ptwsxplox@sapo.ptsw2', 'plox@sapo.pt'), 61)  # double match
