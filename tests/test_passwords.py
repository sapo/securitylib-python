from securitylib.passwords import *
from test_utils import setup_seeded_random, teardown_seeded_random, assert_raises_with_message, with_setup


@with_setup(setup_seeded_random, teardown_seeded_random)
def test_prepare_password_for_storage():
    assert prepare_password_for_storage('EmY5uff2OS', bytearray.fromhex('5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1')) == b'01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96ea'
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', prepare_password_for_storage, 'EmY5uff2OS', bytearray.fromhex('cf9021efdfec6a4e3fd8'))


def test_compare_stored_password():
    assert compare_stored_password('EmY5uff2OS', bytearray.fromhex('5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'), b'01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96ea')
    # Test comparison to upper case stored password
    assert compare_stored_password('EmY5uff2OS', bytearray.fromhex('5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'), '01B857327311A73C1BB3792CC1581F2F679A719CFA83EA9EDB396FD5BEE285909C97B769893FAD96EA')
    assert not compare_stored_password('EmY5uff2OS', bytearray.fromhex('5f07ec7a02bb0d7dc92d8aae1e0817e2a64a1265797b45f4780b49af11df61e1'), '01b857327311a73c1bb3792cc1581f2f679a719cfa83ea9edb396fd5bee285909c97b769893fad96eb')
    assert_raises_with_message(ValueError, 'Parameter authenticator_key must have length 32 bytes.', compare_stored_password, 'EmY5uff2OS', bytearray.fromhex('cf9021efdfec6a4e3fd8'), '')

    
@with_setup(setup_seeded_random, teardown_seeded_random)
def test_generate_password():
    assert generate_password() == '6*#c5IW#px35'
    assert generate_password(16) == 'a^jj3qjHvwPLD*nI'
    assert generate_password(12, False) == 'E%$R^2BZV8Y&'
    assert generate_password(12, True, False) == '78wye$tev*g5'
    assert generate_password(12, True, True, False) == '@#jlff!uJJ&&'
    assert generate_password(12, True, True, True, False) == 'EsmK2x80cORo'
    assert generate_password(50, True, True, True, True, False) == 'MvfvgFjsD3#X&f*H9$MjW$db4Ry7@2fKNnWV7SfWrX7TD7E8DW'
    assert generate_password(8) == '2In*0Ub^'
    assert_raises_with_message(ValueError, 'Parameter length must be at least 8.', generate_password, 7)
    assert_raises_with_message(ValueError, 'At least one of upper, lower, digits or special must be True.', generate_password, 12, False, False, False, False)


def test_validate_password():
    assert validate_password('') == ['min_length', 'min_lower', 'min_upper', 'min_digits', 'min_special', 'min_strength']
    assert validate_password('a') == ['min_length', 'min_upper', 'min_digits', 'min_special', 'min_strength']
    assert validate_password('aaaaaa') == ['min_length', 'min_upper', 'min_digits', 'min_special', 'min_strength']
    assert validate_password('aaaaaaaaaaaa') == ['min_upper', 'min_digits', 'min_special', 'min_strength']
    assert validate_password('Aaaaaaaaaaaa') == ['min_digits', 'min_special', 'min_strength']
    assert validate_password('A1aaaaaaaaaa') == ['min_special']
    assert validate_password('A1!aaaaaaaaa') == []
    assert validate_password('A1!aaaaaaaaa', min_length=14) == ['min_length']
    assert validate_password('A1!aaaaaaaaaaa', min_length=14) == []
    assert validate_password('A1!aaaaaaaaaaa', min_length=14, min_lower=5) == []
    assert validate_password('A1!aaaaaaaaaaa', min_length=14, min_lower=5, min_upper=3) == ['min_upper']
    assert validate_password('AAA1!aaaaaaaaa', min_length=14, min_lower=5, min_upper=3) == []
    assert validate_password('AAA1!aaaaaaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4) == ['min_digits']
    assert validate_password('AAA1111!aaaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4) == []
    assert validate_password('AAA1111!aaaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4, min_special=3) == ['min_special']
    assert validate_password('AAA1111!!!aaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4, min_special=3) == ['min_lower']
    assert validate_password('AAA1111!!!aaaaa', min_length=14, min_lower=5, min_upper=3, min_digits=4, min_special=3) == []
    assert validate_password('5^yhx8xuutn5x9g', min_length=12, min_lower=1, min_upper=0) == []
    assert validate_password('#X9hT', min_length=5) == ['min_strength']
    assert validate_password('#X9hT', min_length=5, min_lower=1, min_upper=1, min_digits=1, min_special=1, min_strength=0) == []
    assert validate_password('7O81k2w6', min_length=8, min_lower=1, min_upper=1, min_digits=1, min_special=0) == ['min_strength']
    assert validate_password('$78jxATr', min_length=8) == []


def test_get_password_strength():
    assert get_password_strength('') == 0
    assert get_password_strength('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') == 22
    assert get_password_strength('aaaabaaaaaaaaaabaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaabaaaaaaaa') == 100
    assert get_password_strength('awL@hd5$c7cp') == 78
    assert get_password_strength('Pac7#FC^') == 47
    assert get_password_strength('cNxTHFgb#%e@') == 77
    assert get_password_strength('3nYgj9JN') == 58
    assert get_password_strength('pZm8uRk0HwBK') == 73
    assert get_password_strength('nqgwxv9n93op') == 61
    assert get_password_strength('4u%2U') == 47
    assert get_password_strength('pacfwldj7wlx') == 61
    assert get_password_strength('asdf') == 11
    assert get_password_strength('2wsxploxsw2') == 52
    assert get_password_strength('23-df-48') == 43
    assert get_password_strength('23-DF-48') == 43
    assert get_password_strength('aa.66.99') == 40
    assert get_password_strength('12/12/12') == 21
    assert get_password_strength('01081996') == 13
    assert get_password_strength('01 8 1996') == 15
    assert get_password_strength('01.8.1996') == 15
    assert get_password_strength('18.1.2020') == 15
    assert get_password_strength('1900.01.29') == 15
    assert get_password_strength('96.30.01') == 15

    assert get_password_strength('sYuj^gkCro*DBRj$') == 92
    assert get_password_strength('aiCJvvjeQAWq!SKD') == 91
    assert get_password_strength('$v$yc1U5zLUF&%n') == 89
    assert get_password_strength('x3m4@xukebowq3$d') == 86
    assert get_password_strength('CgvqM3$gDZ3rQX') == 85
    assert get_password_strength('QH8RbHEipy7bYoOY') == 84
    assert get_password_strength('heZ4SjLPH7MhCXc') == 83
    assert get_password_strength('YLr^sDGrzwkKKn') == 83
    assert get_password_strength('^B8*75H%6$YXAE*') == 83
    assert get_password_strength('LI@S9Fnu1a*in') == 82
    assert get_password_strength('5^yhx8xuutn5x9g') == 80
    assert get_password_strength('7g6XcyCFBd89Fq') == 79
    assert get_password_strength('*b&^b&s@ytiv%b&@') == 78
    assert get_password_strength('ePMvy2*5u&z5') == 78
    assert get_password_strength('dIJwYEYlJkMUXzV') == 78
    assert get_password_strength('wzkfDUssqCxmefK') == 78
    assert get_password_strength('$x!trx!j%j#xdb^') == 76
    assert get_password_strength('1%QZYDO6#8XNQ') == 76
    assert get_password_strength('9rom6seypl03ficn') == 76
    assert get_password_strength('CO1W!$TT@^$JA') == 75
    assert get_password_strength('AB!OZ^LMWVMC@') == 73
    assert get_password_strength('rga67YHtbbfq') == 72
    assert get_password_strength('b5mF4x%lHu') == 71
    assert get_password_strength('!$246YDtMSu') == 71
    assert get_password_strength('@egx9^s3%3^9') == 70
    assert get_password_strength('BN3NH1A5WGLEKN') == 67
    assert get_password_strength('77746@17$5*39@9') == 67
    assert get_password_strength('7!4@^%ju!b') == 65
    assert get_password_strength('*NF$@^J$GB^') == 65
    assert get_password_strength('TI%JKU#JR#Y') == 65
    assert get_password_strength('juduMB2OV1') == 64
    assert get_password_strength('4CS2HWL7ES23W') == 64
    assert get_password_strength('$78jxATr') == 63
    assert get_password_strength('F!CBM&W!GV') == 62
    assert get_password_strength('h%hq@jrdsg') == 62
    assert get_password_strength('ayjnngzzwtfbsx') == 61
    assert get_password_strength('IxsHOSRIjV') == 61
    assert get_password_strength('%#^#!*&$@**^^%&') == 61
    assert get_password_strength('YT#I$KEDX') == 60
    assert get_password_strength('KFWS@YRVY') == 59
    assert get_password_strength('^521@5*8!^6') == 59
    assert get_password_strength('!$HAltUxLF0') == 59
    assert get_password_strength('b74dg9AE') == 58
    assert get_password_strength('ox90ZV^') == 58
    assert get_password_strength('SqEZ0nvb') == 58
    assert get_password_strength('8r&O2JR') == 58
    assert get_password_strength('&NFE#!PEO') == 58
    assert get_password_strength('RQYSSJJMQDLEB') == 57
    assert get_password_strength('vxu6r0kmyg') == 57
    assert get_password_strength('^%$%@##!@^*^##') == 57
    assert get_password_strength('B&U323$2') == 56
    assert get_password_strength('OY%BUPZ^') == 56
    assert get_password_strength('*@7w^%*@') == 56
    assert get_password_strength('%&^*%!%%!&@^**') == 55
    assert get_password_strength('tXqxNpJa') == 55
    assert get_password_strength('V49WL458ZV') == 55
    assert get_password_strength('*@%^*^!$$$%$%') == 54
    assert get_password_strength('#X9hTQ') == 53
    assert get_password_strength('QMR7UWMKO') == 52
    assert get_password_strength('oEmpYSR') == 51
    assert get_password_strength('3USDG501') == 50
    assert get_password_strength('R4XUSL9I') == 50
    assert get_password_strength('VYYFDLPCLF') == 49
    assert get_password_strength('0#4^7272') == 49
    assert get_password_strength('2k&5%m') == 49
    assert get_password_strength('6#hp&c') == 49
    assert get_password_strength('DFBBTHCBTO') == 48
    assert get_password_strength('yzg@!x') == 47
    assert get_password_strength('xELCgY') == 46
    assert get_password_strength('7O81k2w6') == 46
    assert get_password_strength('6^987#%') == 45
    assert get_password_strength('0*!UY') == 44
    assert get_password_strength('fv@gk') == 42
    assert get_password_strength('Mv&4') == 42
    assert get_password_strength('E%#VD') == 42
    assert get_password_strength('0s^p') == 39
    assert get_password_strength('81661417624564') == 38
    assert get_password_strength('%9QQ') == 38
    assert get_password_strength('k@zo') == 37
    assert get_password_strength('X!MJ') == 37
    assert get_password_strength('#Ii') == 36
    assert get_password_strength('!9m') == 34
    assert get_password_strength('%1i') == 34
    assert get_password_strength('Z9l') == 34
    assert get_password_strength('*u6') == 34
    assert get_password_strength('1H*') == 34
    assert get_password_strength('0%$&') == 34
    assert get_password_strength('K4z') == 34
    assert get_password_strength('IF9R') == 33
    assert get_password_strength('cgP') == 32
    assert get_password_strength('5%4$32') == 32
    assert get_password_strength('j$!') == 32
    assert get_password_strength('2495839') == 27
    assert get_password_strength('$$&') == 26
    assert get_password_strength('90d') == 19
    assert get_password_strength('D^') == 14
    assert get_password_strength('%L') == 14
    assert get_password_strength('7p') == 12
    assert get_password_strength('6Y') == 12
    assert get_password_strength('1p') == 12

    # Using username parameter
    assert get_password_strength('2wsxploxsw2', 'piox') == 52  # no match
    assert get_password_strength('2wsxploxsw2', 'plox') == 46  # simple match
    assert get_password_strength('x3m4@xukebowq3$d', 'kebow') == 74  # simple match
    assert get_password_strength('x3m4@xukebowq3$d', 'wobek') == 74  # reversed match
    assert get_password_strength('QH8RbHEipy7bYoOY', 'HEipy7') == 69  # simple match
    assert get_password_strength('QH8RbHEipy7bYoOY', 'hEiPy7') == 69  # case insensitive match
    assert get_password_strength('abab', 'a') == 19  # username too small
    assert get_password_strength('xkebow@kebowq3$d', 'kebow') == 60  # double match
    assert get_password_strength('xwobekukebowq3$d', 'wobek') == 60  # double match, one simple another reversed
    assert get_password_strength('xkeBow@kEbowq3$d', 'kebow') == 64  # double case insensitive match
    assert get_password_strength('xkebow@kebowq3$d', 'kebow@sapo.pt') == 60  # double match, email username
    assert get_password_strength('xkebow@kebowq3$d', 'kebow@sapo.pt@sapo.pt') == 60  # double match, email username, two @
    assert get_password_strength('2wsxplox@sapo.ptsw2', 'plox@sapo.pt') == 54  # simple match
    assert get_password_strength('2wsxtp.opas@xolpsw2', 'plox@sapo.pt') == 54  # reversed match
    assert get_password_strength('2plox@sapo.ptwsxplox@sapo.ptsw2', 'plox@sapo.pt') == 61  # double match
