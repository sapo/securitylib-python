from securitylib.passwords import *
from securitylib.random import *
import operator


def get_random_values_for_strength(n=100):
    d = {}
    for i in xrange(n):
        lower, upper, digits, special = False, False, False, False
        while not any([lower, upper, digits, special]):
            lower, upper, digits, special = get_random_boolean(), get_random_boolean(), get_random_boolean(), get_random_boolean()
        length = get_random_integer(8, 16)
        password = generate_password(length, lower, upper, digits, special)
        strength = get_password_strength(password)
        d[password] = strength
    sorted_d = sorted(d.iteritems(), key=operator.itemgetter(1))
    for password, strength in reversed(sorted_d):
        print "eq_(get_password_strength('{}'), {})".format(password, strength)


def get_password_strength_values():
    first_passwords_to_test = ['',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaabaaaaaaaaaabaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaabaaaaaaaa',
    'awL@hd5$c7cp',
    'Pac7#FC^',
    'cNxTHFgb#%e@',
    '3nYgj9JN',
    'pZm8uRk0HwBK',
    'nqgwxv9n93op',
    '4u%2U',
    'pacfwldj7wlx',
    'asdf',
    '2wsxploxsw2',
    ]

    passwords_to_test = [
    'sYuj^gkCro*DBRj$',
    '^B8*75H%6$YXAE*',
    'ePMvy2*5u&z5',
    'x3m4@xukebowq3$d',
    'LI@S9Fnu1a*in',
    '!$246YDtMSu',
    '$v$yc1U5zLUF&%n',
    '!$HAltUxLF0',
    '1%QZYDO6#8XNQ',
    'aiCJvvjeQAWq!SKD',
    'CgvqM3$gDZ3rQX',
    'QH8RbHEipy7bYoOY',
    '7g6XcyCFBd89Fq',
    '9rom6seypl03ficn',
    'b5mF4x%lHu',
    'B&U323$2',
    'CO1W!$TT@^$JA',
    '@egx9^s3%3^9',
    '$78jxATr',
    '77746@17$5*39@9',
    '^521@5*8!^6',
    'heZ4SjLPH7MhCXc',
    'b74dg9AE',
    '*b&^b&s@ytiv%b&@',
    '7O81k2w6',
    '5^yhx8xuutn5x9g',
    'BN3NH1A5WGLEKN',
    'AB!OZ^LMWVMC@',
    '0#4^7272',
    'rga67YHtbbfq',
    '7!4@^%ju!b',
    '4CS2HWL7ES23W',
    'YLr^sDGrzwkKKn',
    'YT#I$KEDX',
    '*NF$@^J$GB^',
    'juduMB2OV1',
    'TI%JKU#JR#Y',
    'F!CBM&W!GV',
    '3USDG501',
    'ox90ZV^',
    '8r&O2JR',
    'SqEZ0nvb',
    'OY%BUPZ^',
    'V49WL458ZV',
    '&NFE#!PEO',
    '#X9hTQ',
    '$x!trx!j%j#xdb^',
    '*@7w^%*@',
    '6^987#%',
    'dIJwYEYlJkMUXzV',
    'wzkfDUssqCxmefK',
    '5%4$32',
    'h%hq@jrdsg',
    '0*!UY',
    'KFWS@YRVY',
    'QMR7UWMKO',
    'Mv&4',
    'R4XUSL9I',
    '%#^#!*&$@**^^%&',
    '81661417624564',
    'IxsHOSRIjV',
    '^%$%@##!@^*^##',
    '%&^*%!%%!&@^**',
    'tXqxNpJa',
    '6#hp&c',
    '2k&5%m',
    'vxu6r0kmyg',
    '*@%^*^!$$$%$%',
    'RQYSSJJMQDLEB',
    'E%#VD',
    'ayjnngzzwtfbsx',
    'DFBBTHCBTO',
    'VYYFDLPCLF',
    '0%$&',
    'yzg@!x',
    '%9QQ',
    '2495839',
    'Z9l',
    'oEmpYSR',
    '1H*',
    'K4z',
    'xELCgY',
    '0s^p',
    '#Ii',
    'X!MJ',
    'IF9R',
    '!9m',
    '%1i',
    '*u6',
    'fv@gk',
    'j$!',
    '$$&',
    'D^',
    'k@zo',
    '6Y',
    'cgP',
    '%L',
    '90d',
    '7p',
    '1p']

    for password in first_passwords_to_test:
        print "eq_(get_password_strength('{}'), {})".format(password, get_password_strength(password))

    print
    d = {}
    for password in passwords_to_test:
        strength = get_password_strength(password)
        d[password] = strength
    sorted_d = sorted(d.iteritems(), key=operator.itemgetter(1))
    for password, strength in reversed(sorted_d):
        print "eq_(get_password_strength('{}'), {})".format(password, strength)
