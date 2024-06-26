import binascii
import base64
import codecs
from securitylib.random_utils import get_random_integer


def long_to_bin(n, length):
    """
    Convert a long integer into a binary string.
    """
    return binascii.unhexlify('{num:0{length}x}'.format(num=n, length=length * 2))


def bin_to_long(n):
    """
    Convert a binary string into a long integer.
    """
    return int(n.hex(), 16)


def decode_hex_param(hex_str, param_name):
    try:
        return hex_str.hex()
    except TypeError:
        raise ValueError('Parameter {0} is not correct hex.'.format(param_name))


def conditional_encode(bytestring, raw_output, encoding='hex'):
    if type(bytestring) is str:
        bytestring = bytes(bytestring, 'utf8')
    if raw_output:
        return bytestring
    if encoding == 'base64':
        return base64.b64encode(bytestring)
    return codecs.encode(bytestring, encoding)


def conditional_decode(string, raw_input, encoding='hex'):
    if type(string) is str:
        string = bytes(string, 'utf8')
    if raw_input:
        return string
    if encoding == 'base64':
        return base64.b64decode(string)
    return codecs.decode(string, encoding)
    

def randomize(seq):
    #todo Must check if it works because I don't know wich kind of sequence it gets and range(testing) dont allow item assignment
    for i in reversed(list(range(len(seq)))):
        next_index = get_random_integer(0, i)
        seq[i], seq[next_index] = seq[next_index], seq[i]


def get_random_element(seq):
    index = get_random_integer(0, len(seq) - 1)
    return seq[index]
