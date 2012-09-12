"""
.. module:: passwords
    :synopsis: Creation and validation of user passwords.

.. moduleauthor:: Francisco Vieira <francisco.vieira@co.sapo.pt>
"""

from securitylib.utils import randomize, get_random_element
import re

__all__ = ['generate_password', 'validate_password', 'get_password_strength']


def generate_password(length=12, lower=True, upper=True, digits=True, special=True, ambig=True):
    """
    Generates a password according to the given parameters.
    It is guaranteed that if a type of characters (lower, upper, etc.) is allowed in the password,
    then the generated password will always contain at least one character of that type,
    e.g. if the parameter special is True, then the generated password will have at least a special character.

    :param length: Length of the generated password. Must be at least 8.
    :type length: :class:`int`

    :param lower: Whether the password should contain lower case characters.
    :type lower: :class:`bool`

    :param upper: Whether the password should contain upper case characters.
    :type upper: :class:`bool`

    :param digits: Whether the password should contain digits.
    :type digits: :class:`bool`

    :param special: Whether the password should contain special characters (!\@#$%^&*).
    :type special: :class:`bool`

    :param ambig: Whether the password should contain ambiguous characters (iloILO10).
    :type ambig: :class:`bool`

    :returns: :class:`str` -- The generated password.
    """
    if length < 8:
        raise ValueError('Parameter length must be at least 8.')
    if not any([upper, lower, digits, special]):
        raise ValueError('At least one of upper, lower, digits or special must be True.')
    s_all = ''
    s_lower = 'abcdefghjkmnpqrstuvwxyz'
    s_upper = 'ABCDEFGHJKMNPQRSTUVWXYZ'
    s_digits = '23456789'
    s_special = '!@#$%^&*'
    if ambig:
        s_lower += 'ilo'
        s_upper += 'ILO'
        s_digits += '10'
    password = []
    if lower:
        s_all += s_lower
        password.append(get_random_element(s_lower))
    if upper:
        s_all += s_upper
        password.append(get_random_element(s_upper))
    if digits:
        s_all += s_digits
        password.append(get_random_element(s_digits))
    if special:
        s_all += s_special
        password.append(get_random_element(s_special))
    for _ in xrange(length - len(password)):
        password.append(get_random_element(s_all))
    randomize(password)
    return ''.join(password)


def validate_password(password, min_length=12, min_lower=1, min_upper=1, min_digits=1, min_special=1, min_strength=80):
    """
    Validates a given password against some basic rules.

    :param password: Password to validate.
    :type password: :class:`str`

    :param min_length: Minimum length that the password must have.
    :type min_length: :class:`int`

    :param min_lower: Minimum number of lower case characters that the password must contain.
    :type min_lower: :class:`int`

    :param min_upper: Minimum number of upper case characters that the password must contain.
    :type min_upper: :class:`int`

    :param min_digits: Minimum number of digits that the password must contain.
    :type min_digits: :class:`int`

    :param min_special: Minimum number of special characters (!\@#$%^&*) that the password must contain.
    :type min_special: :class:`int`

    :param min_strength: Minimum strength that the password must have according to function :func:`~securitylib.passwords.get_password_strength`.
    :type min_strength: :class:`bool`

    :returns: :class:`list` -- A list with the name of the parameters whose validations have failed.
                               This means a password is valid only if this function returns an empty list.
    """
    s_lower = set('abcdefghijklmnopqrstuvwxyz')
    s_upper = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    s_digits = set('0123456789')
    s_special = set('!@#$%^&*')

    problems = []
    if len(password) < min_length:
        problems.append('min_length')
    if count_occurrences_in_set(password, s_lower) < min_lower:
        problems.append('min_lower')
    if count_occurrences_in_set(password, s_upper) < min_upper:
        problems.append('min_upper')
    if count_occurrences_in_set(password, s_digits) < min_digits:
        problems.append('min_digits')
    if count_occurrences_in_set(password, s_special) < min_special:
        problems.append('min_special')
    if min_strength and get_password_strength(password) < min_strength:
        problems.append('min_strength')
    return problems


def get_password_strength(password):
    """
    Evaluate a password's strength according to some heuristics.

    :param password: Password to evaluate.
    :type password: :class:`str`

    :returns: :class:`int` -- Strength of the password as an int between 0 to 100.
    """
    n_different_characters = len(set(password))
    if n_different_characters == 1:
        return 2

    strength = n_different_characters

    password_length = len(password)

    if 0 < password_length <= 4:
        strength += password_length * 2
    elif 5 <= password_length <= 7:
        strength += 12
    elif 8 <= password_length <= 15:
        strength += 24
    elif password_length >= 16:
        strength += 36

    if re.search('[a-z]', password):
        strength += 1
    if re.search('[A-Z]', password):
        strength += 5
    if re.search('\d', password):
        strength += 5
    if re.search('.*\d.*\d.*\d', password):
        strength += 5
    if re.search('[!,@,#,$,%,^,&,*,?,_,~]', password):
        strength += 5
    if re.search('.*[!,@,#,$,%,^,&,*,?,_,~].*[!,@,#,$,%,^,&,*,?,_,~]', password):
        strength += 5
    if re.search('(?=.*[a-z])(?=.*[A-Z])', password):
        strength += 2
    if re.search('(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', password):
        strength += 2
    if re.search('(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!,@,#,$,%,^,&,*,?,_,~])', password):
        strength += 2

    strength = int(strength * 1.5)
    if strength > 100:
        strength = 100
    return strength


def count_occurrences_in_set(seq, target_set):
    count = 0
    for element in seq:
        if element in target_set:
            count += 1
    return count
