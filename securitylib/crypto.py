from securitylib import advanced_crypto
from securitylib.advanced_crypto import ENCRYPTION_KEY_MINIMUM_LENGTH, HMAC_KEY_MINIMUM_LENGTH
from securitylib.utils import decode_hex_param

__all__ = ['generate_authenticator', 'validate_authenticator',
        'prepare_password_for_storage', 'compare_stored_password', 'generate_encryption_key',
        'generate_authenticator_key', 'generate_encryption_key_from_password',
        'generate_authenticator_key_from_password', 'encrypt', 'decrypt']


def generate_authenticator(data, authenticator_key):
    """
    This function will generate an authenticator for the data (provides authentication and integrity).

    :param data: The data over which to generate the authenticator.
    :type data: :class:`str`

    :param authenticator_key: The secret key to be used by the function, in hex.
                You can use :func:`~securitylib.crypto.generate_authenticator_key` to generate it.
    :type authenticator_key: :class:`str`

    :returns: :class:`str` -- The generated authenticator in hex.
    """
    _validate_authenticator_key(authenticator_key)
    return advanced_crypto.generate_authenticator(data, authenticator_key)


def validate_authenticator(data, authenticator_key, authenticator):
    """
    This function will generate an authenticator for the data using the given secret key
    and compare it to the given authenticator, in order to validate it.
    Use this function instead of performing the comparison yourself, because it
    avoids timing attacks.

    :param data: The data protected by the authenticator.
    :type data: :class:`str`

    :param authenticator_key: The secret key used to generate the given authenticator, in hex.
    :type authenticator_key: :class:`str`

    :param authenticator: The authenticator you want to compare, in hex.
    :type authenticator: :class:`str`

    :returns: :class:`bool` -- True if the given authenticator matches the generated authenticator or False otherwise.
    """
    _validate_authenticator_key(authenticator_key)
    return advanced_crypto.validate_authenticator(data, authenticator_key, authenticator)


def prepare_password_for_storage(password, authenticator_key):
    """
    Use this function if you want to store a password.
    This function returns a hex representation of the password that is safe to be stored.
    It uses a one-way algorithm which means you need to provide the password
    you are trying to verify in :func:`~securitylib.crypto.compare_stored_password` as one of the parameters.

    :param password: The password to be prepared for storage.
    :type password: :class:`str`

    :param authenticator_key: This key is used to make it harder for an attacker to find the users passwords,
                              even if he compromises the database.
                              This is done by making the transformation of the password be unique for the given key
                              (using the given authenticator_key),
                              so even if an attacker gets hold of the stored password,
                              he has no way to verify whether a password matches it without knowing the key.
                              This also means that this key MUST be stored separate from the stored passwords,
                              else an attacker that compromises the database will also get hold of this key.
                              Other recomendations include storing it outside the webserver tree and
                              with read permissions only for the application that must read it.
                              You can use :func:`~securitylib.crypto.generate_authenticator_key` to generate it.
    :type authenticator_key: :class:`str`

    :returns: :class:`str` -- Returns the password prepared for storage.
    """
    _validate_authenticator_key(authenticator_key)
    return advanced_crypto.prepare_password_for_storage(password, authenticator_key)


def compare_stored_password(password, authenticator_key, stored_password):
    """
    Use this function to verify a password given by a user
    against a password stored with :func:`~securitylib.crypto.prepare_password_for_storage`.

    :param password: The password to be compared to the stored one.
    :type password: :class:`str`

    :param authenticator_key: The key that was used when storing the password, in hex.
    :type authenticator_key: :class:`str`

    :param stored_password: Stored password against which the given password is to be compared.
    :type stored_password: :class:`str`

    :returns: :class:`bool` -- True if the given password matches the stored one.
    """
    _validate_authenticator_key(authenticator_key)
    return advanced_crypto.compare_stored_password(password, authenticator_key, stored_password)


def generate_encryption_key():
    """
    Generates a key for use in the :func:`~securitylib.crypto.encrypt` and :func:`~securitylib.crypto.decrypt` functions.

    :returns: :class:`str` -- The generated key, in hex.
    """
    return advanced_crypto.generate_encryption_key()


def generate_authenticator_key():
    """
    Generates an authenticator key.

    :returns: :class:`str` -- The generated key, in hex.
    """
    return advanced_crypto.generate_authenticator_key()


def generate_encryption_key_from_password(password, salt):
    """
    Use this function to generate an encryption key from a password.

    :param password: The password from which to generate the key.
    :type password: :class:`str`

    :param salt: Salt for the password, in hex.
                 You can use :func:`~securitylib.random.get_random_token` to generate it.
    :type salt: :class:`str`

    :returns: :class:`str` -- The generated encryption key, in hex.
    """
    return advanced_crypto.generate_encryption_key_from_password(password, salt)


def generate_authenticator_key_from_password(password, salt):
    """
    Use this function to generate an authenticator key from a password.

    :param password: The password from which to generate the key.
    :type password: :class:`str`

    :param salt: Salt for the password, in hex.
                 You can use :func:`~securitylib.random.get_random_token` to generate it.
    :type salt: :class:`str`

    :returns: :class:`str` -- The generated authenticator key, in hex.
    """
    return advanced_crypto.generate_authenticator_key_from_password(password, salt)


def encrypt(data, key, authenticator_key):
    """
    Use this function to encrypt data.
    Two keys must be provided, one to guarantee confidentiality
    and another to guarantee integrity.

    :param data: The data to encrypt.
    :type data: :class:`str`

    :param key: The key to encrypt the data, in hex. Provides confidentiality.
                You can use :func:`~securitylib.crypto.generate_encryption_key` to generate it.
    :type key: :class:`str`

    :param authenticator_key: The key to authenticate the data, in hex. Provides integrity.
                              You can use :func:`~securitylib.crypto.generate_authenticator_key` to generate it.
    :type authenticator_key: :class:`str`

    :returns: :class:`str` -- The encrypted data.
    """
    _validate_encryption_key(key)
    _validate_authenticator_key(authenticator_key)
    return advanced_crypto.encrypt(data, key, authenticator_key)


def decrypt(ciphertext, key, authenticator_key):
    """
    Use this function to decrypt data that was encrypted using :func:`~securitylib.crypto.encrypt`.
    The same keys used to encrypt the data must be provided to decrypt it.

    :param ciphertext: The encrypted data.
    :type ciphertext: :class:`str`

    :param key: The key that was used to encrypt the data, in hex.
    :type key: :class:`str`

    :param authenticator_key: The key that was used to authenticate the data, in hex.
    :type authenticator_key: :class:`str`

    :returns: :class:`dict` -- The decrypted data.
    """
    _validate_encryption_key(key)
    _validate_authenticator_key(authenticator_key)
    return advanced_crypto.decrypt(ciphertext, key, authenticator_key)['data']


def _validate_authenticator_key(authenticator_key):
    decode_hex_param(authenticator_key, 'authenticator_key')
    if len(authenticator_key) != HMAC_KEY_MINIMUM_LENGTH * 2:
        raise ValueError('Parameter authenticator_key must have length {0} bytes.'.format(HMAC_KEY_MINIMUM_LENGTH))


def _validate_encryption_key(key):
    decode_hex_param(key, 'key')
    if len(key) != ENCRYPTION_KEY_MINIMUM_LENGTH * 2:
        raise ValueError('Parameter key must have length 16 bytes.')
