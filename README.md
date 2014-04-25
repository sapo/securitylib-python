
# securitylib
The purpose of this library is to provide functions/classes that solve common
security related problems, while being easy to use even by those who are not
security experts.

To prepare a password for storage for example:

```python
from securitylib import crypto

password = 'supersecretpassword'

authenticator_key = crypto.generate_authenticator_key()
hashed_password = crypto.prepare_passowrd_for_storage(authenticator_key)
```

Find more information in our [documentation](http://securitylib.bk.sapo.pt/python/).


# Discussion
Please file any bugs you find in our [issue tracker](https://gitlab.intra.sapo.pt/security/securitylib-python).
