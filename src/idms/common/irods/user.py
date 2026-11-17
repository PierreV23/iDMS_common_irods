import base64
from collections.abc import Callable, Hashable
from pathlib import Path
from typing import Generic, Self, TypedDict, cast

from typing_extensions import TypeVar

from idms.common.irods.config import iRODSConfig
from idms.common.irods.exception import UserUnsupportedScheme
from idms.common.irods.session import check_auth, get_irods_token, get_pam_token
from irods.auth.pam_password import AUTH_TTL_KEY
from irods.exception import (
    CAT_INVALID_AUTHENTICATION,
    CAT_INVALID_USER,
    CAT_PASSWORD_EXPIRED,
)
from irods.session import iRODSSession


class TokenExpired(Exception):
    pass


# placeholder de/en-crypt functions are not proper encryption
def encrypt(string: str) -> str:
    return base64.b64encode(string.encode()).decode()

def decrypt(encrypted: str):
    return base64.b64decode(encrypted.encode()).decode()

T = TypeVar("T", default=str)

class User(Generic[T]):
    irods_env: iRODSConfig # zone info / zone ssl config
    username: str

    _encrypted_secret: T

    # so that classes inhereting this one can set up their own encryption if wanted
    _encrypt: Callable[[str], T] = cast("Callable[[str], T]", staticmethod(encrypt))
    _decrypt: Callable[[T], str] = cast("Callable[[T], str]", staticmethod(decrypt))

    pam_ttl: int | None = None

    def __init__(self, irods_config: iRODSConfig, username: str, encrypted_secret: T, *, check_auth = True):
        self.irods_config = irods_config
        self.username = username
        self._encrypted_secret = encrypted_secret
        if check_auth:
            self._check_auth()

    @classmethod
    def login(cls, irods_config: iRODSConfig, username: str, password: str) -> Self:
        match irods_config.authentication_scheme:
            case "pam_password":
                ses = irods_config.session_pam(username, password)
                secret = get_pam_token(ses)
            case "native":
                secret = password
            case "irods":
                ses = irods_config.session_irods(username, irods_password=password)
                secret = get_irods_token(ses)
            case _:
                raise UserUnsupportedScheme

        user = cls(irods_config, username, cls._encrypt(secret))
        return user

    def _check_auth(self):
        with self.session() as ses:
            check_auth(ses)

    def session(self) -> iRODSSession:
        AUTH_EXCEPTIONS = (CAT_PASSWORD_EXPIRED, CAT_INVALID_AUTHENTICATION, CAT_INVALID_USER)

        match self.irods_config.authentication_scheme:
            case "pam_password" | "native":
                ses = self.irods_config.session_native(self.username, native_password=self._decrypt(self._encrypted_secret))
            case "irods":
                ses = self.irods_config.session_irods(self.username, irods_token=self._decrypt(self._encrypted_secret))
            case _:
                raise UserUnsupportedScheme
        
        try:
            check_auth(ses)
        except AUTH_EXCEPTIONS as e:
            ses.cleanup()
            # if auth fails here for a pam user, its the token failing
            # if its a native user, the username or password could be incorrect
            if self.is_pam:
                raise TokenExpired(self.username) from e
            raise # raises the original Exception again
        return ses

    @property
    def authentication_scheme(self):
        return self.irods_config.authentication_scheme

    @property
    def is_pam(self):
        return self.authentication_scheme == "pam_password"

    def env_key(self) -> Hashable:
        return tuple(sorted(self.irods_config.as_dict().items()))


# example usage:
if __name__ == '__main__':
    def custom_encrypt(foo: str):
        return ""
    
    class CustomUser(User):
        # _encrypt = custom_encrypt
        @staticmethod
        def _pam_set_auth_options(ses: iRODSSession):
            ses.set_auth_option_for_scheme("pam_password", AUTH_TTL_KEY, "1")

    # this is just a helper for typechecking
    class SSLConfig(TypedDict, total=False):
        irods_client_server_negotiation: str
        irods_client_server_policy: str
        irods_ssl_ca_certificate_file: str | Path
        irods_encryption_algorithm: str
        irods_encryption_key_size: int
        irods_encryption_num_hash_rounds: int
        irods_encryption_salt_size: int
        irods_ssl_verify_server: str

    SSL_COMMON: SSLConfig = {
        "irods_client_server_negotiation": "request_server_negotiation",
        "irods_client_server_policy": "CS_NEG_REQUIRE",
        "irods_ssl_ca_certificate_file": "/home/pierre/Documents/github_priv/internship-iRODS-Pierre/ssl/irods.crt",
        "irods_encryption_algorithm": "AES-256-CBC",
        "irods_encryption_key_size": 32,
        "irods_encryption_num_hash_rounds": 16,
        "irods_encryption_salt_size": 8,
        "irods_ssl_verify_server": "none",
    }

    environment: IRODSConfig = {
        'host': 'res-irods91.researchlumc.nl',
        'zone': 'tempZone',
        "authentication_scheme": "pam_password",
        "port": 1247,
        **SSL_COMMON,
    }

    user = CustomUser.login(environment, "pamtestuser", "secret123")
    user._check_auth()

    print(user._decrypt(user._encrypted_secret))

    environment_native: IRODSConfig = {
        'host': 'res-irods91.researchlumc.nl',
        'zone': 'tempZone',
        "authentication_scheme": "native",
        "port": 1247,
        **SSL_COMMON,
    }

    user = User.login(environment_native, "rods", "rods")
    user._check_auth()

    print(user._decrypt(user._encrypted_secret))

    print("all ok")
