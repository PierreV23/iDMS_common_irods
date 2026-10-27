import base64
from collections.abc import Callable
from pathlib import Path
from typing import Generic, Hashable, Self, TypedDict, cast

from typing_extensions import TypeVar

import irods.auth
from idms.common.irods.irods_config import IRODSConfig
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
    # maybe rename environment to irods_environment?
    # upstream `environment` can also mean iDMS related settings (db/external URLs)
    environment: IRODSConfig # zone info / zone ssl config
    username: str

    # when is_pam == False, this is the real user's password
    # when is_pam == True, this is the "token" iRODS returns after authenticating pam
    # encrypted in this case means the server side encrypts it
    # this field should only be allowed to be stored in memory
    # TODO: irods 5.1.0 introduces a new authentication type `irods` which...
    # takes a native password but gives a native token back (like pam)
    _encrypted_native_password: T

    # so that classes inhereting this one can set up their own encryption if wanted
    _encrypt: Callable[[str], T] = cast("Callable[[str], T]", staticmethod(encrypt))
    _decrypt: Callable[[T], str] = cast("Callable[[T], str]", staticmethod(decrypt))

    def __init__(self, environment: IRODSConfig, username: str, encrypted_native_password: T):
        self.environment = environment
        self.username = username
        self._encrypted_native_password = encrypted_native_password
        self._check_auth()

    @classmethod
    def login(cls, environment: IRODSConfig, username: str, password: str) -> Self:
        if environment.get("authentication_scheme", "native") == "pam_password":
            token = []
            with iRODSSession(user=username, password=password, **environment) as ses:
                ses.set_auth_option_for_scheme("pam_password", irods.auth.CLIENT_GET_REQUEST_RESULT, token) # write token
                ses.set_auth_option_for_scheme("pam_password", irods.auth.STORE_PASSWORD_IN_MEMORY, True) # never write .irodsA
                cls._pam_set_auth_options(ses)

                assert ses.pool is not None # should never be None, irods session class fills this with a pool before end of __init__
                with ses.pool.get_connection():
                    pass
            native = token[0]
        else:
            native = password

        user = cls(environment, username, cls._encrypt(native))
        user._check_auth()
        return user

    @staticmethod
    def _pam_set_auth_options(ses: iRODSSession):
        ses.set_auth_option_for_scheme("pam_password", AUTH_TTL_KEY, "24")  # token ttl in hours

    def _check_auth(self):
        with self.session() as ses:
            self.__check_auth(ses, self.environment, self.username)

    @staticmethod
    def __check_auth(ses: iRODSSession, environment: IRODSConfig, username: str):
        # underlying irodssession class always assign ses.pool. The typehint is merely wrong
        # asserting rather than noqa ignoring the type error in case underlying logic ever changes
        assert ses.pool is not None
        with ses.pool.get_connection():
            pass
        ses.collections.get(f"/{environment.get('zone')}/home/{username}")

    def session(self) -> iRODSSession:
        AUTH_EXCEPTIONS = (CAT_PASSWORD_EXPIRED, CAT_INVALID_AUTHENTICATION, CAT_INVALID_USER)

        env: IRODSConfig = {**self.environment, "authentication_scheme": "native"} # shallow copy
        ses = iRODSSession(
            user=self.username,
            password=self._decrypt(self._encrypted_native_password),
            **env,
        )
        try:
            self.__check_auth(ses, self.environment, self.username)
        except AUTH_EXCEPTIONS as e:
            ses.cleanup()
            # if auth fails here for a pam user, its the token failing
            # if its a native user, the username or password could be incorrect
            if self.is_pam:
                raise TokenExpired(self.username) from e
            raise
        return ses

    @property
    def is_pam(self):
        return self.environment.get('authentication_scheme', 'native') == "pam_password"


    def env_key(self) -> Hashable:
        # keep the item checks untill iRODSConfig becomes a strictly typed class
        # currently iDMS_web mixes in things like minilims_db among other things that should be in a non-irods env dict (or class)
        
        return tuple(sorted(self.__sanitize_environment(self.environment).items()))

    @staticmethod
    def __sanitize_environment(environment: IRODSConfig) -> IRODSConfig:
        # tightly related to .env_key
        # this function will become redundant once the comment in env_key is fixed
        # this function is also called from .session, because there the env is used as well
        return {
            k:v
            for k, v in environment.items()
            if (k.startswith("irods_")) or (k in {"host", "zone", "port", "authentication_scheme"})
        } # type: ignore
    


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

    print(user._decrypt(user._encrypted_native_password))

    environment_native: IRODSConfig = {
        'host': 'res-irods91.researchlumc.nl',
        'zone': 'tempZone',
        "authentication_scheme": "native",
        "port": 1247,
        **SSL_COMMON,
    }

    user = User.login(environment_native, "rods", "rods")
    user._check_auth()

    print(user._decrypt(user._encrypted_native_password))

    print("all ok")
