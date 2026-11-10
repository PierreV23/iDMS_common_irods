from copy import deepcopy
import io
from pathlib import Path
from typing import Literal, TypedDict, cast
from pydantic import BaseModel, ConfigDict
from irods.session import iRODSAccount, iRODSSession
import irods.auth

from idms.common.irods.irods_exception import iRODSVersionMismatchError




type AUTH_SCHEMES = Literal["native", "pam_password", "irods"]


# if any field is missing, it can be added here with the same naming irods python client expects
class iRODSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    zone: str
    port: int = 1247

    # pam_interactive is only for CLIs
    authentication_scheme: AUTH_SCHEMES = "native"
    irods_client_server_negotiation: Literal["request_server_negotiation"] | None = None
    irods_client_server_policy: Literal["CS_NEG_REQUIRE", "CS_NEG_REFUSE", "CS_NEG_DONT_CARE"] | None = None
    irods_ssl_verify_server: Literal["none", "cert", "hostname"] | None = None
    irods_ssl_ca_certificate_file: Path | None = None
    irods_encryption_algorithm: str | None = None
    irods_encryption_key_size: int | None = None
    irods_encryption_num_hash_rounds: int | None = None
    irods_encryption_salt_size: int | None = None

    def server_version(self):
        env = self.model_dump()
        env.pop("authentication_scheme")
        with iRODSSession(user="", password="", authentication_scheme="native", **env) as ses:
            version = ses.server_version_without_auth()
        return version

    def _session(
        self,
        username: str,
        *,
        password: str | None = None,
        token: str | None = None,
        scheme: AUTH_SCHEMES | None = None,
    ) -> iRODSSession:
        scheme = scheme if scheme is not None else self.authentication_scheme

        if scheme != "irods" and password is None:
            raise ValueError(f"pass a password for auth scheme `{scheme}`")
        elif (password is None) == (token is None):
            raise ValueError(f"pass exactly one of password or token, {"neither was passed" if token is None else "both were passed"}")
        elif scheme != "irods" and token is not None:
            raise ValueError("token can only be supplied with scheme `irods`")

        kwargs = self.model_dump(exclude_none=True)
        kwargs.pop("authentication_scheme")
        print(kwargs)

        if password is not None:
            return iRODSSession(
                user=username,
                password=password,
                authentication_scheme=scheme,
                **kwargs
            )
        else: #token
            ses = iRODSSession(
                user=username,
                authentication_scheme=scheme,
                **kwargs
            )
            ses.set_auth_option_for_scheme("irods", "session_token", token)
            return ses

    def session_native(self, username: str, native_password: str) -> iRODSSession:
        if self.authentication_scheme not in ("native", "pam_password"):
            raise ValueError(f"`session_native` should not be called with {self.authentication_scheme=}")
        return self._session(username, password=native_password, scheme="native")

    def session_pam(self, username: str, pam_password: str) -> iRODSSession:
        if self.authentication_scheme != "pam_password":
            raise ValueError(f"Attempted to create a pam session for authentication scheme `{self.authentication_scheme}`")
        return self._session(username, password=pam_password, scheme="pam_password")

    def session_irods(self, username: str, *, irods_password: str | None = None, irods_token: str | None = None, scheme="irods") -> iRODSSession:
        if self.server_version() < (5, 1, 0):
            raise iRODSVersionMismatchError
        
        if (irods_password is None) == (irods_token is None):
            raise ValueError("Only either of irods_password or irods_token should bet set")
        
        if irods_password is not None:
            return self._session(username, password=irods_password, scheme="irods")
        else: # token
            return self._session(username, token=irods_token, scheme="irods")


def get_pam_token(ses: iRODSSession, ttl_hours: int = 24*14) -> str:
    # token in this case means a temporary native password that can be used in place of the user's pam password

    a_ttl = str(ttl_hours)
    
    ses = ses.clone()
    # .clone() is only shallow
    ses.auth_options_by_scheme = deepcopy(ses.auth_options_by_scheme)

    account = cast(iRODSAccount, getattr(ses, "_iRODSSession__configured"))
    if account.authentication_scheme != "pam_password":
        raise ValueError("This is not a pam session")
    
    native_password_list: list[str] = []
    ses.set_auth_option_for_scheme("pam_password", irods.auth.CLIENT_GET_REQUEST_RESULT, native_password_list)
    ses.set_auth_option_for_scheme("pam_password", "a_ttl", a_ttl)
    assert ses.pool is not None # gets set in iRODSSession.__init__, should never actually be None
    try:
        ses.pool.get_connection()
    finally:
        ses.cleanup()
    return native_password_list[0]

# def get_irods_token
    


if __name__ == '__main__':
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

    environment = {
        'host': 'res-irods91.researchlumc.nl',
        'zone': 'tempZone',
        "authentication_scheme": "pam_password",
        "port": 1247,
        **SSL_COMMON,
    }

    env = iRODSConfig(**environment)

    native_user = "rods"
    native_pw = "rods"

    pam_user = "pamtestuser"
    pam_pw = "secret123"


    ses = env.session_pam(pam_user, pam_pw)
    print(env.server_version())
    print(cast(iRODSAccount, getattr(ses, "_iRODSSession__configured")).password)
    print(get_pam_token(ses))
    # ses = env.session_pam(pam_user, pam_pw)
    print(get_pam_token(ses))
    print(ses.pam_pw_negotiated)
    print(ses.pam_pw_negotiated)

