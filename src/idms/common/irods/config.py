from copy import deepcopy
from pathlib import Path
from typing import Literal, TypedDict, cast

from pydantic import BaseModel, ConfigDict

import irods.auth
from idms.common.irods.exception import iRODSVersionMismatchError
from idms.common.irods.session import session_get_account
from irods.session import iRODSAccount, iRODSSession


# if any field is missing, it can be added here with the same naming irods python client expects
# only fields that pass directly into iRODSSession(*) should be in this model
class iRODSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    zone: str
    port: int = 1247

    # authentication_scheme `irods` is only available on servers >5.1.0
    authentication_scheme: Literal["native", "pam_password", "irods"] = "native"
    irods_client_server_negotiation: Literal["request_server_negotiation"] | None = None
    irods_client_server_policy: Literal["CS_NEG_REQUIRE", "CS_NEG_REFUSE", "CS_NEG_DONT_CARE"] | None = None
    irods_ssl_verify_server: Literal["none", "cert", "hostname"] | None = None
    irods_ssl_ca_certificate_file: Path | None = None
    irods_encryption_algorithm: str | None = None
    irods_encryption_key_size: int | None = None
    irods_encryption_num_hash_rounds: int | None = None
    irods_encryption_salt_size: int | None = None

    # helper functions:
    # these functions never change the class and they always only output something that does not link back to this class

    def as_dict(self, exclude_none = True):
        return self.model_dump(exclude_none=exclude_none)

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
        scheme: Literal["native", "pam_password", "irods"] | None = None,
        **kwargs,
    ) -> iRODSSession:
        scheme = scheme if scheme is not None else self.authentication_scheme

        if scheme != "irods" and password is None:
            raise ValueError(f"pass a password for auth scheme `{scheme}`")
        elif (password is None) and (token is None):
            raise ValueError(f"pass atleast one of password or token")
        elif scheme != "irods" and token is not None:
            raise ValueError("token can only be supplied with scheme `irods`")

        env = self.model_dump(exclude_none=True)
        env.pop("authentication_scheme")

        if password is not None:
            return iRODSSession(
                user=username,
                password=password,
                authentication_scheme=scheme,
                **env,
                **kwargs
            )
        else: #token
            ses = iRODSSession(
                user=username,
                authentication_scheme=scheme,
                **env,
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

        # TODO: consider forcing either of the two rather than supporting both at the same time
        if (irods_password is None) and (irods_token is None):
            raise ValueError("Atleast either of irods_password or irods_token should bet set")
        
        if irods_password is not None:
            return self._session(username, password=irods_password, scheme="irods")
        else: # token
            return self._session(username, token=irods_token, scheme="irods")

if __name__ == '__main__':

    def user_check(ses: iRODSSession):
        account = session_get_account(ses)
        ses.collections.get(f"/tempZone/home/{account.client_user}")
        print("succes")

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

    native_user = "rods"
    native_pw = "rods"

    pam_user = "pamtestuser"
    pam_pw = "secret123"


    env_pam = iRODSConfig(**environment)
    ses_pam = env_pam.session_pam(pam_user, pam_pw)
    user_check(ses_pam)

    pam_token = get_pam_token(ses_pam)
    ses_pam_native = env_pam.session_native(pam_user, pam_token)
    user_check(ses_pam_native)

    _tmp = environment
    _tmp["authentication_scheme"] = "irods"
    env_irods = iRODSConfig(**_tmp)

    ses_irods = env_irods.session_irods(native_user, irods_password=native_pw)
    user_check(ses_irods)

    irods_token = get_irods_token(ses_irods)
    ses_irods_token = env_irods.session_irods(native_user, irods_token=irods_token)
    user_check(ses_irods)





