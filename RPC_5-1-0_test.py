# /// script
# requires-python = ">=3.9"
# dependencies = ["python-irodsclient"]
#
# [tool.uv.sources]
# python-irodsclient = { git = "https://github.com/irods/python-irodsclient", rev = "refs/pull/844/head" }
# ///
import irods.auth
from irods.exception import AUTHENTICATION_ERROR
from irods.session import iRODSSession

SSL_COMMON = {
    "irods_client_server_negotiation": "request_server_negotiation",
    "irods_client_server_policy": "CS_NEG_REQUIRE",
    "irods_ssl_ca_certificate_file": "/home/pierre/Documents/github_priv/internship-iRODS-Pierre/ssl/irods.crt",
    "irods_encryption_algorithm": "AES-256-CBC",
    "irods_encryption_key_size": 32,
    "irods_encryption_num_hash_rounds": 16,
    "irods_encryption_salt_size": 8,
    "irods_ssl_verify_server": "none",
}

BASE = {
    # "host": "----",
    "zone": "tempZone",
    "port": 1247,
    **SSL_COMMON,
}

assert "host" in BASE, "dont forget to set a host, I redacted mine"

NATIVE_USER, NATIVE_PASSWORD = "rods", "rods"
PAM_USER, PAM_PASSWORD = "pamtestuser", "secret123"


def touch(ses: iRODSSession, user: str):
    ses.collections.get(f"/{BASE['zone']}/home/{user}")


def ok_version():
    with iRODSSession(user=NATIVE_USER, password="", authentication_scheme="native", **BASE) as ses:
        version = ses.server_version_without_auth()
    print(f"{version=}")


def ok_native_login():
    with iRODSSession(user=NATIVE_USER, password=NATIVE_PASSWORD, authentication_scheme="native", **BASE) as ses:
        touch(ses, NATIVE_USER)


def ok_pam_login():
    with iRODSSession(user=PAM_USER, password=PAM_PASSWORD, authentication_scheme="pam_password", **BASE) as ses:
        token_list = []
        ses.set_auth_option_for_scheme("pam_password", irods.auth.CLIENT_GET_REQUEST_RESULT, token_list)
        touch(ses, PAM_USER)
        token = token_list[0]
        print(f"{token=}")
    return token


def ok_pam_native_login():
    native_password = ok_pam_login()
    with iRODSSession(user=PAM_USER, password=native_password, authentication_scheme="native", **BASE) as ses:
        touch(ses, PAM_USER)


def ok_irods_password_login():
    with iRODSSession(user=NATIVE_USER, password=NATIVE_PASSWORD, authentication_scheme="irods", **BASE) as ses:
        token_list = []
        ses.set_auth_option_for_scheme("irods", irods.auth.CLIENT_GET_REQUEST_RESULT, token_list)
        touch(ses, NATIVE_USER)
        token = token_list[0]
    print(f"{token=}")
    return token


def ok_irods_token_login():
    token = ok_irods_password_login()
    with iRODSSession(user=NATIVE_USER, authentication_scheme="irods", **BASE) as ses:
        ses.set_auth_option_for_scheme("irods", "session_token", token)
        touch(ses, NATIVE_USER)


def ok_irods_token_multiple():
    sessions = []
    token = ok_irods_password_login()
    for _ in range(4):
        ses = iRODSSession(user=NATIVE_USER, authentication_scheme="irods", **BASE)
        ses.set_auth_option_for_scheme("irods", "session_token", token)
        sessions.append(ses)

    for ses in sessions:
        touch(ses, NATIVE_USER)

    for ses in sessions:
        ses.cleanup()


def err_irods_wrong_password():
    with iRODSSession(user=NATIVE_USER, password="foo", authentication_scheme="irods", **BASE) as ses:
        try:
            touch(ses, NATIVE_USER)
            raise AssertionError
        except AUTHENTICATION_ERROR:
            ...


def err_irods_wrong_token():
    fake_token = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    with iRODSSession(user=NATIVE_USER, authentication_scheme="irods", **BASE) as ses:
        ses.set_auth_option_for_scheme("irods", "session_token", fake_token)
        try:
            touch(ses, NATIVE_USER)
            raise AssertionError
        except AUTHENTICATION_ERROR:
            ...


funcs = [
    ok_version,
    ok_native_login,
    ok_pam_login,
    ok_pam_native_login,
    ok_irods_password_login,
    ok_irods_token_login,
    err_irods_wrong_password,
    err_irods_wrong_token,
]

for func in funcs:
    func_name = func.__name__
    print(f"start: {func_name=}")
    try:
        func()
        print(f"OK   : {func_name=}")
    except Exception:
        print(f"FAIL : {func_name=}")
        raise
    print()
