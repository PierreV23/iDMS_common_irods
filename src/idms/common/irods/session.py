"""Helper functions that run on `iRODSession`s"""
from copy import deepcopy
from typing import cast

import irods.auth
from irods.session import Pool, iRODSAccount, iRODSSession

from idms.common.irods.exception import iRODSSessionNonePool


def session_get_account(ses: iRODSSession) -> iRODSAccount:
    return cast(iRODSAccount, getattr(ses, "_iRODSSession__configured"))

def get_pam_token(ses: iRODSSession, ttl_hours: int = 24*14) -> str:
    # token in this case means a temporary native password that can be used in place of the user's pam password

    a_ttl = str(ttl_hours)
    
    ses = ses.clone()
    # .clone() is only shallow
    ses.auth_options_by_scheme = deepcopy(ses.auth_options_by_scheme)

    if session_get_account(ses).authentication_scheme != "pam_password":
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

# irods tokens ttl is defined server side
def get_irods_token(ses: iRODSSession) -> str:
    ses = ses.clone()
    # .clone() is only shallow
    ses.auth_options_by_scheme = deepcopy(ses.auth_options_by_scheme)

    if session_get_account(ses).authentication_scheme != "irods":
        raise ValueError("This is not an `irods` session")

    irods_token_list: list[str] = []
    ses.set_auth_option_for_scheme("irods", irods.auth.CLIENT_GET_REQUEST_RESULT, irods_token_list)
    assert ses.pool is not None # gets set in iRODSSession.__init__, should never actually be None
    try:
        ses.pool.get_connection()
    finally:
        ses.cleanup()
    return irods_token_list[0]

def assert_pool(ses: iRODSSession) -> Pool:
    if ses.pool is None:
        raise iRODSSessionNonePool
    return ses.pool

def check_auth(ses: iRODSSession):
    with assert_pool(ses).get_connection():
        pass