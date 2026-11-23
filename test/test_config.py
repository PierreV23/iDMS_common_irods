import pytest
from irods.session import iRODSSession

from idms.common.irods.config import iRODSConfig
from idms.common.irods.exception import iRODSVersionMismatchError
from idms.common.irods.session import get_irods_token, get_pam_token, session_get_account


def user_check(ses: iRODSSession):
    account = session_get_account(ses)
    ses.collections.get(f"/{account.client_zone}/home/{account.client_user}")


# --- live server ---

@pytest.mark.irods
def test_session_native(native_config: iRODSConfig, native_creds):
    with native_config.session_native(*native_creds) as ses:
        user_check(ses)

@pytest.mark.irods
def test_session_pam(pam_config: iRODSConfig, pam_creds):
    with pam_config.session_pam(*pam_creds) as ses:
        user_check(ses)

@pytest.mark.irods
def test_pam_token_as_native_password(pam_config: iRODSConfig, pam_creds):
    username, password = pam_creds
    with pam_config.session_pam(username, password) as ses:
        token = get_pam_token(ses)

    with pam_config.session_native(username, token) as ses:
        user_check(ses)

@pytest.mark.irods
def test_session_irods_password(irods_config: iRODSConfig, irods_creds):
    username, password = irods_creds
    with irods_config.session_irods(username, irods_password=password) as ses:
        user_check(ses)

@pytest.mark.irods
def test_session_irods_token(irods_config: iRODSConfig, irods_creds):
    username, password = irods_creds
    with irods_config.session_irods(username, irods_password=password) as ses:
        token = get_irods_token(ses)

    with irods_config.session_irods(username, irods_token=token) as ses:
        user_check(ses)


# no server needed

def offline_config(scheme) -> iRODSConfig:
    return iRODSConfig(host="localhost", zone="tempZone", authentication_scheme=scheme)

@pytest.mark.unit
def test_session_native_rejects_irods_scheme():
    with pytest.raises(ValueError):
        offline_config("irods").session_native("rods", "rods")

@pytest.mark.unit
def test_session_pam_rejects_native_scheme():
    with pytest.raises(ValueError):
        offline_config("native").session_pam("rods", "rods")

@pytest.mark.unit
def test_session_requires_password_for_native():
    with pytest.raises(ValueError):
        offline_config("native")._session("rods", scheme="native")

@pytest.mark.unit
def test_session_requires_password_or_token_for_irods():
    with pytest.raises(ValueError):
        offline_config("irods")._session("rods", scheme="irods")

@pytest.mark.unit
def test_session_rejects_token_for_native():
    with pytest.raises(ValueError):
        offline_config("native")._session("rods", password="rods", token="x", scheme="native")

@pytest.mark.unit
def test_session_irods_old_server(monkeypatch):
    monkeypatch.setattr(iRODSConfig, "server_version", lambda self: (4, 3, 4))
    with pytest.raises(iRODSVersionMismatchError):
        offline_config("irods").session_irods("rods", irods_password="rods")

@pytest.mark.unit
def test_session_irods_requires_password_or_token(monkeypatch):
    monkeypatch.setattr(iRODSConfig, "server_version", lambda self: (5, 1, 0))
    with pytest.raises(ValueError):
        offline_config("irods").session_irods("rods")