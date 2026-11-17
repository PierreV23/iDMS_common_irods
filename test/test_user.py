import pytest

from idms.common.irods.config import iRODSConfig
from idms.common.irods.user import User


@pytest.mark.irods
def test_login_native(native_config: iRODSConfig, native_creds):
    user = User.login(native_config, *native_creds)
    user._check_auth()

@pytest.mark.irods
def test_login_pam(pam_config: iRODSConfig, pam_creds):
    user = User.login(pam_config, *pam_creds)
    user._check_auth()

@pytest.mark.irods
def test_login_irods(irods_config: iRODSConfig, irods_creds):
    user = User.login(irods_config, *irods_creds)
    user._check_auth()
