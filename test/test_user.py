import pytest
from irods.exception import CAT_INVALID_AUTHENTICATION
from irods.session import iRODSSession

from idms.common.irods.config import iRODSConfig
from idms.common.irods.exception import UserUnsupportedScheme
from idms.common.irods.user import User, UserAuthFailure


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

@pytest.mark.irods
def test_native_stores_password(native_config: iRODSConfig, native_creds):
    username, password = native_creds
    user = User.login(native_config, username, password)
    assert user._decrypt(user._encrypted_secret) == password

@pytest.mark.irods
def test_pam_stores_token_not_password(pam_config: iRODSConfig, pam_creds):
    username, password = pam_creds
    user = User.login(pam_config, username, password)
    assert user._decrypt(user._encrypted_secret) != password

@pytest.mark.irods
def test_native_wrong_password(native_config: iRODSConfig, native_creds):
    username, _ = native_creds
    with pytest.raises(UserAuthFailure) as e:
        User.login(native_config, username, "wrong-password")
    assert isinstance(e.value.__cause__, CAT_INVALID_AUTHENTICATION)

@pytest.mark.irods
def test_native_wrong_username(native_config: iRODSConfig, native_creds):
    _, password = native_creds
    with pytest.raises(UserAuthFailure) as e:
        User.login(native_config, "fake-user", password)
    assert isinstance(e.value.__cause__, CAT_INVALID_AUTHENTICATION)

@pytest.mark.irods
def test_pam_bad_token_raises_auth_failure(pam_config: iRODSConfig, pam_creds):
    username, _ = pam_creds
    with pytest.raises(UserAuthFailure):
        User.login(pam_config, username, "not-a-token")


@pytest.mark.irods
def test_irods_bad_password_raises_auth_failure(irods_config: iRODSConfig, irods_creds):
    username, _ = irods_creds
    with pytest.raises(UserAuthFailure):
        User.login(irods_config, username, "wrong-password")

@pytest.mark.irods
def test_pam_bad_token_session_raises_auth_failure(pam_config: iRODSConfig, pam_creds):
    username, _ = pam_creds
    user = User(pam_config, username, User._encrypt("not-a-token"), check_auth=False)
    with pytest.raises(UserAuthFailure):
        user.session()

@pytest.mark.irods
def test_irods_bad_token_session_raises_auth_failure(irods_config: iRODSConfig, irods_creds):
    username, _ = irods_creds
    user = User(irods_config, username, User._encrypt("not-a-token"), check_auth=False)
    with pytest.raises(UserAuthFailure):
        user.session()


class ReversingUser(User):
    _encrypt = staticmethod(lambda s: s[::-1])
    _decrypt = staticmethod(lambda s: s[::-1])

@pytest.mark.irods
def test_custom_encryption(native_config: iRODSConfig, native_creds):
    username, password = native_creds
    user = ReversingUser.login(native_config, username, password)
    assert user._encrypted_secret == password[::-1]
    assert user._decrypt(user._encrypted_secret) == password

class StorePasswordUser(User):
    @staticmethod
    def _login_pam(irods_config: iRODSConfig, username: str, password: str) -> str:
        return password

    @staticmethod
    def _login_irods(irods_config: iRODSConfig, username: str, password: str) -> str:
        return password

    def _session_pam(self) -> iRODSSession:
        ses = self.irods_config.session_pam(self.username, pam_password=self._decrypt(self._encrypted_secret))
        return ses

    def _session_irods(self) -> iRODSSession:
        ses = self.irods_config.session_irods(self.username, irods_password=self._decrypt(self._encrypted_secret))
        return ses

@pytest.mark.irods
def test_store_password_pam(pam_config: iRODSConfig, pam_creds):
    username, password = pam_creds
    user = StorePasswordUser.login(pam_config, username, password)
    assert user._decrypt(user._encrypted_secret) == password

@pytest.mark.irods
def test_store_password_irods(irods_config: iRODSConfig, irods_creds):
    username, password = irods_creds
    user = StorePasswordUser.login(irods_config, username, password)
    assert user._decrypt(user._encrypted_secret) == password

@pytest.mark.irods
def test_store_password_pam_wrong_password(pam_config: iRODSConfig, pam_creds):
    username, _ = pam_creds
    with pytest.raises(UserAuthFailure):
        StorePasswordUser.login(pam_config, username, "wrong-password")




# offline

def offline_user(scheme, host="localhost") -> User:
    config = iRODSConfig(host=host, zone="tempZone", authentication_scheme=scheme)
    return User(config, "rods", User._encrypt("x"), check_auth=False)

def unsupported_config() -> iRODSConfig:
    # skip validation
    return iRODSConfig.model_construct(host="localhost", zone="tempZone", authentication_scheme="foobar")

@pytest.mark.unit
@pytest.mark.parametrize("scheme", ["native", "pam_password", "irods"])
def test_scheme_properties(scheme):
    user = offline_user(scheme)
    assert user.authentication_scheme == scheme
    assert user.is_pam == (scheme == "pam_password")
    assert user.is_irods == (scheme == "irods")

@pytest.mark.unit
def test_env_key():
    a = offline_user("native")
    b = offline_user("native")
    c = offline_user("native", host="other-host")
    assert a.env_key() == b.env_key()
    assert a.env_key() != c.env_key()
    hash(a.env_key())

@pytest.mark.unit
def test_login_unsupported_scheme():
    with pytest.raises(UserUnsupportedScheme):
        User.login(unsupported_config(), "rods", "rods")

@pytest.mark.unit
def test_session_unsupported_scheme():
    user = User(unsupported_config(), "rods", User._encrypt("x"), check_auth=False)
    with pytest.raises(UserUnsupportedScheme):
        user.session()