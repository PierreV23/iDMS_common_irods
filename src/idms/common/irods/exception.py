class iRODSVersionMismatchError(Exception):
    """Exception raised when the iRODS server does not support the requested action.
    
    i.e. `authentication_scheme`: `irods` on a server < 5.1.0
    """

class iRODSSessionNonePool(Exception):
    """iRODSSession.pool being None"""

class UserUnsupportedScheme(Exception):
    """user.User doesnt support the auth scheme defined in the iRODSConfig"""