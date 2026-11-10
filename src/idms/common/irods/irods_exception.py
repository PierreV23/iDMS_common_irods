class iRODSVersionMismatchError(Exception):
    """Exception raised when the iRODS server does not support the requested action.
    
    i.e. `authentication_scheme`: `irods` on a server < 5.1.0
    """