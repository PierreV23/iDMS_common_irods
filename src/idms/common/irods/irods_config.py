from pathlib import Path
from typing import TypedDict

# helper typehints for config

# if any field is missing, it can be added here with the same naming irods python client expects
class IRODSConfig(TypedDict, total=False):
    authentication_scheme: str
    host: str
    zone: str
    port: int
    irods_client_server_negotiation: str
    irods_client_server_policy: str
    irods_ssl_ca_certificate_file: str | Path
    irods_encryption_algorithm: str
    irods_encryption_key_size: int
    irods_encryption_num_hash_rounds: int
    irods_encryption_salt_size: int
    irods_ssl_verify_server: str
