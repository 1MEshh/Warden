"""
Synthetic vulnerable Python module for demonstrating `vault-warden-ir` static AST analysis.
DO NOT USE IN PRODUCTION.
"""

import hashlib
import pickle
import subprocess
import urllib.request
import yaml


def deserialize_session_payload(raw_bytes: bytes) -> object:
    """Demonstrates CWE-502 insecure pickle deserialization."""
    return pickle.loads(raw_bytes)


def parse_untrusted_config(yaml_stream: str) -> object:
    """Demonstrates CWE-502 unsafe YAML load without SafeLoader."""
    return yaml.load(yaml_stream)


def run_diagnostic_ping(target_host: str) -> int:
    """Demonstrates CWE-78 subprocess invocation with shell=True."""
    proc = subprocess.Popen(f"ping -c 1 {target_host}", shell=True)
    return proc.wait()


def compute_legacy_password_digest(password: str) -> str:
    """Demonstrates CWE-328 weak MD5 cryptographic hash for credentials."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def fetch_insecure_webhook(endpoint: str, session_client: object) -> object:
    """Demonstrates CWE-295 disabled TLS certificate verification."""
    return getattr(session_client, "get")(endpoint, verify=False)
