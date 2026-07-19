"""VirusTotal API-key storage with two backends.

* **OS keychain** (Windows Credential Manager / macOS Keychain / Linux Secret
  Service) via the optional ``keyring`` package — encrypted at rest. Opt-in, for
  users who want stronger protection (e.g. a premium VirusTotal key).
* **QSettings** (Windows registry / plist / ini) — plaintext, the default.

Reading prefers, in order: the ``VT_API_KEY`` environment variable, the OS
keychain, then QSettings. Writing goes to whichever backend the caller selects,
and the copy in the other backend is removed so the key lives in exactly one place.
"""

import os

from PyQt6.QtCore import QSettings

_ORG = _APP = _SERVICE = "HashHarvest"
_KEY = "vt_api_key"


def _settings():
    return QSettings(_ORG, _APP)


def _keyring():
    """Return the ``keyring`` module if a real backend is usable, else None."""
    try:
        import keyring
    except ImportError:
        return None
    try:
        from keyring.errors import NoKeyringError
    except Exception:
        NoKeyringError = ()
    try:
        keyring.get_password(_SERVICE, "__probe__")
    except NoKeyringError:
        return None
    except Exception:
        # A locked or otherwise erroring backend still exists — treat as available.
        return keyring
    return keyring


def keychain_available():
    """True when an OS keychain backend can be used for encrypted storage."""
    return _keyring() is not None


def key_in_keychain():
    """True when a key is currently stored in the OS keychain."""
    kr = _keyring()
    if kr is None:
        return False
    try:
        return bool(kr.get_password(_SERVICE, _KEY))
    except Exception:
        return False


def load_key():
    """Return the stored API key from env var, keychain, or QSettings ('' if none)."""
    env = os.environ.get("VT_API_KEY")
    if env:
        return env
    kr = _keyring()
    if kr is not None:
        try:
            value = kr.get_password(_SERVICE, _KEY)
            if value:
                return value
        except Exception:
            pass
    return _settings().value(_KEY, "", str)


def save_key(api_key, secure):
    """Persist ``api_key`` and remove any copy from the other backend.

    Args:
        api_key: the key to store.
        secure: True → OS keychain (encrypted at rest); False → QSettings (plaintext).

    Returns:
        ``"keychain"`` or ``"settings"`` — where the key was written.

    Raises:
        RuntimeError: if ``secure`` is requested but no keychain backend exists.
    """
    settings = _settings()
    if secure:
        kr = _keyring()
        if kr is None:
            raise RuntimeError(
                "No OS keychain backend is available. Install one "
                "(pip install keyring) or use plaintext storage."
            )
        kr.set_password(_SERVICE, _KEY, api_key)
        settings.remove(_KEY)  # drop any plaintext copy left behind
        return "keychain"
    settings.setValue(_KEY, api_key)
    _forget_keychain()
    return "settings"


def _forget_keychain():
    """Delete the keychain copy of the key, if any (best effort)."""
    kr = _keyring()
    if kr is None:
        return
    try:
        kr.delete_password(_SERVICE, _KEY)
    except Exception:
        pass  # nothing stored, or the backend refused — nothing to clean up
