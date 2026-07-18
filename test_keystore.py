"""Self-check for API-key storage backends. Run: python test_keystore.py

Uses fakes for keyring and QSettings so it never touches the real registry
or OS keychain.
"""
import os

import hashharvest.keystore as ks


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def get_password(self, service, key):
        return self.store.get((service, key))

    def set_password(self, service, key, value):
        self.store[(service, key)] = value

    def delete_password(self, service, key):
        self.store.pop((service, key), None)


class FakeSettings:
    def __init__(self, store):
        self.store = store

    def value(self, key, default, _type):
        return self.store.get(key, default)

    def setValue(self, key, value):
        self.store[key] = value

    def remove(self, key):
        self.store.pop(key, None)


def run():
    os.environ.pop("VT_API_KEY", None)
    settings_store = {}
    kr = FakeKeyring()
    ks._settings = lambda: FakeSettings(settings_store)
    ks._keyring = lambda: kr

    # Secure save writes to the keychain and clears any plaintext copy.
    settings_store["vt_api_key"] = "old-plaintext"
    assert ks.save_key("secret1", secure=True) == "keychain"
    assert kr.store[(ks._SERVICE, ks._KEY)] == "secret1"
    assert "vt_api_key" not in settings_store
    assert ks.load_key() == "secret1"       # read prefers keychain
    assert ks.key_in_keychain() is True

    # Plaintext save writes to settings and clears the keychain copy.
    assert ks.save_key("secret2", secure=False) == "settings"
    assert settings_store["vt_api_key"] == "secret2"
    assert kr.store.get((ks._SERVICE, ks._KEY)) is None
    assert ks.load_key() == "secret2"

    # Environment variable wins over both stores.
    os.environ["VT_API_KEY"] = "env-secret"
    assert ks.load_key() == "env-secret"
    os.environ.pop("VT_API_KEY")

    # Secure requested with no backend is a clear error, not silent plaintext.
    ks._keyring = lambda: None
    try:
        ks.save_key("x", secure=True)
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass

    print("ok")


if __name__ == "__main__":
    run()
