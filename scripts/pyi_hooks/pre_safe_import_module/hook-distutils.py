def pre_safe_import_module(api):
    # No-op override: Python 3.12 removed distutils from stdlib.
    # PyInstaller's default hook crashes trying to alias it in conda envs.
    pass
