# -*- coding: utf-8 -*-
"""
Compatibility shim for crypto_swig import.

This module provides backward compatibility for tests that import crypto_swig.
The actual implementation uses pybind11 (crypto_python) instead of SWIG.
"""

import os
import sys

# Import GNU Radio first to register base types
try:
    from gnuradio import gr
except ImportError:
    pass


def _add_build_python_paths():
    """Add likely in-tree build dirs for crypto_python (pybind11 output)."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "build", "python"),
        os.path.join(here, "..", "..", "build", "python"),
    ]
    env_build = os.environ.get("GR_OPENSSL_BUILD_DIR")
    if env_build:
        candidates.insert(0, os.path.join(env_build, "python"))
    for path in candidates:
        path = os.path.normpath(path)
        if os.path.isdir(path) and path not in sys.path:
            sys.path.insert(0, path)


# Try to import crypto_python (pybind11 module)
try:
    _add_build_python_paths()
    import crypto_python

    # Import all symbols from crypto_python into this module's namespace
    for attr in dir(crypto_python):
        if not attr.startswith("_"):
            setattr(sys.modules[__name__], attr, getattr(crypto_python, attr))
except ImportError as e:
    # Try importing from installed location
    try:
        import crypto_python

        for attr in dir(crypto_python):
            if not attr.startswith("_"):
                setattr(sys.modules[__name__], attr, getattr(crypto_python, attr))
    except ImportError:
        raise ImportError(
            "Failed to import crypto_python. "
            "Make sure gr-openssl is built and crypto_python module is available. "
            "Original error: %s" % str(e)
        )
