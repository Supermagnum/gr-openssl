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

# Try to import crypto_python (pybind11 module)
try:
    # First try from build directory
    build_path = os.path.join(os.path.dirname(__file__), "..", "build", "python")
    if os.path.exists(build_path):
        if build_path not in sys.path:
            sys.path.insert(0, build_path)

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
