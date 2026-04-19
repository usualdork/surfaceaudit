"""Allow running the scanner as ``python -m surfaceaudit``."""

# Use the macOS/Windows/Linux system certificate store instead of
# relying on OpenSSL's bundled CA certificates.  This fixes SSL
# verification failures on Homebrew Python installations.
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

from surfaceaudit.cli import main

main()
