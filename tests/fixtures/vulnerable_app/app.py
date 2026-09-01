# Vulnerable sample app for tests

# Security TODO detected
# TODO: auth check for admin

def run_app():
    # Unsafe secret fallback
    SECRET_KEY = "secret"  # noqa: F841
