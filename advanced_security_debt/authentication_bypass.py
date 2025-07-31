# BAD: Authentication bypass patterns
def check_admin_access(user_id):
    # Weak admin check
    if user_id == 1:
        return True
    return False

def validate_token(token):
    # No proper token validation
    if token and len(token) > 0:
        return True
    return False

def is_authenticated(user):
    # Weak authentication check
    return user is not None
