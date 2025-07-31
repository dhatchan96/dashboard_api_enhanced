# BAD: Data exposure patterns
def get_user_details(user_id):
    # Exposing sensitive data
    user = get_user_from_db(user_id)
    return {
        'id': user.id,
        'email': user.email,
        'password': user.password,  # BAD: Exposing password
        'ssn': user.ssn,           # BAD: Exposing SSN
        'credit_card': user.credit_card  # BAD: Exposing credit card
    }

def log_user_data(user_data):
    # Logging sensitive information
    print(f"User data: {user_data}")
    logger.info(f"Processing user: {user_data}")
