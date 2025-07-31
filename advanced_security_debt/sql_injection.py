# BAD: SQL Injection vulnerabilities
def get_user_by_id(user_id):
    # Direct string concatenation - SQL injection risk
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

def search_users(search_term):
    # Another SQL injection example
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    return execute_query(query)

def delete_user(user_id):
    # Dangerous DELETE query
    query = f"DELETE FROM users WHERE id = {user_id}"
    return execute_query(query)
