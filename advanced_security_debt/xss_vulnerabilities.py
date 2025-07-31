# BAD: XSS vulnerabilities
def render_user_comment(comment):
    # No HTML escaping - XSS risk
    return f"<div class='comment'>{comment}</div>"

def display_user_name(name):
    # Another XSS example
    return f"<h1>Welcome, {name}!</h1>"

def render_search_results(query):
    # XSS in search results
    return f"<p>Results for: {query}</p>"
