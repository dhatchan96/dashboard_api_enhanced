// Vulnerable JavaScript Application
// This file contains various security issues to test threat density

// HARDCODED CREDENTIALS - Security Issue #1
const DATABASE_PASSWORD = "super_secret_password_123";
const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const JWT_SECRET = "my_jwt_secret_key_that_is_very_long_and_should_not_be_hardcoded";

// HARDCODED URLS - Security Issue #2
const PAYMENT_GATEWAY_URL = "https://payment.example.com/api/v1/process";
const DATABASE_URL = "postgresql://user:pass@localhost:5432/mydb";
const WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

// DANGEROUS EVAL USAGE - Security Issue #3
function processUserInput(userData) {
    // CRITICAL: Using eval with user input
    const result = eval(userData); // This is dangerous!
    return result;
}

// SQL INJECTION VULNERABILITY - Security Issue #4
function getUserById(userId) {
    // VULNERABLE: Direct string concatenation
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return executeQuery(query);
}

// TIME-BASED LOGIC BOMB - Security Issue #5
function checkSystemMaintenance() {
    const currentTime = new Date();
    // LOGIC BOMB: Time-based trigger
    if (currentTime > new Date('2024-12-31')) {
        // Destructive action triggered by time
        deleteAllData();
        return "System maintenance completed";
    }
    return "System operational";
}

// USER-TARGETED LOGIC BOMB - Security Issue #6
function processUserRequest(userId, requestData) {
    // LOGIC BOMB: User-specific targeting
    if (userId === "admin" && requestData.action === "delete") {
        // Destructive action for specific user
        deleteUserAccount(userId);
        return "Account deleted";
    }
    return "Request processed";
}

// EXECUTION COUNTER LOGIC BOMB - Security Issue #7
let executionCount = 0;

function processTransaction(amount) {
    executionCount++;
    
    // LOGIC BOMB: Counter-based trigger
    if (executionCount > 1000) {
        // Destructive action after certain count
        transferFundsToExternalAccount();
        return "Transaction limit reached";
    }
    return `Transaction ${executionCount} processed`;
}

// DESTRUCTIVE PAYLOAD - Security Issue #8
function cleanupSystem() {
    // DESTRUCTIVE: File system operations
    const fs = require('fs');
    
    // Dangerous file operations
    try {
        fs.rmSync('/tmp/important_data', { recursive: true, force: true });
        fs.unlinkSync('/var/log/system.log');
    } catch (error) {
        console.log('Cleanup error:', error);
    }
    
    // Database cleanup
    executeQuery("DELETE FROM users WHERE status = 'inactive'");
    return "Cleanup completed";
}

// FINANCIAL FRAUD PATTERN - Security Issue #9
function processPayment(amount, currency) {
    // FINANCIAL FRAUD: Suspicious payment redirection
    if (amount > 10000 && currency === "USD") {
        // Redirect to suspicious account
        redirectToAccount("suspicious_account_123");
        return "Payment redirected";
    }
    return "Payment processed normally";
}

// ENVIRONMENT-BASED LOGIC BOMB - Security Issue #10
function checkEnvironment() {
    const env = process.env.ENVIRONMENT;
    
    // LOGIC BOMB: Environment-based trigger
    if (env === "production") {
        // Different behavior in production
        disableSecurityFeatures();
        return "Production mode activated";
    }
    return "Development mode";
}

// VULNERABLE LIBRARY USAGE - Security Issue #11
function parseJsonData(jsonString) {
    // Using vulnerable library version
    const yaml = require('js-yaml');
    // This could be vulnerable if using old version
    return yaml.load(jsonString); // Unsafe by default
}

// PLAIN TEXT STORAGE - Security Issue #12
function storeUserData(userId, data) {
    // PLAIN TEXT: Storing sensitive data unencrypted
    const fs = require('fs');
    const userFile = `/data/users/${userId}.txt`;
    const content = `Password: ${data.password}\nCredit Card: ${data.creditCard}\nSSN: ${data.ssn}\n`;
    fs.writeFileSync(userFile, content);
    return "Data stored";
}

// RATE LIMITING BYPASS - Security Issue #13
function apiEndpoint(request) {
    // NO RATE LIMITING: Vulnerable to abuse
    const userIp = request.ip;
    // No rate limiting implemented
    return processRequest(request);
}

// INSECURE COOKIE - Security Issue #14
function setUserCookie(userId) {
    // INSECURE: Cookie without security flags
    const cookieValue = `user_id=${userId}; expires=2025-01-01`;
    return cookieValue;
}

// XSS VULNERABILITY - Security Issue #15
function displayUserMessage(message) {
    // XSS: Direct DOM manipulation with user input
    document.getElementById('message').innerHTML = message; // Vulnerable to XSS
    return "Message displayed";
}

// CORS MISCONFIGURATION - Security Issue #16
function setupCORS() {
    // CORS: Wildcard origin
    app.use(cors({
        origin: '*', // DANGEROUS: Allows any origin
        credentials: true
    }));
}

// MAIN FUNCTION WITH MULTIPLE ISSUES
function main() {
    // Multiple security issues in one function
    const userInput = prompt("Enter command: ");
    const result = eval(userInput); // Dangerous eval
    
    // Hardcoded credentials
    const dbPassword = "admin123";
    
    // SQL injection
    const query = `SELECT * FROM users WHERE name = '${userInput}'`;
    
    // Time-based logic bomb
    if (new Date().getFullYear() > 2024) {
        deleteSystem();
    }
    
    return result;
}

// Export functions for testing
module.exports = {
    processUserInput,
    getUserById,
    checkSystemMaintenance,
    processUserRequest,
    processTransaction,
    cleanupSystem,
    processPayment,
    checkEnvironment,
    parseJsonData,
    storeUserData,
    apiEndpoint,
    setUserCookie,
    displayUserMessage,
    setupCORS,
    main
}; 