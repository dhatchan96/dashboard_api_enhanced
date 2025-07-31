#!/usr/bin/env python3
"""
ThreatGuard Pro - Enhanced Logic Bomb Detection System
Advanced Malicious Code Pattern Detection & Threat Intelligence
Copyright 2025 - Enhanced with comprehensive security features
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

@dataclass
class SecurityRule:
    """Enhanced logic bomb detection rule definition with tech debt support"""
    id: str
    name: str
    description: str
    severity: str  # CRITICAL_BOMB, HIGH_RISK, MEDIUM_RISK, LOW_RISK, SUSPICIOUS, CRITICAL, MAJOR, MINOR
    type: str  # LOGIC_BOMB, SCHEDULED_THREAT, TARGETED_ATTACK, EXECUTION_TRIGGER, DESTRUCTIVE_PAYLOAD, SECURITY_TECH_DEBT
    language: str
    pattern: str
    remediation_effort: int  # minutes
    tags: List[str]
    enabled: bool = True
    custom: bool = False
    threat_category: str = "UNKNOWN"
    # Tech debt specific fields
    debt_category: str = "UNKNOWN"  # HARDCODED_CREDENTIALS, HARDCODED_URLS, etc.
    business_impact: str = "Medium"  # Critical, High, Medium, Low

@dataclass
class SecurityIssue:
    """Enhanced security issue with comprehensive tracking and hierarchical tagging"""
    id: str
    rule_id: str
    file_path: str
    line_number: int
    column: int
    message: str
    severity: str
    type: str
    status: str  # ACTIVE_THREAT, NEUTRALIZED, UNDER_REVIEW, FALSE_POSITIVE, RESOLVED
    assignee: Optional[str] = None
    creation_date: str = ""
    update_date: str = ""
    effort: int = 0
    debt: str = ""
    code_snippet: str = ""
    suggested_fix: str = ""
    threat_level: str = "UNKNOWN"
    trigger_analysis: str = ""
    payload_analysis: str = ""
    
    # Hierarchical Organization Tags (AIT → SPK → Repo → Scan)
    ait_tag: str = "AIT"                    # Top level: Application Integration Team
    spk_tag: str = "SPK-DEFAULT"            # Second level: Specific Product/Workstream Key
    repo_name: str = "unknown-repo"         # Third level: Repository name
    scan_id: str = "unknown-scan"           # Fourth level: Specific scan identifier
    
    # Security Tech Debt Classification
    debt_category: str = "UNKNOWN"          # HARDCODED_CREDENTIALS, HARDCODED_URLS, INPUT_VALIDATION, etc.
    business_impact: str = "Medium"         # Critical, High, Medium, Low
    compliance_impact: str = "None"         # SOX, PCI_DSS, GDPR, HIPAA, None
    security_domain: str = "APPLICATION"    # APPLICATION, INFRASTRUCTURE, DATA, NETWORK
    
    # Enhanced Metadata
    file_name: str = ""                     # Just the filename without path
    component_name: str = ""                # Application component/module name
    team_owner: str = ""                    # Team responsible for remediation
    priority_score: int = 0                 # Calculated priority (1-100)
    last_modified: str = ""                 # Last time file was modified
    
    # Risk Assessment
    exploitability: str = "UNKNOWN"         # EASY, MEDIUM, HARD, VERY_HARD
    attack_vector: str = "UNKNOWN"          # NETWORK, LOCAL, PHYSICAL
    data_classification: str = "UNKNOWN"    # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

@dataclass
class ThreatShield:
    """Enhanced threat protection shield configuration"""
    id: str
    name: str
    protection_rules: List[Dict[str, Any]]
    is_default: bool = False
    threat_categories: List[str] = None
    risk_threshold: str = "MEDIUM_RISK"

@dataclass
class ScanResult:
    """Enhanced scan result with threat intelligence"""
    project_id: str
    scan_id: str
    timestamp: str
    duration_ms: int
    files_scanned: int
    lines_of_code: int
    issues: List[SecurityIssue]
    coverage: float
    duplications: float
    maintainability_rating: str
    reliability_rating: str
    security_rating: str
    threat_shield_status: str
    logic_bomb_risk_score: float = 0.0
    threat_intelligence: Dict[str, Any] = None
    # Added for hierarchical project display
    ait_tag: str = "AIT"
    spk_tag: str = "SPK-DEFAULT"
    repo_name: str = "unknown-repo"

class LogicBombRulesEngine:
    """Enhanced rules engine with comprehensive threat detection"""
    
    def __init__(self, rules_file: str = "logic_bomb_rules.json"):
        self.rules_file = rules_file
        self.rules: Dict[str, SecurityRule] = {}
        self.load_rules()
    
    def load_rules(self):
        """Load rules from JSON file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    rules_data = json.load(f)
                    for rule_data in rules_data:
                        rule = SecurityRule(**rule_data)
                        self.rules[rule.id] = rule
            except Exception as e:
                print(f"Error loading rules: {e}")
        else:
            self._create_default_logic_bomb_rules()
    
    def _create_default_logic_bomb_rules(self):
        """Create comprehensive default logic bomb detection rules"""
        default_rules = [
            # Time-based Logic Bombs
            SecurityRule(
                id="logic-bomb-time-trigger",
                name="Time-Based Logic Bomb",
                description="Detects suspicious time-based conditional execution that may trigger malicious actions on specific dates",
                severity="CRITICAL_BOMB",
                type="SCHEDULED_THREAT",
                language="*",
                pattern=r'if.*(?:date|datetime|time).*[><=].*\d{4}.*:.*(?:delete|remove|destroy|format|kill|rmdir|unlink)',
                remediation_effort=90,
                tags=["logic-bomb", "time-trigger", "malicious-code", "date-based"],
                threat_category="SCHEDULED_THREAT"
            ),
            # User-targeted Logic Bombs
            SecurityRule(
                id="logic-bomb-user-targeted",
                name="User-Targeted Logic Bomb", 
                description="Detects malicious code that targets specific users for harmful actions",
                severity="CRITICAL_BOMB",
                type="TARGETED_ATTACK",
                language="*", 
                pattern=r'if.*(?:user|username|getuser|USER).*==.*["\'][^"\']*["\'].*:.*(?:delete|remove|destroy|corrupt|kill)',
                remediation_effort=75,
                tags=["logic-bomb", "user-targeted", "malicious-code", "personalized-attack"],
                threat_category="TARGETED_ATTACK"
            ),
            # Counter-based Logic Bombs
            SecurityRule(
                id="logic-bomb-execution-counter",
                name="Counter-Based Logic Bomb",
                description="Detects execution count-based triggers that activate malicious behavior after N executions", 
                severity="HIGH_RISK",
                type="EXECUTION_TRIGGER",
                language="*",
                pattern=r'(?:count|counter|iteration|exec_count).*[><=].*\d+.*:.*(?:delete|remove|destroy|corrupt|format)',
                remediation_effort=60,
                tags=["logic-bomb", "counter-based", "trigger-condition", "execution-based"],
                threat_category="EXECUTION_TRIGGER"
            ),
            # Environment-based Logic Bombs
            SecurityRule(
                id="logic-bomb-environment-condition",
                name="Environment-Based Logic Bomb",
                description="Detects environment-specific triggers that activate malicious behavior on target systems",
                severity="HIGH_RISK", 
                type="SYSTEM_SPECIFIC_THREAT",
                language="*",
                pattern=r'if.*(?:env|environment|hostname|platform|gethostname).*==.*["\'][^"\']*["\'].*:.*(?:sys\.|os\.|subprocess|system)',
                remediation_effort=50,
                tags=["logic-bomb", "environment-trigger", "system-specific", "conditional-attack"],
                threat_category="SYSTEM_SPECIFIC_THREAT"
            ),
            # Destructive Payloads
            SecurityRule(
                id="destructive-payload-detector",
                name="Destructive Payload Detection",
                description="Detects potentially destructive operations that could be payloads of logic bombs",
                severity="CRITICAL_BOMB",
                type="DESTRUCTIVE_PAYLOAD", 
                language="*",
                pattern=r'(?:shutil\.rmtree|os\.remove|subprocess\.call.*rm|system.*(?:del|rm)|format.*c:|rmdir.*\/s)',
                remediation_effort=120,
                tags=["destructive-payload", "system-damage", "malicious-code", "data-destruction"],
                threat_category="DESTRUCTIVE_PAYLOAD"
            ),
            # Network-based Logic Bombs
            SecurityRule(
                id="logic-bomb-network-trigger",
                name="Network-Based Logic Bomb",
                description="Detects network condition-based triggers for malicious activation",
                severity="MEDIUM_RISK",
                type="CONNECTION_BASED_THREAT",
                language="*", 
                pattern=r'if.*(?:ping|connect|socket|urllib).*(?:fail|error|timeout).*:.*(?:delete|remove|destroy)',
                remediation_effort=45,
                tags=["logic-bomb", "network-trigger", "connectivity-based"],
                threat_category="CONNECTION_BASED_THREAT"
            ),
            # Financial Fraud Detection
            SecurityRule(
                id="financial-fraud-detector",
                name="Financial Fraud Pattern",
                description="Detects potential financial fraud and unauthorized money redirection",
                severity="CRITICAL_BOMB",
                type="FINANCIAL_FRAUD",
                language="*",
                pattern=r'(?:bitcoin.*address|crypto.*wallet|paypal\.me|transfer.*money|redirect.*payment)',
                remediation_effort=90,
                tags=["financial-fraud", "money-redirection", "cryptocurrency"],
                threat_category="FINANCIAL_FRAUD"
            ),
            # Security Tech Debt Rules
            SecurityRule(
                id="hardcoded-secrets-detector",
                name="Hardcoded Secrets",
                description="Detects hardcoded passwords, API keys, and secrets",
                severity="CRITICAL",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:password|secret|key|token|credential).*=.*["\'][^"\']{8,}["\']',
                remediation_effort=30,
                tags=["security-debt", "hardcoded-secrets", "credentials"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="HARDCODED_CREDENTIALS",
                business_impact="High"
            ),
            SecurityRule(
                id="hardcoded-urls-detector",
                name="Hardcoded URLs",
                description="Detects hardcoded URLs and endpoints",
                severity="MAJOR",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:url|endpoint|api|webhook).*=.*["\']https?://[^"\']*["\']',
                remediation_effort=20,
                tags=["security-debt", "hardcoded-urls", "configuration"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="HARDCODED_URLS",
                business_impact="Medium"
            ),
            SecurityRule(
                id="input-validation-detector",
                name="Missing Input Validation",
                description="Detects code without proper input validation",
                severity="CRITICAL",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'f["\'](?:SELECT|INSERT|UPDATE|DELETE).*\{[^}]*\}["\']',
                remediation_effort=45,
                tags=["security-debt", "input-validation", "sql-injection"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="INPUT_VALIDATION",
                business_impact="Critical"
            ),
            SecurityRule(
                id="vulnerable-libraries-detector",
                name="Vulnerable Library Versions",
                description="Detects known vulnerable library versions",
                severity="MAJOR",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:requests==2\.25\.1|django==2\.2\.28|flask==1\.1\.4|cryptography==3\.3\.2)',
                remediation_effort=60,
                tags=["security-debt", "vulnerable-libraries", "dependencies"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="VULNERABLE_LIBRARIES",
                business_impact="High"
            ),
            SecurityRule(
                id="plain-text-storage-detector",
                name="Plain Text Storage",
                description="Detects sensitive data stored in plain text",
                severity="CRITICAL",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:password|credit_card|ssn|social_security).*:.*["\'][^"\']*["\']',
                remediation_effort=40,
                tags=["security-debt", "plain-text", "data-protection"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="PLAIN_TEXT_STORAGE",
                business_impact="Critical"
            ),
            SecurityRule(
                id="cors-policy-detector",
                name="Overly Permissive CORS",
                description="Detects overly permissive CORS configuration",
                severity="MINOR",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:CORS_ORIGIN_ALLOW_ALL.*True|CORS_ALLOWED_ORIGINS.*\["\*"\]|Access-Control-Allow-Origin.*\*)',
                remediation_effort=15,
                tags=["security-debt", "cors", "web-security"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="CORS_POLICY",
                business_impact="Medium"
            ),
            SecurityRule(
                id="rate-limiting-detector",
                name="Missing Rate Limiting",
                description="Detects API endpoints without rate limiting",
                severity="MINOR",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'@app\.route.*(?:login|register|reset-password).*methods.*POST',
                remediation_effort=25,
                tags=["security-debt", "rate-limiting", "api-security"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="RATE_LIMITING",
                business_impact="Medium"
            ),
            SecurityRule(
                id="secure-cookies-detector",
                name="Insecure Cookie Configuration",
                description="Detects insecure cookie settings",
                severity="MINOR",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:SESSION_COOKIE_SECURE.*False|SESSION_COOKIE_HTTPONLY.*False)',
                remediation_effort=10,
                tags=["security-debt", "cookies", "session-security"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="SECURE_COOKIES",
                business_impact="Medium"
            ),
            SecurityRule(
                id="ssl-tls-detector",
                name="Weak SSL/TLS Configuration",
                description="Detects weak SSL/TLS settings",
                severity="CRITICAL",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:SSL_VERSION.*SSLv3|CERT_VERIFY.*False|SSL_CHECK_HOSTNAME.*False)',
                remediation_effort=35,
                tags=["security-debt", "ssl-tls", "encryption"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="SSL_TLS",
                business_impact="Critical"
            ),
            SecurityRule(
                id="secrets-management-detector",
                name="Poor Secrets Management",
                description="Detects poor secrets management practices",
                severity="MAJOR",
                type="SECURITY_TECH_DEBT",
                language="*",
                pattern=r'(?:default.*password|default.*secret|default.*key)',
                remediation_effort=30,
                tags=["security-debt", "secrets-management", "configuration"],
                threat_category="SECURITY_TECH_DEBT",
                debt_category="SECRETS_MANAGEMENT",
                business_impact="High"
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.id] = rule
        
        self.save_rules()
    
    def save_rules(self):
        """Save rules to JSON file"""
        try:
            rules_data = [asdict(rule) for rule in self.rules.values()]
            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
        except Exception as e:
            print(f"Error saving rules: {e}")
    
    def add_rule(self, rule: SecurityRule):
        """Add a new logic bomb detection rule"""
        self.rules[rule.id] = rule
        self.save_rules()
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]):
        """Update an existing rule"""
        if rule_id in self.rules:
            rule = self.rules[rule_id]
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self.save_rules()
    
    def delete_rule(self, rule_id: str):
        """Delete a rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.save_rules()
    
    def get_enabled_rules(self, language: str = None) -> List[SecurityRule]:
        """Get enabled rules for a specific language"""
        enabled_rules = [rule for rule in self.rules.values() if rule.enabled]
        if language:
            enabled_rules = [rule for rule in enabled_rules 
                           if rule.language == language or rule.language == "*"]
        return enabled_rules

class ThreatShieldManager:
    """Enhanced threat protection shields management"""
    
    def __init__(self, shields_file: str = "threat_shields.json"):
        self.shields_file = shields_file
        self.shields: Dict[str, ThreatShield] = {}
        self.load_shields()
    
    def load_shields(self):
        """Load threat shields from file"""
        if os.path.exists(self.shields_file):
            try:
                with open(self.shields_file, 'r') as f:
                    shields_data = json.load(f)
                    for shield_data in shields_data:
                        shield = ThreatShield(**shield_data)
                        self.shields[shield.id] = shield
            except Exception as e:
                print(f"Error loading threat shields: {e}")
        else:
            self._create_default_shields()
    
    def _create_default_shields(self):
        """Create default threat protection shields"""
        default_shield = ThreatShield(
            id="logic-bomb-protection-shield",
            name="Logic Bomb Protection Shield",
            is_default=True,
            risk_threshold="MEDIUM_RISK",
            threat_categories=["SCHEDULED_THREAT", "TARGETED_ATTACK", "EXECUTION_TRIGGER", "DESTRUCTIVE_PAYLOAD"],
            protection_rules=[
                {"threat_type": "SCHEDULED_THREAT", "risk_threshold": "HIGH_RISK", "block": True, "alert": True},
                {"threat_type": "TARGETED_ATTACK", "risk_threshold": "CRITICAL_BOMB", "block": True, "alert": True}, 
                {"threat_type": "EXECUTION_TRIGGER", "risk_threshold": "HIGH_RISK", "block": True, "alert": True},
                {"threat_type": "DESTRUCTIVE_PAYLOAD", "risk_threshold": "CRITICAL_BOMB", "block": True, "alert": True},
                {"threat_type": "SYSTEM_SPECIFIC_THREAT", "risk_threshold": "MEDIUM_RISK", "block": False, "alert": True},
                {"threat_type": "CONNECTION_BASED_THREAT", "risk_threshold": "MEDIUM_RISK", "block": False, "alert": True},
                {"threat_type": "FINANCIAL_FRAUD", "risk_threshold": "CRITICAL_BOMB", "block": True, "alert": True}
            ]
        )
        
        self.shields[default_shield.id] = default_shield
        self.save_shields()
    
    def save_shields(self):
        """Save threat shields to file"""
        try:
            shields_data = [asdict(shield) for shield in self.shields.values()]
            with open(self.shields_file, 'w') as f:
                json.dump(shields_data, f, indent=2)
        except Exception as e:
            print(f"Error saving threat shields: {e}")
    
    def evaluate_shield(self, shield_id: str, threat_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate threat shield against detected threats"""
        if shield_id not in self.shields:
            return {"status": "ERROR", "message": "Threat shield not found"}
        
        shield = self.shields[shield_id]
        results = []
        overall_status = "PROTECTED"
        
        for rule in shield.protection_rules:
            threat_count = threat_metrics.get(rule["threat_type"], 0)
            risk_threshold = rule["risk_threshold"]
            should_block = rule.get("block", False)
            
            # Determine if threshold is exceeded
            risk_levels = {"SUSPICIOUS": 1, "LOW_RISK": 2, "MEDIUM_RISK": 3, "HIGH_RISK": 4, "CRITICAL_BOMB": 5}
            threshold_level = risk_levels.get(risk_threshold, 3)
            
            # Check if any threats exceed threshold
            # A threat exceeds threshold if threats are detected AND severity meets threshold
            threat_exceeded = False
            if threat_count > 0:
                # Get actual issues for severity evaluation
                issues = threat_metrics.get("issues", [])
                for issue in issues:
                    if issue.type == rule["threat_type"]:
                        issue_severity_level = risk_levels.get(issue.severity, 1)
                        if issue_severity_level >= threshold_level:
                            threat_exceeded = True
                            break
                # If no matching issues found, use count-based logic
                if not threat_exceeded:
                    threat_exceeded = threat_count > 0
            
            rule_result = {
                "threat_type": rule["threat_type"],
                "threshold": risk_threshold,
                "detected_count": threat_count,
                "threshold_exceeded": threat_exceeded,
                "should_block": should_block,
                "should_alert": rule.get("alert", False)
            }
            
            results.append(rule_result)
            
            if threat_exceeded:
                if should_block:
                    overall_status = "BLOCKED"
                elif overall_status == "PROTECTED":
                    overall_status = "ALERT"
        
        return {
            "status": overall_status,
            "protection_rules": results,
            "shield_name": shield.name
        }

class ThreatIssueManager:
    """Enhanced threat issue management with detailed analysis"""
    
    def __init__(self, issues_file: str = "threat_issues.json"):
        self.issues_file = issues_file
        self.issues: Dict[str, SecurityIssue] = {}
        self.load_issues()
    
    def load_issues(self):
        """Load issues from file"""
        if os.path.exists(self.issues_file):
            try:
                with open(self.issues_file, 'r') as f:
                    issues_data = json.load(f)
                    for issue_data in issues_data:
                        issue = SecurityIssue(**issue_data)
                        self.issues[issue.id] = issue
            except Exception as e:
                print(f"Error loading issues: {e}")
    
    def save_issues(self):
        """Save issues to file"""
        try:
            issues_data = [asdict(issue) for issue in self.issues.values()]
            with open(self.issues_file, 'w') as f:
                json.dump(issues_data, f, indent=2)
        except Exception as e:
            print(f"Error saving issues: {e}")
    
    def create_issue(self, rule_id: str, file_path: str, line_number: int,
                    column: int, message: str, severity: str, issue_type: str,
                    code_snippet: str = "", suggested_fix: str = "", rule: SecurityRule = None) -> SecurityIssue:
        """Create a new enhanced security issue with threat analysis"""
        issue_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        # Enhanced threat analysis
        trigger_analysis = self._analyze_trigger(code_snippet, issue_type)
        payload_analysis = self._analyze_payload(code_snippet, severity)
        threat_level = self._calculate_threat_level(severity, issue_type)
        
        # Get rule-specific information for tech debt
        debt_category = "UNKNOWN"
        business_impact = "Medium"
        effort = 30
        
        if rule:
            debt_category = getattr(rule, 'debt_category', 'UNKNOWN')
            business_impact = getattr(rule, 'business_impact', 'Medium')
            effort = getattr(rule, 'remediation_effort', 30)
            # Debug: Print rule information
            print(f"Creating issue for rule {rule.id}: debt_category={debt_category}, business_impact={business_impact}")
        else:
            print(f"Warning: No rule provided for issue creation with rule_id={rule_id}")
        
        # Map UNKNOWN to appropriate category based on issue type and severity
        if debt_category == "UNKNOWN":
            if issue_type == "SECURITY_TECH_DEBT":
                if "password" in message.lower() or "secret" in message.lower() or "key" in message.lower():
                    debt_category = "HARDCODED_CREDENTIALS"
                elif "url" in message.lower() or "http" in message.lower() or "api" in message.lower():
                    debt_category = "HARDCODED_URLS"
                elif "sql" in message.lower() or "query" in message.lower() or "input" in message.lower():
                    debt_category = "INPUT_VALIDATION"
                elif "library" in message.lower() or "version" in message.lower() or "dependency" in message.lower():
                    debt_category = "VULNERABLE_LIBRARIES"
                elif "cors" in message.lower() or "origin" in message.lower():
                    debt_category = "CORS_POLICY"
                elif "rate" in message.lower() or "limit" in message.lower():
                    debt_category = "RATE_LIMITING"
                elif "cookie" in message.lower() or "session" in message.lower():
                    debt_category = "SECURE_COOKIES"
                elif "ssl" in message.lower() or "tls" in message.lower() or "encryption" in message.lower():
                    debt_category = "SSL_TLS"
                elif "default" in message.lower() or "management" in message.lower():
                    debt_category = "SECRETS_MANAGEMENT"
                else:
                    debt_category = "GENERAL_SECURITY_DEBT"
            elif issue_type == "LOGIC_BOMB":
                debt_category = "MALICIOUS_CODE"
            elif issue_type == "SCHEDULED_THREAT":
                debt_category = "TIME_BASED_THREAT"
            elif issue_type == "TARGETED_ATTACK":
                debt_category = "USER_TARGETED_THREAT"
            elif issue_type == "DESTRUCTIVE_PAYLOAD":
                debt_category = "DESTRUCTIVE_ACTION"
            elif issue_type == "FINANCIAL_FRAUD":
                debt_category = "FINANCIAL_SECURITY"
            else:
                debt_category = "SECURITY_ISSUE"
        
        # Ensure file_path is not empty and extract file_name properly
        if not file_path or file_path.strip() == "":
            file_path = "unknown_file"
            file_name = "unknown_file"
        else:
            file_name = os.path.basename(file_path)
            if not file_name or file_name.strip() == "":
                file_name = "unknown_file"
        
        issue = SecurityIssue(
            id=issue_id,
            rule_id=rule_id,
            file_path=file_path,
            file_name=file_name,
            line_number=line_number,
            column=column,
            message=message,
            severity=severity,
            type=issue_type,
            status="ACTIVE_THREAT",
            creation_date=current_time,
            update_date=current_time,
            effort=effort,
            code_snippet=code_snippet,
            suggested_fix=suggested_fix,
            threat_level=threat_level,
            trigger_analysis=trigger_analysis,
            payload_analysis=payload_analysis,
            debt_category=debt_category,
            business_impact=business_impact
        )
        
        self.issues[issue_id] = issue
        return issue
    
    def _analyze_trigger(self, code_snippet: str, issue_type: str) -> str:
        """Analyze what triggers this threat"""
        trigger_patterns = {
            "SCHEDULED_THREAT": "Triggered by specific date/time conditions",
            "TARGETED_ATTACK": "Triggered when specific user is detected",
            "EXECUTION_TRIGGER": "Triggered after N executions",
            "SYSTEM_SPECIFIC_THREAT": "Triggered on specific system environments",
            "DESTRUCTIVE_PAYLOAD": "Direct destructive action detected",
            "FINANCIAL_FRAUD": "Financial redirection detected",
            "CONNECTION_BASED_THREAT": "Network-based trigger detected"
        }
        
        base_analysis = trigger_patterns.get(issue_type, "Unknown trigger pattern")
        
        # Add specific analysis based on code content
        if "datetime" in code_snippet or "date" in code_snippet:
            base_analysis += " - Date/time comparison found"
        if "user" in code_snippet.lower():
            base_analysis += " - User-specific condition detected"
        if "count" in code_snippet.lower():
            base_analysis += " - Counter-based logic found"
        
        return base_analysis
    
    def _analyze_payload(self, code_snippet: str, severity: str) -> str:
        """Analyze potential damage from this threat"""
        if "delete" in code_snippet or "remove" in code_snippet:
            return "File/directory deletion - Data loss risk"
        elif "format" in code_snippet:
            return "System formatting - Complete data destruction"
        elif "kill" in code_snippet or "terminate" in code_snippet:
            return "Process termination - System disruption"
        elif "corrupt" in code_snippet:
            return "Data corruption - Information integrity loss"
        elif "bitcoin" in code_snippet or "crypto" in code_snippet:
            return "Financial redirection - Money theft risk"
        elif "exec" in code_snippet or "eval" in code_snippet:
            return "Code execution - System compromise risk"
        else:
            return f"Unknown payload - {severity} level threat detected"
    
    def _calculate_threat_level(self, severity: str, issue_type: str) -> str:
        """Calculate overall threat level"""
        if severity == "CRITICAL_BOMB" or issue_type == "DESTRUCTIVE_PAYLOAD":
            return "EXTREME"
        elif severity == "HIGH_RISK":
            return "HIGH"
        elif severity == "MEDIUM_RISK":
            return "MEDIUM"
        else:
            return "LOW"
    
    def update_issue_status(self, issue_id: str, status: str, assignee: str = None):
        """Update issue status"""
        if issue_id in self.issues:
            self.issues[issue_id].status = status
            self.issues[issue_id].update_date = datetime.now().isoformat()
            if assignee:
                self.issues[issue_id].assignee = assignee
            self.save_issues()
    
    def get_active_threats(self) -> List[SecurityIssue]:
        """Get all active threat issues"""
        return [issue for issue in self.issues.values() if issue.status == "ACTIVE_THREAT"]
    
    def get_critical_bombs(self) -> List[SecurityIssue]:
        """Get critical logic bomb threats"""
        return [issue for issue in self.issues.values() 
                if issue.severity == "CRITICAL_BOMB" and issue.status == "ACTIVE_THREAT"]

class ThreatMetricsCalculator:
    """Enhanced threat intelligence metrics calculator"""
    
    @staticmethod
    def calculate_logic_bomb_risk_score(issues: List[SecurityIssue]) -> float:
        """Calculate enhanced logic bomb risk score (0-100)"""
        if not issues:
            return 0.0
        
        risk_weights = {
            "CRITICAL_BOMB": 25,
            "HIGH_RISK": 15,
            "MEDIUM_RISK": 8,
            "LOW_RISK": 3,
            "SUSPICIOUS": 1
        }
        
        total_risk = sum(risk_weights.get(issue.severity, 0) for issue in issues)
        max_possible_risk = len(issues) * 25
        normalized_score = min(100, (total_risk / max_possible_risk) * 100 if max_possible_risk > 0 else 0)
        
        return round(normalized_score, 1)
    
    @staticmethod
    def calculate_threat_intelligence(issues: List[SecurityIssue]) -> Dict[str, Any]:
        """Calculate comprehensive threat intelligence"""
        if not issues:
            return {"threat_level": "MINIMAL", "recommendations": ["No threats detected"]}
        
        # Count by threat type
        threat_types = {}
        for issue in issues:
            threat_types[issue.type] = threat_types.get(issue.type, 0) + 1
        
        # Determine overall threat level
        critical_count = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
        high_count = len([i for i in issues if i.severity == "HIGH_RISK"])
        
        if critical_count > 0:
            threat_level = "CRITICAL"
        elif high_count > 2:
            threat_level = "HIGH" 
        elif high_count > 0:
            threat_level = "ELEVATED"
        else:
            threat_level = "MODERATE"
        
        # Generate recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append(f"URGENT: {critical_count} critical logic bombs detected - Immediate neutralization required")
        if "SCHEDULED_THREAT" in threat_types:
            recommendations.append(f"Time-based triggers detected - Review date/time conditions in {threat_types['SCHEDULED_THREAT']} locations")
        if "DESTRUCTIVE_PAYLOAD" in threat_types:
            recommendations.append(f"Destructive payloads found - High risk of data loss in {threat_types['DESTRUCTIVE_PAYLOAD']} locations")
        if "FINANCIAL_FRAUD" in threat_types:
            recommendations.append(f"Financial fraud patterns detected - Review money handling in {threat_types['FINANCIAL_FRAUD']} locations")
        
        return {
            "threat_level": threat_level,
            "total_threats": len(issues),
            "critical_bombs": critical_count,
            "threat_distribution": threat_types,
            "recommendations": recommendations[:5]
        }
    
    @staticmethod
    def calculate_threat_density(issues: List[SecurityIssue], lines_of_code: int) -> float:
        """Calculate threat density (threats per 1000 lines of code)"""
        if not issues or lines_of_code <= 0:
            return 0.0
        
        total_threats = len(issues)
        threat_density = (total_threats / lines_of_code) * 1000
        return round(threat_density, 1)
    
    @staticmethod
    def calculate_detection_confidence(issues: List[SecurityIssue]) -> float:
        """Calculate average detection confidence based on threat severity and type"""
        if not issues:
            return 85.0  # Default confidence when no issues
        
        # Confidence weights based on severity and type
        confidence_weights = {
            "CRITICAL_BOMB": 95.0,  # High confidence for critical bombs
            "HIGH_RISK": 90.0,      # High confidence for high risk
            "MEDIUM_RISK": 85.0,    # Medium confidence
            "LOW_RISK": 75.0,       # Lower confidence for low risk
            "SUSPICIOUS": 65.0       # Lower confidence for suspicious
        }
        
        # Type-specific confidence adjustments
        type_adjustments = {
            "SCHEDULED_THREAT": 5.0,      # Time-based threats are easier to detect
            "TARGETED_ATTACK": 3.0,       # Targeted attacks have clear patterns
            "EXECUTION_TRIGGER": 2.0,     # Execution triggers are detectable
            "DESTRUCTIVE_PAYLOAD": 8.0,   # Destructive payloads are very detectable
            "FINANCIAL_FRAUD": 7.0,       # Financial fraud has clear patterns
            "SECURITY_TECH_DEBT": 90.0    # Tech debt is very detectable
        }
        
        total_confidence = 0.0
        for issue in issues:
            base_confidence = confidence_weights.get(issue.severity, 80.0)
            type_adjustment = type_adjustments.get(issue.type, 0.0)
            issue_confidence = min(100.0, base_confidence + type_adjustment)
            total_confidence += issue_confidence
        
        avg_confidence = total_confidence / len(issues)
        return round(avg_confidence, 1)
    
    @staticmethod
    def calculate_neutralization_urgency(issues: List[SecurityIssue]) -> float:
        """Calculate neutralization urgency in hours based on threat severity and type"""
        if not issues:
            return 24.0  # Default urgency when no issues
        
        # Urgency weights in hours (lower = more urgent)
        urgency_weights = {
            "CRITICAL_BOMB": 2.0,    # Critical bombs need immediate attention
            "HIGH_RISK": 6.0,        # High risk within 6 hours
            "MEDIUM_RISK": 12.0,     # Medium risk within 12 hours
            "LOW_RISK": 24.0,        # Low risk within 24 hours
            "SUSPICIOUS": 48.0        # Suspicious within 48 hours
        }
        
        # Type-specific urgency adjustments
        type_adjustments = {
            "SCHEDULED_THREAT": -4.0,     # Time-based threats are more urgent
            "TARGETED_ATTACK": -2.0,      # Targeted attacks are urgent
            "EXECUTION_TRIGGER": -1.0,    # Execution triggers are urgent
            "DESTRUCTIVE_PAYLOAD": -6.0,  # Destructive payloads are very urgent
            "FINANCIAL_FRAUD": -3.0,      # Financial fraud is urgent
            "SECURITY_TECH_DEBT": 12.0    # Tech debt is less urgent
        }
        
        # Calculate weighted average urgency
        total_urgency = 0.0
        total_weight = 0.0
        
        for issue in issues:
            base_urgency = urgency_weights.get(issue.severity, 24.0)
            type_adjustment = type_adjustments.get(issue.type, 0.0)
            issue_urgency = max(1.0, base_urgency + type_adjustment)  # Minimum 1 hour
            
            # Weight by severity (critical issues have more weight)
            weight = {"CRITICAL_BOMB": 5, "HIGH_RISK": 3, "MEDIUM_RISK": 2, "LOW_RISK": 1, "SUSPICIOUS": 1}.get(issue.severity, 1)
            
            total_urgency += issue_urgency * weight
            total_weight += weight
        
        if total_weight == 0:
            return 24.0
        
        avg_urgency = total_urgency / total_weight
        return round(avg_urgency, 1)
    
    @staticmethod
    def calculate_shield_effectiveness(issues: List[SecurityIssue], shield_status: str) -> float:
        """Calculate shield effectiveness based on threats blocked vs total threats"""
        if not issues:
            return 95.0  # High effectiveness when no threats
        
        # Base effectiveness based on shield status
        base_effectiveness = {
            "PROTECTED": 85.0,
            "ALERT": 60.0,
            "BLOCKED": 95.0,
            "VULNERABLE": 30.0
        }.get(shield_status, 70.0)
        
        # Calculate threat severity distribution
        total_threats = len(issues)
        critical_threats = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
        high_threats = len([i for i in issues if i.severity == "HIGH_RISK"])
        medium_threats = len([i for i in issues if i.severity == "MEDIUM_RISK"])
        
        # Effectiveness adjustments based on threat profile
        if critical_threats > 0:
            # Critical threats reduce effectiveness significantly
            effectiveness_penalty = min(40.0, critical_threats * 15.0)
            base_effectiveness -= effectiveness_penalty
        elif high_threats > 2:
            # Multiple high threats reduce effectiveness
            effectiveness_penalty = min(25.0, high_threats * 5.0)
            base_effectiveness -= effectiveness_penalty
        elif medium_threats > 5:
            # Many medium threats reduce effectiveness
            effectiveness_penalty = min(15.0, medium_threats * 2.0)
            base_effectiveness -= effectiveness_penalty
        
        # Bonus for low threat density
        if total_threats <= 2:
            base_effectiveness += 10.0
        elif total_threats <= 5:
            base_effectiveness += 5.0
        
        # Ensure effectiveness is within bounds
        final_effectiveness = max(0.0, min(100.0, base_effectiveness))
        return round(final_effectiveness, 1)
    
    @staticmethod
    def calculate_trigger_complexity(issues: List[SecurityIssue]) -> float:
        """Calculate trigger complexity score based on threat types and patterns"""
        if not issues:
            return 0.0  # No complexity when no threats
        
        # Complexity weights based on threat type
        complexity_weights = {
            "SCHEDULED_THREAT": 85.0,      # Time-based triggers are complex
            "TARGETED_ATTACK": 90.0,       # Targeted attacks are very complex
            "EXECUTION_TRIGGER": 75.0,     # Execution triggers are moderately complex
            "DESTRUCTIVE_PAYLOAD": 95.0,   # Destructive payloads are very complex
            "FINANCIAL_FRAUD": 80.0,       # Financial fraud is complex
            "SYSTEM_SPECIFIC_THREAT": 70.0, # System-specific threats are moderately complex
            "CONNECTION_BASED_THREAT": 65.0, # Connection-based threats are less complex
            "SECURITY_TECH_DEBT": 30.0     # Tech debt is less complex
        }
        
        # Severity adjustments
        severity_adjustments = {
            "CRITICAL_BOMB": 15.0,  # Critical bombs are more complex
            "HIGH_RISK": 10.0,      # High risk threats are complex
            "MEDIUM_RISK": 5.0,     # Medium risk threats are moderately complex
            "LOW_RISK": 0.0,        # Low risk threats are simple
            "SUSPICIOUS": -5.0       # Suspicious patterns are less complex
        }
        
        total_complexity = 0.0
        for issue in issues:
            base_complexity = complexity_weights.get(issue.type, 50.0)
            severity_adjustment = severity_adjustments.get(issue.severity, 0.0)
            issue_complexity = max(0.0, min(100.0, base_complexity + severity_adjustment))
            total_complexity += issue_complexity
        
        avg_complexity = total_complexity / len(issues)
        return round(avg_complexity, 1)
    
    @staticmethod
    def calculate_payload_severity(issues: List[SecurityIssue]) -> float:
        """Calculate payload severity score based on threat severity and type"""
        if not issues:
            return 0.0  # No severity when no threats
        
        # Severity weights based on threat type
        severity_weights = {
            "DESTRUCTIVE_PAYLOAD": 95.0,   # Destructive payloads are very severe
            "FINANCIAL_FRAUD": 90.0,       # Financial fraud is very severe
            "TARGETED_ATTACK": 85.0,       # Targeted attacks are severe
            "SCHEDULED_THREAT": 80.0,      # Time-based threats are severe
            "EXECUTION_TRIGGER": 75.0,     # Execution triggers are moderately severe
            "SYSTEM_SPECIFIC_THREAT": 60.0, # System-specific threats are moderately severe
            "CONNECTION_BASED_THREAT": 50.0, # Connection-based threats are less severe
            "SECURITY_TECH_DEBT": 40.0     # Tech debt is less severe
        }
        
        # Severity level adjustments
        severity_level_adjustments = {
            "CRITICAL_BOMB": 20.0,  # Critical bombs are very severe
            "HIGH_RISK": 15.0,      # High risk threats are severe
            "MEDIUM_RISK": 10.0,    # Medium risk threats are moderately severe
            "LOW_RISK": 5.0,        # Low risk threats are less severe
            "SUSPICIOUS": 0.0       # Suspicious patterns are least severe
        }
        
        total_severity = 0.0
        for issue in issues:
            base_severity = severity_weights.get(issue.type, 50.0)
            level_adjustment = severity_level_adjustments.get(issue.severity, 0.0)
            issue_severity = max(0.0, min(100.0, base_severity + level_adjustment))
            total_severity += issue_severity
        
        avg_severity = total_severity / len(issues)
        return round(avg_severity, 1)

class LogicBombDetector:
    """Enhanced main logic bomb detection system"""
    
    def __init__(self, data_dir: str = "threatguard_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize enhanced components
        self.rules_engine = LogicBombRulesEngine(str(self.data_dir / "logic_bomb_rules.json"))
        self.threat_shields = ThreatShieldManager(str(self.data_dir / "threat_shields.json"))
        self.issue_manager = ThreatIssueManager(str(self.data_dir / "threat_issues.json"))
        self.scan_history_file = str(self.data_dir / "scan_history.json")
        
        # Load scan history
        self.scan_history: List[ScanResult] = []
        self.load_scan_history()
    
    def load_scan_history(self):
        """Load scan history from file"""
        if os.path.exists(self.scan_history_file):
            try:
                with open(self.scan_history_file, 'r') as f:
                    history_data = json.load(f)
                    for scan_data in history_data:
                        # Convert issues back to SecurityIssue objects
                        issues = [SecurityIssue(**issue_data) for issue_data in scan_data.get('issues', [])]
                        scan_data['issues'] = issues
                        scan_result = ScanResult(**scan_data)
                        self.scan_history.append(scan_result)
            except Exception as e:
                print(f"Error loading scan history: {e}")
    
    def save_scan_history(self):
        """Save scan history to file"""
        try:
            history_data = []
            for scan in self.scan_history:
                scan_dict = asdict(scan)
                scan_dict['issues'] = [asdict(issue) for issue in scan.issues]
                history_data.append(scan_dict)
            
            with open(self.scan_history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            print(f"Error saving scan history: {e}")
    
    def generate_neutralization_guide(self, issue: SecurityIssue, rule: SecurityRule) -> str:
        """Generate specific neutralization instructions for threats"""
        neutralization_guides = {
            "logic-bomb-time-trigger": "Remove or modify date/time conditions. Use proper scheduling systems instead.",
            "logic-bomb-user-targeted": "Remove user-specific conditions. Implement proper user authentication if needed.",
            "logic-bomb-execution-counter": "Remove counter-based conditions. Use proper iteration controls if needed.",
            "logic-bomb-environment-condition": "Remove environment checks or replace with proper configuration management.",
            "destructive-payload-detector": "CRITICAL: Remove all destructive file operations. Implement proper data management.",
            "logic-bomb-network-trigger": "Replace network failure conditions with proper error handling.",
            "financial-fraud-detector": "URGENT: Remove unauthorized financial redirections. Use legitimate payment systems.",
            "hardcoded-secrets-detector": "Move secrets to environment variables or secure vault services.",
            "sql-injection-detector": "Use parameterized queries or ORM methods to prevent SQL injection.",
            "eval-usage-detector": "Replace eval() with safer alternatives like JSON.parse() for data"
        }
        
        return neutralization_guides.get(rule.id, "Review and remove suspicious conditional logic according to security best practices")
    
    def scan_project(self, project_path: str, project_id: str) -> ScanResult:
        """Enhanced project scanning with comprehensive threat detection"""
        start_time = datetime.now()
        scan_id = str(uuid.uuid4())
        
        print(f"🔍 ThreatGuard Pro: Enhanced scanning for threats in {project_path}")
        
        # Find all source files
        source_files = []
        for ext in ['.py', '.js', '.ts', '.java', '.cs', '.php', '.c', '.cpp', '.go', '.rb']:
            source_files.extend(list(Path(project_path).rglob(f'*{ext}')))
        
        issues = []
        lines_of_code = 0
        
        # Enhanced scan with comprehensive threat detection
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_lines = len(content.splitlines())
                    lines_of_code += file_lines
                
                # Get language from file extension
                language = file_path.suffix[1:] if file_path.suffix else 'unknown'
                
                # Get applicable threat detection rules
                applicable_rules = self.rules_engine.get_enabled_rules(language)
                
                # Scan file with enhanced threat detection
                file_issues = self._scan_file_for_logic_bombs(
                    str(file_path), content, applicable_rules
                )
                issues.extend(file_issues)
                
            except Exception as e:
                print(f"Error scanning file {file_path}: {e}")
        
        # Calculate enhanced threat metrics
        logic_bomb_risk_score = ThreatMetricsCalculator.calculate_logic_bomb_risk_score(issues)
        threat_intelligence = ThreatMetricsCalculator.calculate_threat_intelligence(issues)
        
        # Calculate standard security ratings
        security_rating = self._calculate_security_rating(issues)
        reliability_rating = "A"
        maintainability_rating = "B"
        
        # Evaluate threat shield
        threat_metrics = {
            "SCHEDULED_THREAT": len([i for i in issues if i.type == "SCHEDULED_THREAT"]),
            "TARGETED_ATTACK": len([i for i in issues if i.type == "TARGETED_ATTACK"]),
            "EXECUTION_TRIGGER": len([i for i in issues if i.type == "EXECUTION_TRIGGER"]),
            "DESTRUCTIVE_PAYLOAD": len([i for i in issues if i.type == "DESTRUCTIVE_PAYLOAD"]),
            "FINANCIAL_FRAUD": len([i for i in issues if i.type == "FINANCIAL_FRAUD"]),
            "SYSTEM_SPECIFIC_THREAT": len([i for i in issues if i.type == "SYSTEM_SPECIFIC_THREAT"]),
            "CONNECTION_BASED_THREAT": len([i for i in issues if i.type == "CONNECTION_BASED_THREAT"]),
            "issues": issues  # Pass actual issues for severity evaluation
        }
        
        default_shield = next((s for s in self.threat_shields.shields.values() if s.is_default), None)
        threat_shield_status = "PROTECTED"
        if default_shield:
            shield_eval = self.threat_shields.evaluate_shield(default_shield.id, threat_metrics)
            threat_shield_status = shield_eval["status"]
        
        # Determine project hierarchy tags for the scan
        if issues:
            ait_tag = issues[0].ait_tag if hasattr(issues[0], 'ait_tag') else "AIT"
            spk_tag = issues[0].spk_tag if hasattr(issues[0], 'spk_tag') else "SPK-DEFAULT"
            repo_name = issues[0].repo_name if hasattr(issues[0], 'repo_name') else "unknown-repo"
        else:
            ait_tag = "AIT"
            spk_tag = "SPK-DEFAULT"
            repo_name = "unknown-repo"
        
        # Create enhanced scan result
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        scan_result = ScanResult(
            project_id=project_id,
            scan_id=scan_id,
            timestamp=start_time.isoformat(),
            duration_ms=duration_ms,
            files_scanned=len(source_files),
            lines_of_code=lines_of_code,
            issues=issues,
            coverage=85.0,
            duplications=2.5,
            maintainability_rating=maintainability_rating,
            reliability_rating=reliability_rating,
            security_rating=security_rating,
            threat_shield_status=threat_shield_status,
            logic_bomb_risk_score=logic_bomb_risk_score,
            threat_intelligence=threat_intelligence,
            ait_tag=ait_tag,
            spk_tag=spk_tag,
            repo_name=repo_name
        )
        
        # Save to history
        self.scan_history.append(scan_result)
        self.save_scan_history()
        
        # Save issues to issue manager
        for issue in issues:
            self.issue_manager.issues[issue.id] = issue
        self.issue_manager.save_issues()
        
        print(f"✅ Enhanced scan completed: {len(issues)} threats detected, Risk Score: {logic_bomb_risk_score}")
        
        return scan_result
    
    def _scan_file_for_logic_bombs(self, file_path: str, content: str, 
                                  rules: List[SecurityRule]) -> List[SecurityIssue]:
        """Enhanced file scanning with detailed threat analysis"""
        import re
        
        issues = []
        lines = content.splitlines()
        
        # Ensure file_path is properly set
        if not file_path or file_path.strip() == "":
            file_path = "unknown_file"
        
        for rule in rules:
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                
                for line_num, line in enumerate(lines, 1):
                    matches = pattern.finditer(line)
                    for match in matches:
                        issue = self.issue_manager.create_issue(
                            rule_id=rule.id,
                            file_path=file_path,
                            line_number=line_num,
                            column=match.start() + 1,
                            message=rule.description,
                            severity=rule.severity,
                            issue_type=rule.type,
                            code_snippet=line.strip(),
                            suggested_fix=self.generate_neutralization_guide(None, rule),
                            rule=rule
                        )
                        issues.append(issue)
                        
            except re.error as e:
                print(f"Invalid regex pattern in rule {rule.id}: {e}")
        
        return issues
    
    def _calculate_security_rating(self, issues: List[SecurityIssue]) -> str:
        """Calculate security rating based on threats detected"""
        critical_bombs = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
        high_risks = len([i for i in issues if i.severity == "HIGH_RISK"])
        
        if critical_bombs > 0:
            return "F"
        elif high_risks > 2:
            return "E"
        elif high_risks > 0:
            return "D"
        elif len(issues) > 5:
            return "C"
        elif len(issues) > 0:
            return "B"
        else:
            return "A"
    
    def get_command_center_metrics(self, project_id: str = None) -> Dict[str, Any]:
        """Get enhanced command center metrics for display"""
        if project_id:
            project_scans = [s for s in self.scan_history if s.project_id == project_id]
            latest_scan = max(project_scans, key=lambda x: x.timestamp) if project_scans else None
        else:
            latest_scan = max(self.scan_history, key=lambda x: x.timestamp) if self.scan_history else None
        
        if not latest_scan:
            return {"error": "No scan data available"}
        
        # Calculate enhanced threat counts
        threat_severity_counts = {}
        for severity in ["CRITICAL_BOMB", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "SUSPICIOUS"]:
            threat_severity_counts[severity] = len([i for i in latest_scan.issues if i.severity == severity])
        
        threat_type_counts = {}
        for threat_type in ["SCHEDULED_THREAT", "TARGETED_ATTACK", "EXECUTION_TRIGGER", "DESTRUCTIVE_PAYLOAD", "FINANCIAL_FRAUD"]:
            threat_type_counts[threat_type] = len([i for i in latest_scan.issues if i.type == threat_type])
        
        # Add recent threats data
        recent_threats = []
        for scan in self.scan_history[-5:]:
            for issue in scan.issues[:10]:
                recent_threats.append({
                    'id': issue.id,
                    'rule_id': issue.rule_id,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'message': issue.message,
                    'severity': issue.severity,
                    'type': issue.type,
                    'status': issue.status,
                    'suggested_fix': issue.suggested_fix,
                    'trigger_analysis': issue.trigger_analysis,
                    'payload_analysis': issue.payload_analysis,
                    'threat_level': issue.threat_level,
                    'code_snippet': issue.code_snippet
                })
        
        return {
            "scan_info": {
                "project_id": latest_scan.project_id,
                "scan_date": latest_scan.timestamp,
                "files_scanned": latest_scan.files_scanned,
                "lines_of_code": latest_scan.lines_of_code,
                "duration_ms": latest_scan.duration_ms
            },
            "threat_ratings": {
                "security": latest_scan.security_rating,
                "reliability": latest_scan.reliability_rating,
                "maintainability": latest_scan.maintainability_rating,
                "logic_bomb_risk_score": latest_scan.logic_bomb_risk_score
            },
            "threat_shield": {
                "status": latest_scan.threat_shield_status,
                "protection_effectiveness": ThreatMetricsCalculator.calculate_shield_effectiveness(latest_scan.issues, latest_scan.threat_shield_status)
            },
            "threats": {
                "total": len(latest_scan.issues),
                "by_severity": threat_severity_counts,
                "by_type": threat_type_counts,
                "critical_bombs": len([i for i in latest_scan.issues if i.severity == "CRITICAL_BOMB"]),
                "active_threats": len([i for i in latest_scan.issues if i.status == "ACTIVE_THREAT"])
            },
            "threat_intelligence": latest_scan.threat_intelligence,
            "recent_threats": recent_threats[-20:],
            "logic_bomb_analysis": {
                "by_type": threat_type_counts,
                "by_severity": threat_severity_counts
            },
            "logic_bomb_metrics": {
                "threat_density": ThreatMetricsCalculator.calculate_threat_density(latest_scan.issues, latest_scan.lines_of_code),
                "detection_confidence_avg": ThreatMetricsCalculator.calculate_detection_confidence(latest_scan.issues),
                "neutralization_urgency_hours": ThreatMetricsCalculator.calculate_neutralization_urgency(latest_scan.issues),
                "trigger_complexity_score": ThreatMetricsCalculator.calculate_trigger_complexity(latest_scan.issues),
                "payload_severity_score": ThreatMetricsCalculator.calculate_payload_severity(latest_scan.issues)
            },
            "metrics": {
                "coverage": latest_scan.coverage,
                "duplications": latest_scan.duplications,
                "technical_debt": sum(issue.effort for issue in latest_scan.issues)
            }
        }


if __name__ == "__main__":
    # Example usage
    print("🛡️ ThreatGuard Pro - Enhanced Logic Bomb Detection System")
    print("=" * 60)
    
    detector = LogicBombDetector()
    
    # Enhanced scan demonstration
    result = detector.scan_project(".", "test-project")
    
    print(f"\n📊 Enhanced Scan Results:")
    print(f"Scan completed in {result.duration_ms}ms")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Logic bomb threats found: {len(result.issues)}")
    print(f"Security rating: {result.security_rating}")
    print(f"Logic bomb risk score: {result.logic_bomb_risk_score}/100")
    print(f"Threat shield status: {result.threat_shield_status}")
    
    # Get enhanced command center metrics
    metrics = detector.get_command_center_metrics()
    print(f"\n🎯 Enhanced Command Center Metrics:")
    print(f"Total threats: {metrics['threats']['total']}")
    print(f"Critical bombs: {metrics['threats']['critical_bombs']}")
    print(f"Threat level: {metrics['threat_intelligence']['threat_level']}")
    
    if metrics['threat_intelligence']['recommendations']:
        print(f"\n⚠️ Threat Intelligence Recommendations:")
        for rec in metrics['threat_intelligence']['recommendations']:
            print(f"  • {rec}")
