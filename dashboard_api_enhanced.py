#!/usr/bin/env python3
"""
ThreatGuard Pro - Enhanced Command Center Dashboard API
Advanced Threat Pattern Detection & Threat Intelligence Dashboard
Copyright 2025 - Enhanced with comprehensive security features
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import uuid
import tempfile
from pathlib import Path
import io
import zipfile
from dataclasses import dataclass

# Import our enhanced main threat detector components
from threatguard_main_enhanced import (
    LogicBombDetector, SecurityRule, ThreatShield, SecurityIssue,
    ThreatMetricsCalculator, ScanResult
)

app = Flask(__name__)
CORS(app)

# Initialize enhanced threat pattern detector
detector = LogicBombDetector()

@dataclass
class ThreatPattern:
    """Advanced threat pattern for multi-language detection."""
    pattern_type: str
    description: str
    severity: str
    line_number: int
    code_snippet: str
    confidence: float
    language: str
    trigger_analysis: str = ""
    payload_analysis: str = ""

class AdvancedThreatPatternDetector:
    def __init__(self):
        self.threat_patterns = []
        self.supported_languages = {
            '.py': 'python', '.java': 'java', '.js': 'javascript', '.ts': 'typescript',
            '.cs': 'csharp', '.vb': 'vbnet', '.jsx': 'react', '.tsx': 'react_typescript',
            '.json': 'config', '.html': 'html', '.php': 'php', '.rb': 'ruby',
            '.go': 'golang', '.cpp': 'cpp', '.c': 'c', '.rs': 'rust'
        }
        self.init_threat_pattern_signatures()

    def init_threat_pattern_signatures(self):
        """Initialize comprehensive threat pattern signatures"""
        # Scheduled Threat (Time Bombs)
        self.scheduled_threat_patterns = [
            (r'if.*(?:date|datetime|time).*[><=].*\d{4}.*:.*(?:delete|remove|destroy|format)', "Date-based trigger"),
            (r'(?:datetime\.now|time\.time|Date\.now)\(\).*[><=].*\d+.*:.*(?:rm|del|unlink)', "Time comparison trigger"),
            (r'if.*(?:month|day|year).*==.*\d+.*:.*(?:format|rmdir|system)', "Calendar-based trigger")
        ]
        
        # Targeted Attack (User Bombs)  
        self.targeted_attack_patterns = [
            (r'if.*(?:getuser|username|user|USER).*==.*["\'][^"\']+["\'].*:.*(?:delete|corrupt|destroy)', "User-specific trigger"),
            (r'if.*os\.environ\[["\'](?:USER|USERNAME)["\'].*==.*:.*(?:subprocess|system|exec)', "Environment user check"),
            (r'if.*whoami.*==.*["\'][^"\']+["\'].*:.*(?:rm|del|kill)', "Identity-based trigger")
        ]
        
        # Execution Trigger (Counter Bombs)
        self.execution_trigger_patterns = [
            (r'(?:count|counter|iteration|exec_count)\s*[><=]\s*\d+.*:.*(?:delete|remove|destroy)', "Execution counter"),
            (r'if.*(?:attempts|tries|loops).*==.*\d+.*:.*(?:format|corrupt|terminate)', "Attempt-based trigger"),
            (r'for.*range\(\d+\).*:.*(?:break|exit).*(?:delete|remove)', "Loop-based trigger")
        ]
        
        # System-Specific Threat (Environment Bombs)
        self.system_specific_threat_patterns = [
            (r'if.*(?:hostname|platform|gethostname).*==.*["\'][^"\']*["\'].*:.*(?:sys\.|os\.|subprocess)', "System-specific trigger"),
            (r'if.*(?:env|environment).*!=.*["\'][^"\']*["\'].*:.*(?:destroy|corrupt)', "Environment mismatch trigger"),
            (r'if.*socket\.gethostname.*==.*["\'][^"\']*["\'].*:.*(?:system|exec)', "Network hostname trigger")
        ]
        
        # Destructive payload detection
        self.payload_patterns = [
            (r'(?:shutil\.rmtree|os\.remove|subprocess\.call.*rm|system.*(?:del|rm)|rmdir.*\/s)', "File destruction"),
            (r'(?:format.*c:|mkfs|fdisk|dd.*if=)', "Disk formatting/destruction"),
            (r'(?:kill.*-9|taskkill.*\/f|killall|pkill)', "Process termination"),
            (r'(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM.*WHERE.*1=1)', "Database destruction")
        ]
        
        # Financial Fraud patterns
        self.financial_fraud_patterns = [
            (r'bitcoin.*address.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "Bitcoin address detected"),
            (r'paypal\.me/[a-zA-Z0-9]+', "PayPal redirection"),
            (r'crypto.*wallet.*0x[a-fA-F0-9]{40}', "Crypto wallet address"),
            (r'transfer.*money.*(?:personal|admin|dev)', "Unauthorized money transfer")
        ]
        
        # Connection-Based Threat (Network Bombs)
        self.connection_based_threat_patterns = [
            (r'if.*(?:ping|connect|socket|urllib).*(?:fail|error|timeout).*:.*(?:delete|remove|destroy)', "Network failure trigger"),
            (r'if.*(?:requests\.get|urllib\.request).*(?:status_code|response).*!=.*200.*:.*(?:corrupt|delete)', "HTTP status trigger"),
            (r'if.*(?:socket\.connect|telnet|ssh).*(?:refused|timeout).*:.*(?:system|exec)', "Connection failure trigger")
        ]

    def detect_language(self, filepath: str, content: str) -> str:
        _, ext = os.path.splitext(filepath.lower())
        return self.supported_languages.get(ext, 'unknown')

    def analyze_file(self, filepath: str) -> list:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            language = self.detect_language(filepath, content)
            self.threat_patterns = []
            self._check_all_patterns(content, language, filepath)
            return self.threat_patterns
        except Exception:
            return []

    def _check_all_patterns(self, content: str, language: str, filepath: str):
        lines = content.split('\n')
        
        pattern_groups = [
            (self.scheduled_threat_patterns, "SCHEDULED_THREAT"),
            (self.targeted_attack_patterns, "TARGETED_ATTACK"), 
            (self.execution_trigger_patterns, "EXECUTION_TRIGGER"),
            (self.system_specific_threat_patterns, "SYSTEM_SPECIFIC_THREAT"),
            (self.payload_patterns, "DESTRUCTIVE_PAYLOAD"),
            (self.financial_fraud_patterns, "FINANCIAL_FRAUD"),
            (self.connection_based_threat_patterns, "CONNECTION_BASED_THREAT")
        ]
        
        for pattern_list, threat_type in pattern_groups:
            for pattern, desc in pattern_list:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Enhanced analysis
                        trigger_analysis = self._analyze_trigger_condition(line, threat_type)
                        payload_analysis = self._analyze_payload_potential(line, threat_type)
                        
                        # Determine severity based on threat type and payload
                        severity = self._determine_severity(threat_type, line)
                        confidence = self._calculate_confidence(line, threat_type, pattern)
                        
                        self.threat_patterns.append(
                            ThreatPattern(
                                threat_type, desc, severity, i, line.strip(), 
                                confidence, language, trigger_analysis, payload_analysis
                            )
                        )

    def _analyze_trigger_condition(self, line: str, threat_type: str) -> str:
        """Enhanced trigger analysis"""
        if threat_type == "SCHEDULED_THREAT":
            if re.search(r'\d{4}', line):
                return f"Triggered on specific year: {re.search(r'\d{4}', line).group()}"
            elif "datetime" in line or "time" in line:
                return "Triggered by time-based condition"
        elif threat_type == "TARGETED_ATTACK":
            user_match = re.search(r'["\']([^"\']+)["\']', line)
            if user_match:
                return f"Triggered for user: {user_match.group(1)}"
        elif threat_type == "EXECUTION_TRIGGER":
            count_match = re.search(r'\d+', line)
            if count_match:
                return f"Triggered after {count_match.group()} executions"
        elif threat_type == "SYSTEM_SPECIFIC_THREAT":
            env_match = re.search(r'["\']([^"\']+)["\']', line)
            if env_match:
                return f"Triggered on system: {env_match.group(1)}"
        elif threat_type == "FINANCIAL_FRAUD":
            return "Financial redirection detected - money theft risk"
        return f"Conditional trigger detected for {threat_type}"

    def _analyze_payload_potential(self, line: str, threat_type: str) -> str:
        """Enhanced payload analysis"""
        destructive_keywords = {
            "delete": "File deletion - Data loss",
            "remove": "Data removal - Information loss", 
            "destroy": "Data destruction - Complete loss",
            "format": "System formatting - Total destruction",
            "kill": "Process termination - Service disruption",
            "corrupt": "Data corruption - Integrity loss",
            "truncate": "Database truncation - Data wipe",
            "drop": "Database destruction - Schema loss",
            "bitcoin": "Cryptocurrency theft - Financial loss",
            "transfer": "Unauthorized transfer - Money theft"
        }
        
        for keyword, description in destructive_keywords.items():
            if keyword in line.lower():
                return description
        
        return f"Potential {threat_type} payload detected"

    def _determine_severity(self, threat_type: str, line: str) -> str:
        """Enhanced severity determination"""
        if threat_type == "DESTRUCTIVE_PAYLOAD":
            return "CRITICAL_BOMB"
        elif threat_type == "FINANCIAL_FRAUD":
            return "CRITICAL_BOMB"
        elif "format" in line.lower() or "destroy" in line.lower():
            return "CRITICAL_BOMB"
        elif threat_type in ["SCHEDULED_THREAT", "TARGETED_ATTACK"]:
            return "HIGH_RISK"
        elif threat_type == "EXECUTION_TRIGGER":
            return "MEDIUM_RISK"
        else:
            return "LOW_RISK"

    def _calculate_confidence(self, line: str, threat_type: str, pattern: str) -> float:
        """Enhanced confidence calculation"""
        base_confidence = 0.7
        
        # Increase confidence for specific indicators
        if threat_type == "DESTRUCTIVE_PAYLOAD":
            base_confidence += 0.2
        if threat_type == "FINANCIAL_FRAUD":
            base_confidence += 0.15
        if re.search(r'if.*:.*(?:delete|remove|destroy)', line):
            base_confidence += 0.1
        if len(re.findall(r'(?:delete|remove|destroy|corrupt|kill)', line, re.IGNORECASE)) > 1:
            base_confidence += 0.1
            
        return min(1.0, base_confidence)

# Global advanced threat pattern detector instance
advanced_detector = AdvancedThreatPatternDetector()

@app.route('/api/command-center/metrics')
def get_command_center_metrics():
    """Get enhanced command center metrics"""
    try:
        metrics = detector.get_command_center_metrics()
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logic-bomb-scan', methods=['POST'])
def start_logic_bomb_scan():
    """Start a new logic bomb detection scan"""
    try:
        data = request.get_json()
        project_path = data.get('project_path')
        project_id = data.get('project_id')
        
        if not project_path or not project_id:
            return jsonify({'error': 'Missing project_path or project_id'}), 400
        
        if not os.path.exists(project_path):
            return jsonify({'error': 'Project path does not exist'}), 400
        
        # Start enhanced logic bomb scan
        result = detector.scan_project(project_path, project_id)
        
        return jsonify({
            'scan_id': result.scan_id,
            'project_id': result.project_id,
            'timestamp': result.timestamp,
            'files_scanned': result.files_scanned,
            'logic_bombs_detected': len(result.issues),
            'duration_ms': result.duration_ms,
            'threat_shield_status': result.threat_shield_status,
            'logic_bomb_risk_score': result.logic_bomb_risk_score,
            'threat_level': result.threat_intelligence.get('threat_level', 'UNKNOWN')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Enhanced API endpoints for UI compatibility
@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Enhanced scan endpoint for backward compatibility"""
    try:
        data = request.get_json()
        project_path = data.get('project_path')
        project_id = data.get('project_id')
        
        if not project_path or not project_id:
            return jsonify({'error': 'Missing project_path or project_id'}), 400
        
        if not os.path.exists(project_path):
            return jsonify({'error': 'Project path does not exist'}), 400
        
        # Start enhanced scan
        result = detector.scan_project(project_path, project_id)
        
        return jsonify({
            'scan_id': result.scan_id,
            'project_id': result.project_id,
            'timestamp': result.timestamp,
            'files_scanned': result.files_scanned,
            'issues_found': len(result.issues),
            'duration_ms': result.duration_ms,
            'quality_gate_status': result.threat_shield_status
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats')
def get_threats():
    """Get all threat issues"""
    try:
        threats = []
        for issue in detector.issue_manager.issues.values():
            threats.append({
                'id': issue.id,
                'rule_id': issue.rule_id,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'column': issue.column,
                'message': issue.message,
                'severity': issue.severity,
                'type': issue.type,
                'status': issue.status,
                'assignee': issue.assignee,
                'creation_date': issue.creation_date,
                'update_date': issue.update_date,
                'effort': issue.effort,
                'code_snippet': issue.code_snippet,
                'suggested_fix': issue.suggested_fix,
                'threat_level': issue.threat_level,
                'trigger_analysis': issue.trigger_analysis,
                'payload_analysis': issue.payload_analysis
            })
        
        return jsonify(threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics/summary')
def get_metrics_summary():
    """Get summary metrics across all scans"""
    try:
        if not detector.scan_history:
            return jsonify({'error': 'No scan data available'})
        
        latest_scan = max(detector.scan_history, key=lambda x: x.timestamp)
        all_issues = []
        for scan in detector.scan_history[-10:]:  # Last 10 scans
            all_issues.extend(scan.issues)
        
        # Calculate trend data
        trends = {
            'security_rating_trend': [],
            'issues_trend': [],
            'coverage_trend': []
        }
        
        for scan in detector.scan_history[-10:]:
            trends['security_rating_trend'].append({
                'date': scan.timestamp,
                'value': ord(scan.security_rating) - ord('A') + 1
            })
            trends['issues_trend'].append({
                'date': scan.timestamp,
                'value': len(scan.issues)
            })
            trends['coverage_trend'].append({
                'date': scan.timestamp,
                'value': scan.coverage
            })
        
        summary = {
            'total_scans': len(detector.scan_history),
            'total_projects': len(set(scan.project_id for scan in detector.scan_history)),
            'total_issues': len(all_issues),
            'open_issues': len([i for i in all_issues if i.status == 'OPEN']),
            'resolved_issues': len([i for i in all_issues if i.status == 'RESOLVED']),
            'average_scan_duration': sum(scan.duration_ms for scan in detector.scan_history) / len(detector.scan_history),
            'latest_scan': {
                'project_id': latest_scan.project_id,
                'timestamp': latest_scan.timestamp,
                'security_rating': latest_scan.security_rating,
                'quality_gate_status': latest_scan.quality_gate_status
            },
            'trends': trends,
            'top_rules_violated': _get_top_rules_violated(all_issues),
            'issues_by_severity': _get_issues_by_severity(all_issues),
            'issues_by_type': _get_issues_by_type(all_issues)
        }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
def _get_top_rules_violated(issues):
    """Get top rules violated"""
    rule_counts = {}
    for issue in issues:
        rule_counts[issue.rule_id] = rule_counts.get(issue.rule_id, 0) + 1

    # Sort by count and return top 10
    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    return [{'rule_id': rule, 'count': count} for rule, count in sorted_rules[:10]]

def _get_issues_by_severity(issues):
    """Get issues grouped by severity"""
    severity_counts = {}
    for issue in issues:
        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
    return severity_counts

def _get_issues_by_type(issues):
    """Get issues grouped by type"""
    type_counts = {}
    for issue in issues:
        type_counts[issue.type] = type_counts.get(issue.type, 0) + 1
    return type_counts


@app.route('/api/issues')
def get_issues():
    """Backward compatibility endpoint for issues"""
    return get_threats()

@app.route('/api/threats/<threat_id>/status', methods=['PUT'])
def update_threat_status(threat_id):
    """Update threat status"""
    try:
        data = request.get_json()
        status = data.get('status')
        assignee = data.get('assignee')
        
        if not status:
            return jsonify({'error': 'Missing status'}), 400
        
        detector.issue_manager.update_issue_status(threat_id, status, assignee)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/issues/<issue_id>/status', methods=['PUT'])
def update_issue_status(issue_id):
    """Backward compatibility endpoint for issue status"""
    return update_threat_status(issue_id)

@app.route('/api/threats/<threat_id>/neutralize', methods=['POST'])
def neutralize_threat(threat_id):
    """Neutralize a specific threat"""
    try:
        detector.issue_manager.update_issue_status(threat_id, "NEUTRALIZED")
        return jsonify({'success': True, 'message': 'Threat neutralized'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-shields')
def get_threat_shields():
    """Get all threat shields"""
    try:
        shields = {}
        for shield_id, shield in detector.threat_shields.shields.items():
            shields[shield_id] = {
                'id': shield.id,
                'name': shield.name,
                'protection_rules': shield.protection_rules,
                'is_default': shield.is_default,
                'threat_categories': shield.threat_categories,
                'risk_threshold': shield.risk_threshold
            }
        
        return jsonify(shields)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Backward compatibility - map to threat shields
@app.route('/api/quality-gates')
def get_quality_gates():
    """Backward compatibility endpoint for quality gates"""
    return get_threat_shields()

@app.route('/api/threat-shields', methods=['POST'])
def create_threat_shield():
    """Create a new threat shield"""
    try:
        data = request.get_json()
        
        shield_id = str(uuid.uuid4())
        shield = ThreatShield(
            id=shield_id,
            name=data['name'],
            protection_rules=data.get('protection_rules', []),
            is_default=data.get('is_default', False),
            threat_categories=data.get('threat_categories', []),
            risk_threshold=data.get('risk_threshold', 'MEDIUM_RISK')
        )
        
        detector.threat_shields.shields[shield_id] = shield
        detector.threat_shields.save_shields()
        
        return jsonify({'success': True, 'shield_id': shield_id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence')
def get_threat_intelligence():
    """Get threat intelligence data"""
    try:
        history = []
        for scan in detector.scan_history:
            history.append({
                'scan_id': scan.scan_id,
                'project_id': scan.project_id,
                'timestamp': scan.timestamp,
                'duration_ms': scan.duration_ms,
                'files_scanned': scan.files_scanned,
                'logic_bombs': len(scan.issues),
                'logic_bomb_risk_score': scan.logic_bomb_risk_score,
                'threat_shield_status': scan.threat_shield_status,
                'threat_level': scan.threat_intelligence.get('threat_level', 'UNKNOWN') if scan.threat_intelligence else 'UNKNOWN'
            })
        
        # Sort by timestamp, newest first
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Calculate intelligence stats
        total_scans = len(history)
        threats_neutralized = len([i for i in detector.issue_manager.issues.values() if i.status == "NEUTRALIZED"])
        avg_risk_score = sum(h.get('logic_bomb_risk_score', 0) for h in history) / max(1, total_scans)
        shield_effectiveness = len([h for h in history if h['threat_shield_status'] == 'PROTECTED']) / max(1, total_scans) * 100
        
        return jsonify({
            'scan_history': history,
            'total_scans': total_scans,
            'threats_neutralized': threats_neutralized,
            'avg_risk_score': round(avg_risk_score, 1),
            'shield_effectiveness': round(shield_effectiveness, 1)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules')
def get_rules():
    """Get all security rules"""
    try:
        rules = {}
        for rule_id, rule in detector.rules_engine.rules.items():
            rules[rule_id] = {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'type': rule.type,
                'language': rule.language,
                'pattern': rule.pattern,
                'remediation_effort': rule.remediation_effort,
                'tags': rule.tags,
                'enabled': rule.enabled,
                'custom': rule.custom,
                'threat_category': rule.threat_category
            }
        
        return jsonify(rules)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules', methods=['POST'])
def create_rule():
    """Create a new security rule"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['id', 'name', 'description', 'severity', 'type', 'language', 'pattern']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if rule ID already exists
        if data['id'] in detector.rules_engine.rules:
            return jsonify({'error': 'Rule ID already exists'}), 400
        
        # Create new rule
        rule = SecurityRule(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            severity=data['severity'],
            type=data['type'],
            language=data['language'],
            pattern=data['pattern'],
            remediation_effort=data.get('remediation_effort', 30),
            tags=data.get('tags', []),
            enabled=data.get('enabled', True),
            custom=data.get('custom', True),
            threat_category=data.get('threat_category', 'UNKNOWN')
        )
        
        detector.rules_engine.add_rule(rule)
        return jsonify({'success': True, 'rule_id': rule.id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Update a security rule"""
    try:
        data = request.get_json()
        
        if rule_id not in detector.rules_engine.rules:
            return jsonify({'error': 'Rule not found'}), 404
        
        detector.rules_engine.update_rule(rule_id, data)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete a security rule"""
    try:
        if rule_id not in detector.rules_engine.rules:
            return jsonify({'error': 'Rule not found'}), 404
        
        detector.rules_engine.delete_rule(rule_id)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/files', methods=['POST'])
def scan_uploaded_files():
    """Enhanced file scanning with advanced threat detection"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id', str(uuid.uuid4()))
        scan_type = data.get('scan_type', 'quick')
        file_contents = data.get('file_contents', [])
        project_id = data.get('project_id', f'upload-scan-{int(datetime.now().timestamp())}')
        project_name = data.get('project_name', 'File Upload Scan')

        if not file_contents:
            return jsonify({'error': 'No files provided'}), 400

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            file_paths = []

            for file_data in file_contents:
                file_path = temp_path / file_data['name']
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['content'])

                file_paths.append({
                    'id': file_data['id'],
                    'name': file_data['name'],
                    'path': str(file_path),
                    'type': file_data['type']
                })

            # Enhanced file scan with comprehensive threat analysis
            scan_result = perform_enhanced_file_scan(
                scan_id=scan_id,
                project_id=project_id,
                project_name=project_name,
                file_paths=file_paths,
                scan_type=scan_type
            )

            return jsonify(scan_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def perform_enhanced_file_scan(scan_id: str, project_id: str, project_name: str, 
                              file_paths: list, scan_type: str = 'quick') -> dict:
    """Enhanced file scan with comprehensive threat detection"""
    start_time = datetime.now()
    total_issues = []
    total_threat_patterns = []
    file_results = []
    total_lines = 0

    for file_info in file_paths:
        try:
            file_path = file_info['path']
            file_name = file_info['name']
            file_type = file_info['type']
            file_id = file_info['id']

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.splitlines()
            file_lines = len(lines)
            total_lines += file_lines

            # Enhanced standard security rules scan
            applicable_rules = detector.rules_engine.get_enabled_rules(file_type)
            file_issues = scan_file_content(file_name, content, applicable_rules, file_id)

            # Advanced threat pattern detection
            threat_matches = advanced_detector.analyze_file(file_path)
            threat_issues = [
                detector.issue_manager.create_issue(
                    rule_id=f"MALWARE_{pattern.pattern_type}",
                    file_path=file_name,
                    line_number=pattern.line_number,
                    column=1,
                    message=f"{pattern.description} - {pattern.trigger_analysis}",
                    severity=pattern.severity,
                    issue_type=pattern.pattern_type,
                    code_snippet=pattern.code_snippet,
                    suggested_fix=f"Remove {pattern.pattern_type.lower()} behavior - {pattern.payload_analysis}"
                )
                for pattern in threat_matches
            ]

            all_issues = file_issues + threat_issues

            # Enhanced threat metrics per file
            logic_bomb_count = len([p for p in threat_matches if 'BOMB' in p.pattern_type or 'TRIGGER' in p.pattern_type])
            critical_threats = len([i for i in all_issues if i.severity in ['BLOCKER', 'CRITICAL', 'CRITICAL_BOMB']])
            
            file_result = {
                'file_id': file_id,
                'file_name': file_name,
                'file_type': file_type,
                'lines_scanned': file_lines,
                'issues': [format_issue_for_response(issue) for issue in all_issues],
                'issues_count': len(all_issues),
                'logic_bomb_count': logic_bomb_count,
                'threat_pattern_count': len(threat_matches),
                'critical_threats': critical_threats,
                'scan_status': 'completed',
                'threat_level': determine_file_threat_level(all_issues, threat_matches)
            }

            file_results.append(file_result)
            total_issues.extend(all_issues)
            total_threat_patterns.extend(threat_matches)

        except Exception as e:
            file_results.append({
                'file_id': file_info['id'],
                'file_name': file_info['name'],
                'file_type': file_info['type'],
                'scan_status': 'error',
                'error_message': str(e)
            })

    # Enhanced metrics calculation
    logic_bomb_risk_score = ThreatMetricsCalculator.calculate_logic_bomb_risk_score(total_issues)
    threat_intelligence = ThreatMetricsCalculator.calculate_threat_intelligence(total_issues)
    
    # Calculate threat-specific metrics
    threat_metrics = {
        "SCHEDULED_THREAT": len([p for p in total_threat_patterns if p.pattern_type == "SCHEDULED_THREAT"]),
        "TARGETED_ATTACK": len([p for p in total_threat_patterns if p.pattern_type == "TARGETED_ATTACK"]),
        "EXECUTION_TRIGGER": len([p for p in total_threat_patterns if p.pattern_type == "EXECUTION_TRIGGER"]),
        "DESTRUCTIVE_PAYLOAD": len([p for p in total_threat_patterns if p.pattern_type == "DESTRUCTIVE_PAYLOAD"]),
        "FINANCIAL_FRAUD": len([p for p in total_threat_patterns if p.pattern_type == "FINANCIAL_FRAUD"]),
        "SYSTEM_SPECIFIC_THREAT": len([p for p in total_threat_patterns if p.pattern_type == "SYSTEM_SPECIFIC_THREAT"]),
        "CONNECTION_BASED_THREAT": len([p for p in total_threat_patterns if p.pattern_type == "CONNECTION_BASED_THREAT"])
    }

    # Evaluate threat shield
    default_shield = next((s for s in detector.threat_shields.shields.values() if s.is_default), None)
    shield_result = detector.threat_shields.evaluate_shield(default_shield.id, threat_metrics) if default_shield else {}
    shield_status = shield_result.get("status", "PROTECTED")

    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
    timestamp = start_time.isoformat()

    # Create enhanced scan result object
    scan_result_obj = ScanResult(
        project_id=project_id,
        scan_id=scan_id,
        timestamp=timestamp,
        duration_ms=duration_ms,
        files_scanned=len(file_paths),
        lines_of_code=total_lines,
        issues=total_issues,
        coverage=85.0,
        duplications=2.0,
        maintainability_rating="B",
        reliability_rating="A",
        security_rating=calculate_security_rating_from_issues(total_issues),
        threat_shield_status=shield_status,
        logic_bomb_risk_score=logic_bomb_risk_score,
        threat_intelligence=threat_intelligence
    )

    # Save to detector (history + issues)
    detector.scan_history.append(scan_result_obj)
    detector.save_scan_history()

    for issue in total_issues:
        detector.issue_manager.issues[issue.id] = issue
    detector.issue_manager.save_issues()

    return {
        'scan_id': scan_id,
        'project_id': project_id,
        'project_name': project_name,
        'scan_type': scan_type,
        'timestamp': timestamp,
        'duration_ms': duration_ms,
        'files_scanned': len(file_paths),
        'lines_of_code': total_lines,
        'file_results': file_results,
        'summary': {
            'total_issues': len(total_issues),
            'logic_bomb_patterns_found': len(total_threat_patterns),
            'critical_threats': len([i for i in total_issues if i.severity in ['BLOCKER', 'CRITICAL', 'CRITICAL_BOMB']]),
            'security_rating': calculate_security_rating_from_issues(total_issues),
            'logic_bomb_risk_score': logic_bomb_risk_score,
            'threat_level': threat_intelligence.get('threat_level', 'MINIMAL'),
            'quality_gate_passed': shield_status == "PROTECTED",
            'technical_debt_hours': sum(getattr(i, 'effort', 0) for i in total_issues) // 60
        },
        'logic_bomb_metrics': threat_metrics,
        'metrics': {
            'coverage': 85.0,
            'duplications': 2.0,
            'lines_of_code': total_lines,
            'maintainability_rating': "B",
            'reliability_rating': "A",
            'security_rating': calculate_security_rating_from_issues(total_issues),
            'technical_debt_hours': sum(getattr(i, 'effort', 0) for i in total_issues) // 60
        },
        'threat_shield': {
            'status': shield_status,
            'message': 'Threat Shield Active' if shield_status == 'PROTECTED' else 'Threats Detected'
        },
        'threat_intelligence': threat_intelligence,
        'issue_breakdown': {
            'by_file': {f['file_name']: f['issues_count'] for f in file_results},
            'by_severity': {
                severity: len([i for i in total_issues if i.severity == severity])
                for severity in ['CRITICAL_BOMB', 'HIGH_RISK', 'MEDIUM_RISK', 'LOW_RISK', 'CRITICAL', 'MAJOR', 'MINOR']
            },
            'by_type': {
                threat_type: count for threat_type, count in threat_metrics.items()
            }
        }
    }

def determine_file_threat_level(issues: list, patterns: list) -> str:
    """Determine threat level for a specific file"""
    critical_count = len([i for i in issues if i.severity in ['CRITICAL_BOMB', 'CRITICAL']])
    high_count = len([i for i in issues if i.severity in ['HIGH_RISK', 'MAJOR']])
    pattern_count = len(patterns)
    
    if critical_count > 0 or pattern_count > 2:
        return "CRITICAL"
    elif high_count > 1 or pattern_count > 0:
        return "HIGH"
    elif high_count > 0:
        return "MEDIUM"
    else:
        return "LOW"

def calculate_security_rating_from_issues(issues: list) -> str:
    """Calculate security rating based on issues detected"""
    critical_bombs = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
    critical_issues = len([i for i in issues if i.severity == "CRITICAL"])
    high_risks = len([i for i in issues if i.severity == "HIGH_RISK"])
    
    if critical_bombs > 0:
        return "F"
    elif critical_issues > 0:
        return "E"
    elif high_risks > 2:
        return "D"
    elif high_risks > 0:
        return "C"
    elif len(issues) > 5:
        return "B"
    else:
        return "A"

def format_issue_for_response(issue) -> dict:
    """Format issue for JSON response"""
    return {
        'id': issue.id,
        'rule_id': issue.rule_id,
        'line_number': issue.line_number,
        'column': issue.column,
        'message': issue.message,
        'severity': issue.severity,
        'type': issue.type,
        'status': issue.status,
        'code_snippet': issue.code_snippet,
        'suggested_fix': issue.suggested_fix,
        'threat_level': getattr(issue, 'threat_level', 'UNKNOWN'),
        'trigger_analysis': getattr(issue, 'trigger_analysis', ''),
        'payload_analysis': getattr(issue, 'payload_analysis', ''),
        'effort_minutes': getattr(issue, 'effort', 0)
    }

def scan_file_content(file_name: str, content: str, rules: list, file_id: str) -> list:
    """Scan file content with security rules"""
    import re
    issues = []
    lines = content.splitlines()

    for rule in rules:
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)

            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issue = detector.issue_manager.create_issue(
                        rule_id=rule.id,
                        file_path=file_name,
                        line_number=line_num,
                        column=match.start() + 1,
                        message=rule.description,
                        severity=rule.severity,
                        issue_type=rule.type,
                        code_snippet=line.strip(),
                        suggested_fix=generate_fix_suggestion(rule, line.strip())
                    )
                    issue.effort = rule.remediation_effort
                    issues.append(issue)

        except re.error as e:
            print(f"⚠️ Invalid regex in rule {rule.id}: {e}")

    return issues

def generate_fix_suggestion(rule, code_snippet: str) -> str:
    """Generate specific fix suggestions based on rule and code"""
    suggestions = {
        'logic-bomb-time-trigger': f"Remove time-based conditions: {code_snippet[:50]}... Use proper scheduling systems instead.",
        'logic-bomb-user-targeted': f"Remove user-specific targeting: {code_snippet[:50]}... Implement proper authentication.",
        'logic-bomb-execution-counter': f"Remove execution counters: {code_snippet[:50]}... Use proper iteration controls.",
        'destructive-payload-detector': f"CRITICAL: Remove destructive operations: {code_snippet[:50]}... Implement proper data management.",
        'financial-fraud-detector': f"URGENT: Remove financial redirections: {code_snippet[:50]}... Use legitimate payment systems.",
        'hardcoded-secrets-detector': f"Move secrets to environment variables: os.getenv('SECRET_KEY')",
        'sql-injection-detector': "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        'eval-usage-detector': "Replace eval() with JSON.parse() for data or safer alternatives"
    }
    
    base_suggestion = suggestions.get(rule.id, "Review and fix according to security best practices")
    
    # Add context-specific suggestions
    if 'password' in code_snippet.lower():
        return f"{base_suggestion}. Consider using secure password hashing with bcrypt or argon2."
    elif 'key' in code_snippet.lower():
        return f"{base_suggestion}. Use a secure key management service."
    elif 'token' in code_snippet.lower():
        return f"{base_suggestion}. Generate tokens securely and store them encrypted."
    
    return base_suggestion

@app.route('/api/export')
def export_data():
    """Export all scanner data"""
    try:
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'export_type': 'threatguard_pro_data',
            'rules': [
                {
                    'id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'type': rule.type,
                    'language': rule.language,
                    'pattern': rule.pattern,
                    'remediation_effort': rule.remediation_effort,
                    'tags': rule.tags,
                    'enabled': rule.enabled,
                    'custom': rule.custom,
                    'threat_category': rule.threat_category
                }
                for rule in detector.rules_engine.rules.values()
            ],
            'threat_shields': [
                {
                    'id': shield.id,
                    'name': shield.name,
                    'protection_rules': shield.protection_rules,
                    'is_default': shield.is_default,
                    'threat_categories': shield.threat_categories,
                    'risk_threshold': shield.risk_threshold
                }
                for shield in detector.threat_shields.shields.values()
            ],
            'threats': [
                {
                    'id': issue.id,
                    'rule_id': issue.rule_id,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'column': issue.column,
                    'message': issue.message,
                    'severity': issue.severity,
                    'type': issue.type,
                    'status': issue.status,
                    'assignee': issue.assignee,
                    'creation_date': issue.creation_date,
                    'update_date': issue.update_date,
                    'effort': issue.effort,
                    'code_snippet': issue.code_snippet,
                    'suggested_fix': issue.suggested_fix,
                    'threat_level': issue.threat_level,
                    'trigger_analysis': issue.trigger_analysis,
                    'payload_analysis': issue.payload_analysis
                }
                for issue in detector.issue_manager.issues.values()
            ],
            'scan_history': [
                {
                    'scan_id': scan.scan_id,
                    'project_id': scan.project_id,
                    'timestamp': scan.timestamp,
                    'duration_ms': scan.duration_ms,
                    'files_scanned': scan.files_scanned,
                    'lines_of_code': scan.lines_of_code,
                    'coverage': scan.coverage,
                    'duplications': scan.duplications,
                    'maintainability_rating': scan.maintainability_rating,
                    'reliability_rating': scan.reliability_rating,
                    'security_rating': scan.security_rating,
                    'threat_shield_status': scan.threat_shield_status,
                    'logic_bomb_risk_score': scan.logic_bomb_risk_score,
                    'threats_count': len(scan.issues)
                }
                for scan in detector.scan_history
            ]
        }
        
        response = app.response_class(
            response=json.dumps(export_data, indent=2),
            status=200,
            mimetype='application/json'
        )
        response.headers['Content-Disposition'] = 'attachment; filename=threatguard_pro_export.json'
        
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced system health check for ThreatGuard Pro"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'scanner_status': 'operational',
        'malware_detection': 'enabled',
        'threat_detection': 'enhanced',
        'supported_languages': list(advanced_detector.supported_languages.values()),
        'data_directory': str(detector.data_dir),
        'rules_count': len(detector.rules_engine.rules),
        'quality_gates_count': len(detector.threat_shields.shields),
        'total_issues': len(detector.issue_manager.issues),
        'scan_history_count': len(detector.scan_history),
        'active_threats': len(detector.issue_manager.get_active_threats()),
        'critical_bombs': len(detector.issue_manager.get_critical_bombs()),
        'system_features': {
            'logic_bomb_detection': 'enabled',
            'advanced_pattern_matching': 'enabled',
            'threat_intelligence': 'enabled',
            'real_time_analysis': 'enabled',
            'auto_neutralization': 'available'
        }
    })

# Additional endpoints for UI compatibility
@app.route('/api/dashboard/metrics')
def get_dashboard_metrics():
    """Backward compatibility endpoint for dashboard metrics"""
    return get_command_center_metrics()

@app.route('/api/scan-history')
def get_scan_history():
    """Get scan history"""
    return get_threat_intelligence()

# Delete endpoints for admin panel
@app.route('/api/threats', methods=['DELETE'])
def delete_all_threats():
    """Delete all threats"""
    try:
        detector.issue_manager.issues.clear()
        detector.issue_manager.save_issues()
        return jsonify({'success': True, 'message': 'All threats deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/issues', methods=['DELETE'])
def delete_all_issues():
    """Backward compatibility endpoint for deleting all issues"""
    return delete_all_threats()

@app.route('/api/scan-history', methods=['DELETE'])
def delete_scan_history():
    """Delete scan history"""
    try:
        detector.scan_history.clear()
        detector.save_scan_history()
        return jsonify({'success': True, 'message': 'Scan history cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting ThreatGuard Pro Enhanced Dashboard...")
    print("🛡️ Advanced Logic Bomb Detection & Threat Intelligence enabled:")
    print("  • Enhanced Threat Pattern Detection")
    print("  • Real-time Logic Bomb Analysis")
    print("  • Advanced Threat Intelligence")
    print("  • Comprehensive Threat Shields")
    print("  • Financial Fraud Detection")
    print("  • User-targeted Attack Detection")
    print("  • Time-based Trigger Detection")
    print("  • Destructive Payload Analysis")
    print("\n🌐 ThreatGuard Command Center available at: http://localhost:5000")
    print("📋 Enhanced API endpoints:")
    print("  • GET  /api/command-center/metrics - Enhanced threat metrics")
    print("  • POST /api/logic-bomb-scan - Advanced logic bomb scan")
    print("  • GET  /api/threats - Comprehensive threat management")
    print("  • GET  /api/threat-shields - Threat protection shields")
    print("  • GET  /api/threat-intelligence - Threat intelligence data")
    print("  • POST /api/scan/files - Enhanced file scanning")
    print("  • GET  /api/health - System health monitoring")
    print("="*80)
    
    app.run(host='127.0.0.1', port=5000, debug=True)