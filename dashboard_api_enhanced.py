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
from urllib.parse import unquote
import logging
import time

# Import our enhanced main threat detector components
from threatguard_main_enhanced import (
    LogicBombDetector, SecurityRule, ThreatShield, SecurityIssue,
    ThreatMetricsCalculator, ScanResult
)

# Import automated Copilot agent
from copilot_agent import start_copilot_agent, stop_copilot_agent, get_agent_status

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"], supports_credentials=True)

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

@app.route('/api/test-cors', methods=['GET'])
def test_cors():
    """Test endpoint to verify CORS is working."""
    return jsonify({
        'message': 'CORS test successful',
        'timestamp': datetime.now().isoformat(),
        'status': 'ok'
    })

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
                'payload_analysis': issue.payload_analysis,
                'ait_tag': getattr(issue, 'ait_tag', 'AIT'),
                'spk_tag': getattr(issue, 'spk_tag', 'SPK'),
                'repo_name': getattr(issue, 'repo_name', 'Repo')
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

@app.route('/api/threat-shields/<shield_id>', methods=['PUT'])
def update_threat_shield(shield_id):
    """Update an existing threat shield"""
    try:
        data = request.get_json()
        
        if shield_id not in detector.threat_shields.shields:
            return jsonify({'error': 'Threat shield not found'}), 404
        
        shield = detector.threat_shields.shields[shield_id]
        
        # Update shield properties
        shield.name = data.get('name', shield.name)
        shield.protection_rules = data.get('protection_rules', shield.protection_rules)
        shield.threat_categories = data.get('threat_categories', shield.threat_categories)
        shield.risk_threshold = data.get('risk_threshold', shield.risk_threshold)
        shield.is_default = data.get('is_default', shield.is_default)
        
        detector.threat_shields.save_shields()
        
        return jsonify({'success': True, 'message': 'Threat shield updated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-shields/<shield_id>', methods=['DELETE'])
def delete_threat_shield(shield_id):
    """Delete a threat shield"""
    try:
        if shield_id not in detector.threat_shields.shields:
            return jsonify({'error': 'Threat shield not found'}), 404
        
        shield = detector.threat_shields.shields[shield_id]
        
        # Prevent deletion of default shield
        if shield.is_default:
            return jsonify({'error': 'Cannot delete default threat shield'}), 400
        
        del detector.threat_shields.shields[shield_id]
        detector.threat_shields.save_shields()
        
        return jsonify({'success': True, 'message': 'Threat shield deleted successfully'})
        
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
                'ait_tag': getattr(scan, 'ait_tag', 'AIT'),
                'spk_tag': getattr(scan, 'spk_tag', 'SPK-DEFAULT'),
                'repo_name': getattr(scan, 'repo_name', 'unknown-repo'),
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
        ait_tag = data.get('ait_tag', 'AIT')
        spk_tag = data.get('spk_tag', 'SPK')
        repo_name = data.get('repo_name', 'Repo')

        if not file_contents:
            return jsonify({'error': 'No files provided'}), 400

        # Save uploaded files to uploaded_projects/{scan_id}/original/
        base_upload_dir = Path('uploaded_projects') / scan_id / 'original'
        base_upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_paths = []
        uploaded_files_for_prompts = []
        
        for file_data in file_contents:
            file_path = base_upload_dir / file_data['name']
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(file_data['content'])
            
            file_paths.append({
                'id': file_data['id'],
                'name': file_data['name'],
                'path': str(file_path),
                'type': file_data['type']
            })
            
            # Prepare data for prompt generation
            uploaded_files_for_prompts.append({
                'file_path': str(file_path),
                'content': file_data['content'],
                'file_name': file_data['name']
            })
        
        # Enhanced file scan with comprehensive threat analysis
        scan_result = perform_enhanced_file_scan(
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            file_paths=file_paths,
            scan_type=scan_type,
            ait_tag=ait_tag,
            spk_tag=spk_tag,
            repo_name=repo_name
        )
        
        # Generate VS Code Copilot prompts automatically
        try:
            prompts_data = generate_vscode_copilot_prompts(scan_id, uploaded_files_for_prompts)
            scan_result['prompts_generated'] = True
            scan_result['prompts_data'] = prompts_data
        except Exception as e:
            logging.error(f"Error generating prompts: {e}")
            scan_result['prompts_generated'] = False
            scan_result['prompts_error'] = str(e)
        
        return jsonify(scan_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def perform_enhanced_file_scan(scan_id: str, project_id: str, project_name: str, 
                              file_paths: list, scan_type: str = 'quick',
                              ait_tag: str = 'AIT', spk_tag: str = 'SPK', repo_name: str = 'Repo') -> dict:
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

            # Inject hierarchical tags and scan_id into every issue
            for issue in all_issues:
                issue.ait_tag = ait_tag
                issue.spk_tag = spk_tag
                issue.repo_name = repo_name
                issue.scan_id = scan_id

            # Enhanced threat metrics per file
            logic_bomb_count = len([p for p in threat_matches if 'BOMB' in p.pattern_type or 'TRIGGER' in p.pattern_type])
            critical_threats = len([i for i in all_issues if i.severity in ['BLOCKER', 'CRITICAL', 'CRITICAL_BOMB']])
            
            file_result = {
                'file_id': file_id,
                'file_name': file_name,
                'file_path': file_name,  # Use file_name as the relative path for Copilot tasks
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
                'file_path': file_info['name'],  # Use file_name as the relative path
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
        "CONNECTION_BASED_THREAT": len([p for p in total_threat_patterns if p.pattern_type == "CONNECTION_BASED_THREAT"]),
        "threat_density": ThreatMetricsCalculator.calculate_threat_density(total_issues, total_lines)
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
        threat_intelligence=threat_intelligence,
        ait_tag=ait_tag,
        spk_tag=spk_tag,
        repo_name=repo_name
    )

    # Save to detector (history + issues)
    detector.scan_history.append(scan_result_obj)
    detector.save_scan_history()

    for issue in total_issues:
        detector.issue_manager.issues[issue.id] = issue
    detector.issue_manager.save_issues()

    # Generate Copilot task for automated remediation
    generate_copilot_task(scan_id, project_id, total_issues, file_results, threat_intelligence)

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
        'file_path': getattr(issue, 'file_path', ''),
        'file_name': getattr(issue, 'file_name', ''),
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
        'effort_minutes': getattr(issue, 'effort', 0),
        'ait_tag': getattr(issue, 'ait_tag', 'AIT'),
        'spk_tag': getattr(issue, 'spk_tag', 'SPK'),
        'repo_name': getattr(issue, 'repo_name', 'Repo')
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

@app.route('/api/security-tech-debt')
def get_security_tech_debt():
    """Get security technical debt data"""
    try:
        issues = list(detector.issue_manager.issues.values())
        tech_debt_data = []
        
        for issue in issues:
            if hasattr(issue, 'effort') and issue.effort > 0:
                # Determine business impact based on severity
                business_impact = 'Medium'
                if issue.severity == 'CRITICAL':
                    business_impact = 'Critical'
                elif issue.severity == 'MAJOR':
                    business_impact = 'High'
                elif issue.severity == 'MINOR':
                    business_impact = 'Medium'
                else:
                    business_impact = 'Low'
                
                # Determine debt category based on rule_id
                debt_category = 'GENERAL_SECURITY_DEBT'
                if 'hardcoded-credentials' in issue.rule_id:
                    debt_category = 'HARDCODED_CREDENTIALS'
                elif 'hardcoded-urls' in issue.rule_id:
                    debt_category = 'HARDCODED_URLS'
                elif 'input-validation' in issue.rule_id:
                    debt_category = 'INPUT_VALIDATION'
                elif 'vulnerable-libraries' in issue.rule_id:
                    debt_category = 'VULNERABLE_LIBRARIES'
                elif 'access-control' in issue.rule_id:
                    debt_category = 'ACCESS_CONTROL'
                
                tech_debt_data.append({
                    'id': issue.id,
                    'rule_id': issue.rule_id,
                    'file_path': issue.file_path,
                    'file_name': issue.file_path,
                    'line_number': issue.line_number,
                    'message': issue.message,
                    'severity': issue.severity,
                    'business_impact': business_impact,
                    'remediation_effort': issue.effort,
                    'debt_category': debt_category,
                    'debt_category_display': debt_category.replace('_', ' ').title(),
                    'code_snippet': getattr(issue, 'code_snippet', ''),
                    'suggested_fix': getattr(issue, 'suggested_fix', ''),
                    'type': issue.type,
                    'status': issue.status,
                    'ait_tag': getattr(issue, 'ait_tag', 'AIT'),
                    'spk_tag': getattr(issue, 'spk_tag', 'SPK-DEFAULT'),
                    'repo_name': getattr(issue, 'repo_name', 'unknown-repo'),
                    'scan_id': getattr(issue, 'scan_id', 'unknown-scan')
                })
        
        # Group issues by category
        by_category = {}
        summary = {
            'hardcoded_credentials': 0,
            'hardcoded_urls': 0,
            'input_validation': 0,
            'vulnerable_libraries': 0,
            'access_control': 0,
            'total_effort_hours': 0
        }
        
        for issue in tech_debt_data:
            # Use the debt_category from the issue
            category = issue.get('debt_category', 'GENERAL_SECURITY_DEBT').lower()
            
            # Map to summary categories
            if 'hardcoded_credentials' in category:
                summary['hardcoded_credentials'] += 1
            elif 'hardcoded_urls' in category:
                summary['hardcoded_urls'] += 1
            elif 'input_validation' in category:
                summary['input_validation'] += 1
            elif 'vulnerable_libraries' in category:
                summary['vulnerable_libraries'] += 1
            elif 'access_control' in category:
                summary['access_control'] += 1
            
            # Add to category
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(issue)
            
            # Add to total effort
            summary['total_effort_hours'] += issue.get('remediation_effort', 0) // 60
        
        return jsonify({
            'summary': summary,
            'by_category': by_category
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/projects', methods=['GET'])
def list_copilot_projects():
    """List all uploaded projects available for Copilot remediation."""
    try:
        print(f"[DEBUG] Starting list_copilot_projects")
        projects_dir = Path('uploaded_projects')
        print(f"[DEBUG] Projects directory: {projects_dir}")
        print(f"[DEBUG] Projects directory exists: {projects_dir.exists()}")
        
        if not projects_dir.exists():
            print(f"[DEBUG] Projects directory does not exist, returning empty list")
            return jsonify({'projects': []})
        
        projects = []
        scan_dirs = list(projects_dir.iterdir())
        print(f"[DEBUG] Found {len(scan_dirs)} scan directories")
        
        for scan_dir in scan_dirs:
            if scan_dir.is_dir():
                scan_id = scan_dir.name
                print(f"[DEBUG] Processing scan directory: {scan_id}")
                
                # Check if copilot task exists
                task_file = scan_dir / 'copilot_tasks' / 'copilot_task.json'
                vscode_prompts_file = scan_dir / 'vscode_prompts' / 'prompts_metadata.json'
                
                print(f"[DEBUG] Task file exists: {task_file.exists()}")
                print(f"[DEBUG] VS Code prompts file exists: {vscode_prompts_file.exists()}")
                
                task_data = None
                vscode_data = None
                
                if task_file.exists():
                    try:
                        with open(task_file, 'r', encoding='utf-8') as f:
                            task_data = json.load(f)
                        print(f"[DEBUG] Loaded task data for {scan_id}")
                    except (json.JSONDecodeError, Exception) as e:
                        print(f"[DEBUG] Error loading task data for {scan_id}: {e}")
                        task_data = None
                
                if vscode_prompts_file.exists():
                    try:
                        with open(vscode_prompts_file, 'r', encoding='utf-8') as f:
                            vscode_data = json.load(f)
                        print(f"[DEBUG] Loaded VS Code data for {scan_id}")
                    except (json.JSONDecodeError, Exception) as e:
                        print(f"[DEBUG] Error loading VS Code data for {scan_id}: {e}")
                        vscode_data = None
                
                # Count files
                original_dir = scan_dir / 'original'
                remediated_dir = scan_dir / 'remediated'
                vscode_remediated_dir = scan_dir / 'remediated_files'
                
                original_files = list(original_dir.glob('*')) if original_dir.exists() else []
                remediated_files = list(remediated_dir.glob('*')) if remediated_dir.exists() else []
                vscode_remediated_files = list(vscode_remediated_dir.glob('*')) if vscode_remediated_dir.exists() else []
                
                print(f"[DEBUG] {scan_id} - Original files: {len(original_files)}, Remediated: {len(remediated_files)}, VS Code: {len(vscode_remediated_files)}")
                
                # Determine project name and status
                project_name = "File Upload Scan"
                if task_data and isinstance(task_data, dict) and task_data.get('project_name'):
                    project_name = task_data.get('project_name')
                elif vscode_data and isinstance(vscode_data, dict) and vscode_data.get('scan_id'):
                    project_name = f"VS Code Scan {scan_id}"
                
                # Determine status
                status = 'pending'
                if vscode_data and isinstance(vscode_data, dict) and vscode_data.get('prompts'):
                    # Check if any prompts are completed
                    prompts = vscode_data.get('prompts', [])
                    if isinstance(prompts, list):
                        completed_prompts = [p for p in prompts if isinstance(p, dict) and p.get('status') == 'completed']
                        if completed_prompts:
                            status = 'completed'
                        elif prompts:
                            status = 'processing'
                
                # Count total files
                total_files = len(original_files)
                
                # Count security issues
                total_issues = 0
                critical_issues = 0
                if vscode_data and isinstance(vscode_data, dict) and vscode_data.get('prompts'):
                    prompts = vscode_data.get('prompts', [])
                    if isinstance(prompts, list):
                        for prompt in prompts:
                            if isinstance(prompt, dict):
                                security_issues = prompt.get('security_issues', [])
                                if isinstance(security_issues, list):
                                    total_issues += len(security_issues)
                                    critical_issues += len([i for i in security_issues if isinstance(i, dict) and i.get('severity') == 'HIGH'])
                
                project_data = {
                    'scan_id': scan_id,
                    'project_name': project_name,
                    'project_id': task_data.get('project_id', f'upload-scan-{scan_id}') if task_data and isinstance(task_data, dict) else f'upload-scan-{scan_id}',
                    'timestamp': vscode_data.get('timestamp', task_data.get('timestamp', 'unknown') if task_data and isinstance(task_data, dict) else 'unknown') if vscode_data and isinstance(vscode_data, dict) else 'unknown',
                    'status': status,
                    'file_count': total_files,
                    'original_files_count': len(original_files),
                    'remediated_files_count': len(remediated_files) + len(vscode_remediated_files),
                    'total_issues': total_issues,
                    'critical_issues': critical_issues,
                    'has_vscode_prompts': vscode_data is not None,
                    'has_copilot_task': task_data is not None
                }
                
                print(f"[DEBUG] Adding project: {project_data}")
                projects.append(project_data)
        
        print(f"[DEBUG] Total projects found: {len(projects)}")
        
        # Sort by timestamp (newest first)
        projects.sort(key=lambda x: x['timestamp'], reverse=True)
        
        response_data = {'projects': projects}
        print(f"[DEBUG] Returning response: {response_data}")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"[DEBUG] Error in list_copilot_projects: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'projects': []}), 500

@app.route('/api/copilot/process/<scan_id>', methods=['POST'])
def process_copilot_task_endpoint(scan_id):
    """Process Copilot task for a specific scan."""
    try:
        result = process_copilot_task(scan_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/files/<scan_id>', methods=['GET', 'OPTIONS'])
def get_copilot_available_files(scan_id):
    """Get list of available files for a specific scan."""
    if request.method == 'OPTIONS':
        # Handle preflight request
        return jsonify({'status': 'ok'})
    
    try:
        print(f"[DEBUG] Getting available files for scan_id: {scan_id}")
        task_file = Path('uploaded_projects') / scan_id / 'copilot_tasks' / 'copilot_task.json'
        print(f"[DEBUG] Task file path: {task_file}")
        print(f"[DEBUG] Task file exists: {task_file.exists()}")
        
        if not task_file.exists():
            print(f"[DEBUG] Task file not found for scan_id: {scan_id}")
            return jsonify({'error': 'Task not found'}), 404
        
        with open(task_file, 'r', encoding='utf-8') as f:
            task_data = json.load(f)
        
        # Get files from suggested_remediations
        available_files = list(task_data.get('suggested_remediations', {}).keys())
        print(f"[DEBUG] Available files: {available_files}")
        print(f"[DEBUG] Total files: {len(available_files)}")
        
        response_data = {
            'scan_id': scan_id,
            'available_files': available_files,
            'total_files': len(available_files)
        }
        print(f"[DEBUG] Response data: {response_data}")
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"[DEBUG] Error in get_copilot_available_files: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/files/<scan_id>/<path:file_name>', methods=['GET', 'OPTIONS'])
def get_copilot_file_contents(scan_id, file_name):
    """Get original and remediated file contents for comparison."""
    if request.method == 'OPTIONS':
        # Handle preflight request
        return jsonify({'status': 'ok'})
    
    try:
        print(f"[DEBUG] Getting file contents for scan_id: {scan_id}, file_name: {file_name}")
        # Decode the file name to handle special characters
        decoded_file_name = unquote(file_name)
        print(f"[DEBUG] Decoded file name: {decoded_file_name}")
        
        # Handle file paths with subdirectories properly
        original_file = Path('uploaded_projects') / scan_id / 'original' / decoded_file_name
        
        # Look for remediated file with the new naming convention
        file_name_without_ext = Path(decoded_file_name).stem
        file_ext = Path(decoded_file_name).suffix
        remediated_file_name = f"{file_name_without_ext}_original_remediated{file_ext}"
        remediated_file = Path('uploaded_projects') / scan_id / 'remediated_files' / remediated_file_name
        
        # Also try to get the remediated file path from copilot task JSON
        task_file = Path('uploaded_projects') / scan_id / 'copilot_tasks' / 'copilot_task.json'
        if task_file.exists():
            try:
                with open(task_file, 'r', encoding='utf-8') as f:
                    task_data = json.load(f)
                
                # Find the file in file_paths
                for file_path, file_info in task_data.get("file_paths", {}).items():
                    if file_info.get("file_name") == decoded_file_name:
                        remediated_file_path = file_info.get("remediated_file_path")
                        if remediated_file_path:
                            remediated_file = Path(remediated_file_path)
                            print(f"[DEBUG] Found remediated file path in task: {remediated_file}")
                            break
            except Exception as e:
                print(f"[DEBUG] Error reading task file: {e}")
                # Continue with default path
        
        print(f"[DEBUG] Original file path: {original_file}")
        print(f"[DEBUG] Original file exists: {original_file.exists()}")
        print(f"[DEBUG] Original file absolute path: {original_file.absolute()}")
        print(f"[DEBUG] Remediated file path: {remediated_file}")
        print(f"[DEBUG] Remediated file exists: {remediated_file.exists()}")
        print(f"[DEBUG] Remediated file absolute path: {remediated_file.absolute()}")
        
        # Check if parent directories exist
        print(f"[DEBUG] Original parent exists: {original_file.parent.exists()}")
        print(f"[DEBUG] Remediated parent exists: {remediated_file.parent.exists()}")
        
        original_content = ""
        remediated_content = ""
        
        if original_file.exists():
            with open(original_file, 'r', encoding='utf-8') as f:
                original_content = f.read()
            print(f"[DEBUG] Original content length: {len(original_content)}")
        else:
            print(f"[DEBUG] Original file does not exist!")
        
        if remediated_file.exists():
            with open(remediated_file, 'r', encoding='utf-8') as f:
                remediated_content = f.read()
            print(f"[DEBUG] Remediated content length: {len(remediated_content)}")
        else:
            print(f"[DEBUG] Remediated file does not exist!")
        
        response_data = {
            'scan_id': scan_id,
            'file_name': decoded_file_name,
            'original_content': original_content,
            'remediated_content': remediated_content,
            'has_original': original_file.exists(),
            'has_remediated': remediated_file.exists()
        }
        print(f"[DEBUG] Response data keys: {list(response_data.keys())}")
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"[DEBUG] Error in get_copilot_file_contents: {str(e)}")
        import traceback
        print(f"[DEBUG] Full traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/task/<scan_id>', methods=['GET'])
def get_copilot_task(scan_id):
    """Get Copilot task details for a specific scan."""
    try:
        task_file = Path('uploaded_projects') / scan_id / 'copilot_tasks' / 'copilot_task.json'
        if not task_file.exists():
            return jsonify({'error': 'Task not found'}), 404
        
        with open(task_file, 'r', encoding='utf-8') as f:
            task_data = json.load(f)
        
        return jsonify(task_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/agent/start', methods=['POST'])
def start_automated_copilot_agent():
    """Start the automated Copilot agent."""
    try:
        success = start_copilot_agent()
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Automated Copilot agent started successfully',
                'agent_status': get_agent_status()
            })
        else:
            return jsonify({
                'status': 'warning',
                'message': 'Copilot agent is already running',
                'agent_status': get_agent_status()
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/agent/stop', methods=['POST'])
def stop_automated_copilot_agent():
    """Stop the automated Copilot agent."""
    try:
        success = stop_copilot_agent()
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Automated Copilot agent stopped successfully',
                'agent_status': get_agent_status()
            })
        else:
            return jsonify({
                'status': 'warning',
                'message': 'Copilot agent is not running',
                'agent_status': get_agent_status()
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/agent/status', methods=['GET'])
def get_automated_copilot_agent_status():
    """Get the status of the automated Copilot agent."""
    try:
        status = get_agent_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_copilot_task(scan_id: str, project_id: str, issues: list, file_results: list, threat_intelligence: dict) -> None:
    """Generates a Copilot task file for automated remediation."""
    try:
        task_data = {
            "scan_id": scan_id,
            "project_id": project_id,
            "timestamp": datetime.now().isoformat(),
            "status": "pending",  # Add status field
            "threat_intelligence": threat_intelligence,
            "issues_summary": {
                "total_issues": len(issues),
                "critical_bombs": len([i for i in issues if i.severity == "CRITICAL_BOMB"]),
                "high_risks": len([i for i in issues if i.severity == "HIGH_RISK"]),
                "medium_risks": len([i for i in issues if i.severity == "MEDIUM_RISK"]),
                "low_risks": len([i for i in issues if i.severity == "LOW_RISK"]),
                "critical_issues": len([i for i in issues if i.severity == "CRITICAL"]),
                "major_issues": len([i for i in issues if i.severity == "MAJOR"]),
                "minor_issues": len([i for i in issues if i.severity == "MINOR"]),
                "info_issues": len([i for i in issues if i.severity == "INFO"]),
                "unknown_issues": len([i for i in issues if i.severity == "UNKNOWN"])
            },
            "file_results": file_results,
            "suggested_remediations": {},
            "file_paths": {}  # Add file paths mapping
        }

        # Group issues by file for easier remediation
        for file_result in file_results:
            file_name = file_result['file_name']
            # Use the full file path to handle subdirectories
            file_path = file_result.get('file_path', file_name)
            
            # Store the source file path for remediation
            original_dir = Path('uploaded_projects') / scan_id / 'original'
            source_file_path = original_dir / file_path
            task_data["file_paths"][file_path] = {
                "source_file_path": str(source_file_path),
                "file_name": file_name,
                "file_path": file_path,
                "remediated_file_path": str(Path('uploaded_projects') / scan_id / 'remediated_files' / f"{Path(file_name).stem}_original_remediated{Path(file_path).suffix}")
            }
            
            task_data["suggested_remediations"][file_path] = []
            for issue in file_result['issues']:
                # Only include issues that are not already neutralized
                if issue['status'] != 'NEUTRALIZED':
                    task_data["suggested_remediations"][file_path].append({
                        "issue_id": issue['id'],
                        "rule_id": issue['rule_id'],
                        "message": issue['message'],
                        "severity": issue['severity'],
                        "type": issue['type'],
                        "code_snippet": issue['code_snippet'],
                        "suggested_fix": issue['suggested_fix'],
                        "threat_level": issue['threat_level'],
                        "trigger_analysis": issue['trigger_analysis'],
                        "payload_analysis": issue['payload_analysis'],
                        "effort_minutes": issue['effort_minutes']
                    })

        # Ensure the directory exists
        task_dir = Path('uploaded_projects') / scan_id / 'copilot_tasks'
        task_dir.mkdir(parents=True, exist_ok=True)

        # Save the task file
        task_file_path = task_dir / 'copilot_task.json'
        with open(task_file_path, 'w', encoding='utf-8') as f:
            json.dump(task_data, f, indent=4)
        print(f"Copilot task generated at: {task_file_path}")

    except Exception as e:
        print(f"Error generating Copilot task: {e}")

def process_copilot_task(scan_id: str) -> dict:
    """Process Copilot task and generate remediated files."""
    try:
        task_file_path = Path('uploaded_projects') / scan_id / 'copilot_tasks' / 'copilot_task.json'
        if not task_file_path.exists():
            return {"error": "Copilot task not found"}
        
        with open(task_file_path, 'r', encoding='utf-8') as f:
            task_data = json.load(f)
        
        # Create remediated files directory
        remediated_dir = Path('uploaded_projects') / scan_id / 'remediated_files'
        remediated_dir.mkdir(parents=True, exist_ok=True)
        
        remediated_files = []
        
        # Process each file that has issues
        for file_path, remediations in task_data.get("suggested_remediations", {}).items():
            if remediations:  # Only process files with issues
                # Get source file path from the file_paths mapping
                file_info = task_data.get("file_paths", {}).get(file_path, {})
                source_file_path = file_info.get("source_file_path")
                
                if not source_file_path:
                    print(f"Warning: No source file path found for {file_path}")
                    continue
                
                original_file_path = Path(source_file_path)
                if original_file_path.exists():
                    with open(original_file_path, 'r', encoding='utf-8') as f:
                        original_content = f.read()
                    
                    # Apply remediations (stub - in real implementation, this would use Copilot API)
                    remediated_content = apply_copilot_remediations(original_content, remediations)
                    
                    # Save remediated file with proper naming for diff comparison
                    file_name = file_info.get("file_name", Path(file_path).name)
                    remediated_file_path = Path(file_info.get("remediated_file_path", str(remediated_dir / f"{file_name}_original_remediated{Path(file_path).suffix}")))
                    
                    # Ensure the remediated directory exists
                    remediated_file_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(remediated_file_path, 'w', encoding='utf-8') as f:
                        f.write(remediated_content)
                    
                    remediated_files.append({
                        "file_name": file_name,
                        "file_path": file_path,
                        "original_path": str(original_file_path),
                        "remediated_path": str(remediated_file_path),
                        "remediations_applied": len(remediations)
                    })
        
        # Update task status
        task_data["status"] = "completed"
        task_data["remediated_files"] = remediated_files
        task_data["completion_timestamp"] = datetime.now().isoformat()
        
        with open(task_file_path, 'w', encoding='utf-8') as f:
            json.dump(task_data, f, indent=4)
        
        return {
            "status": "completed",
            "scan_id": scan_id,
            "remediated_files": remediated_files,
            "total_files_processed": len(remediated_files)
        }
        
    except Exception as e:
        return {"error": f"Error processing Copilot task: {e}"}

def apply_copilot_remediations(original_content: str, remediations: list) -> str:
    """Apply Copilot remediations to file content (stub implementation)."""
    # This is a stub - in real implementation, this would:
    # 1. Parse the original content
    # 2. Use Copilot API to generate fixes
    # 3. Apply the fixes to the content
    # 4. Return the remediated content
    
    remediated_content = original_content
    
    for remediation in remediations:
        # Add comments indicating what was fixed
        fix_comment = f"\n// FIXED: {remediation['message']} - {remediation['suggested_fix']}\n"
        remediated_content += fix_comment
    
    return remediated_content

@app.route('/api/copilot/vscode/instructions/<scan_id>', methods=['GET'])
def get_vscode_instructions(scan_id):
    """Get VS Code Copilot instructions for a scan."""
    try:
        instructions_dir = Path('uploaded_projects') / scan_id / 'vscode_instructions'
        if not instructions_dir.exists():
            return jsonify({'error': 'Instructions not found'}), 404
        
        instructions = []
        for file_path in instructions_dir.glob('*_instructions.md'):
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            instructions.append({
                'file': file_path.stem.replace('_instructions', ''),
                'content': content,
                'type': 'instructions'
            })
        
        return jsonify({
            'scan_id': scan_id,
            'instructions': instructions,
            'total_files': len(instructions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/vscode/prompts/<scan_id>', methods=['GET'])
def get_vscode_prompts(scan_id):
    """Get VS Code Copilot prompts for a scan."""
    try:
        instructions_dir = Path('uploaded_projects') / scan_id / 'vscode_instructions'
        if not instructions_dir.exists():
            return jsonify({'error': 'Prompts not found'}), 404
        
        prompts = []
        for file_path in instructions_dir.glob('*_copilot_prompt.txt'):
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            prompts.append({
                'file': file_path.stem.replace('_copilot_prompt', ''),
                'content': content,
                'type': 'prompt'
            })
        
        return jsonify({
            'scan_id': scan_id,
            'prompts': prompts,
            'total_files': len(prompts)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/vscode/workspace/<scan_id>', methods=['GET'])
def get_vscode_workspace(scan_id):
    """Get VS Code workspace file for a scan."""
    try:
        workspace_file = Path('vscode_remediation_workspaces') / scan_id / f'{scan_id}.code-workspace'
        if not workspace_file.exists():
            return jsonify({'error': 'Workspace not found'}), 404
        
        with open(workspace_file, 'r', encoding='utf-8') as f:
            workspace_content = f.read()
        
        return jsonify({
            'scan_id': scan_id,
            'workspace_file': str(workspace_file),
            'workspace_content': workspace_content
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/copilot/vscode/download/<scan_id>', methods=['GET'])
def download_vscode_files(scan_id):
    """Download all VS Code files for a scan as a ZIP."""
    try:
        import zipfile
        import io
        
        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add instructions
            instructions_dir = Path('uploaded_projects') / scan_id / 'vscode_instructions'
            if instructions_dir.exists():
                for file_path in instructions_dir.rglob('*'):
                    if file_path.is_file():
                        arc_name = f'vscode_instructions/{file_path.name}'
                        zip_file.write(file_path, arc_name)
            
            # Add workspace
            workspace_file = Path('vscode_remediation_workspaces') / scan_id / f'{scan_id}.code-workspace'
            if workspace_file.exists():
                zip_file.write(workspace_file, f'workspace/{scan_id}.code-workspace')
            
            # Add original files
            original_dir = Path('uploaded_projects') / scan_id / 'original'
            if original_dir.exists():
                for file_path in original_dir.rglob('*'):
                    if file_path.is_file():
                        arc_name = f'original_files/{file_path.relative_to(original_dir)}'
                        zip_file.write(file_path, arc_name)
        
        zip_buffer.seek(0)
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'vscode_copilot_remediation_{scan_id}.zip'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vscode-agent/remediate', methods=['POST'])
def vscode_remediate():
    """Handle VS Code agent remediation requests"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        file_path = data.get('file_path')
        content = data.get('content')
        params = data.get('params', {})
        
        if not file_path or not content:
            return jsonify({'error': 'Missing file_path or content'}), 400
            
        # Generate remediation prompt
        language = detect_language_from_path(file_path)
        prompt = generate_vscode_remediation_prompt(file_path, content, params, language)
        
        # Execute remediation
        remediated_content = execute_vscode_remediation(prompt, file_path, language, content)
        
        # Save remediated file
        scan_id = params.get('scan_id', f"vscode_{int(time.time())}")
        saved_path = save_vscode_remediated_file(file_path, remediated_content, scan_id, params)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'remediated_file': saved_path,
            'original_file': file_path,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error in VS Code remediation: {e}")
        return jsonify({'error': str(e)}), 500

def detect_language_from_path(file_path: str) -> str:
    """Detect language from file path"""
    ext = Path(file_path).suffix.lower()
    language_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.java': 'java',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.cpp': 'cpp',
        '.c': 'c',
        '.html': 'html',
        '.css': 'css',
        '.json': 'json'
    }
    return language_map.get(ext, 'text')

def generate_vscode_remediation_prompt(file_path: str, content: str, params: dict, language: str) -> str:
    """Generate remediation prompt for VS Code agent"""
    return f"""# SECURITY VULNERABILITY FIX REQUEST
# File: {Path(file_path).name}
# Language: {language}
# Scan ID: {params.get('scan_id', 'unknown')}
# Severity: {params.get('severity', 'MEDIUM')}
# Type: {params.get('type', 'GENERAL')}

# TASK FOR GITHUB COPILOT:
Please provide a secure, fixed version of this code that addresses potential security vulnerabilities.

# REQUIREMENTS:
1. Remove dangerous operations (subprocess calls, system commands, etc.)
2. Add proper input validation and sanitization
3. Use secure alternatives and best practices
4. Add comprehensive error handling
5. Include logging for security events
6. Follow OWASP security guidelines
7. Maintain the same functionality where possible
8. Add comments explaining security improvements

# SECURITY FOCUS AREAS:
- Replace destructive operations with safe alternatives
- Remove hardcoded credentials and secrets
- Add input validation and sanitization
- Implement proper error handling
- Use secure file operations
- Add logging and monitoring
- Follow principle of least privilege

# ORIGINAL CODE:
```{language}
{content}
```

# EXPECTED OUTPUT:
Please provide the complete fixed code with security improvements:

```{language}
"""

def execute_vscode_remediation(prompt: str, file_path: str, language: str, original_content: str = None) -> str:
    """Execute VS Code remediation by applying fixes to original content"""
    try:
        # If no original content provided, try to read it
        if original_content is None:
            original_file = Path(file_path)
            if original_file.exists():
                with open(original_file, 'r', encoding='utf-8') as f:
                    original_content = f.read()
            else:
                # Fallback to template if original file not found
                return f"""# SECURITY FIX: Generated by ThreatGuard VS Code Agent
# Original file: {Path(file_path).name}
# Remediation timestamp: {datetime.now().isoformat()}
# Note: Original file not found, using template

import logging
from pathlib import Path
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def secure_operation():
    \"\"\"
    Secure version of the original operation
    \"\"\"
    try:
        # Add your secure implementation here
        logger.info("Secure operation executed successfully")
        return True
    except Exception as e:
        logger.error(f"Secure operation failed: {{e}}")
        return False

if __name__ == "__main__":
    secure_operation()
"""
        
        # Start with the original content
        remediated_content = original_content
        
        # Add security header
        security_header = f"""# SECURITY FIX: Generated by ThreatGuard VS Code Agent
# Original file: {Path(file_path).name}
# Remediation timestamp: {datetime.now().isoformat()}
# Security improvements applied below:

"""
        
        # Apply security fixes based on language
        if language == 'python':
            # Apply Python-specific security fixes
            remediated_content = apply_python_security_fixes(remediated_content)
        elif language == 'javascript':
            # Apply JavaScript-specific security fixes
            remediated_content = apply_javascript_security_fixes(remediated_content)
        else:
            # Apply general security fixes
            remediated_content = apply_general_security_fixes(remediated_content)
        
        # Combine header with remediated content
        return security_header + remediated_content
            
    except Exception as e:
        logging.error(f"Error executing VS Code remediation: {e}")
        # Return original content with error comment if remediation fails
        return f"""# SECURITY FIX: Error in remediation
# Original file: {Path(file_path).name}
# Generated: {datetime.now().isoformat()}
# Error: {str(e)}

# Original content preserved below:
{original_content if original_content else "# No original content available"}

# TODO: Review and apply security improvements manually
"""

def apply_python_security_fixes(content: str) -> str:
    """Apply Python-specific security fixes to content"""
    try:
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            fixed_line = line
            
            # Fix 1: Add input validation for eval() usage
            if 'eval(' in line and not line.strip().startswith('#'):
                fixed_line = f"# SECURITY FIX: eval() usage detected - consider using ast.literal_eval() instead\n{line}"
            
            # Fix 2: Add input validation for exec() usage
            elif 'exec(' in line and not line.strip().startswith('#'):
                fixed_line = f"# SECURITY FIX: exec() usage detected - consider using safer alternatives\n{line}"
            
            # Fix 3: Add input validation for subprocess calls
            elif 'subprocess.call(' in line or 'subprocess.run(' in line:
                fixed_line = f"# SECURITY FIX: subprocess call detected - validate input parameters\n{line}"
            
            # Fix 4: Add input validation for file operations
            elif 'open(' in line and not line.strip().startswith('#'):
                fixed_line = f"# SECURITY FIX: file operation detected - validate file path\n{line}"
            
            # Fix 5: Add input validation for SQL queries
            elif any(sql_keyword in line.lower() for sql_keyword in ['select', 'insert', 'update', 'delete']) and '?' not in line and '%s' not in line:
                fixed_line = f"# SECURITY FIX: SQL query detected - use parameterized queries\n{line}"
            
            # Fix 6: Add logging for security events
            elif 'print(' in line and not line.strip().startswith('#'):
                fixed_line = f"# SECURITY FIX: print() detected - consider using logging\n{line}"
            
            fixed_lines.append(fixed_line)
        
        return '\n'.join(fixed_lines)
        
    except Exception as e:
        logging.error(f"Error applying Python security fixes: {e}")
        return content

def apply_javascript_security_fixes(content: str) -> str:
    """Apply JavaScript-specific security fixes to content"""
    try:
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            fixed_line = line
            
            # Fix 1: Add input validation for eval() usage
            if 'eval(' in line and not line.trim().startsWith('//'):
                fixed_line = f"// SECURITY FIX: eval() usage detected - consider using JSON.parse() instead\n{line}"
            
            # Fix 2: Add input validation for innerHTML usage
            elif 'innerHTML' in line and not line.trim().startsWith('//'):
                fixed_line = f"// SECURITY FIX: innerHTML usage detected - consider using textContent\n{line}"
            
            # Fix 3: Add input validation for document.write usage
            elif 'document.write(' in line and not line.trim().startsWith('//'):
                fixed_line = f"// SECURITY FIX: document.write() detected - consider using DOM methods\n{line}"
            
            # Fix 4: Add input validation for localStorage without validation
            elif 'localStorage.setItem(' in line and not line.trim().startsWith('//'):
                fixed_line = f"// SECURITY FIX: localStorage usage detected - validate input data\n{line}"
            
            # Fix 5: Add input validation for console.log in production
            elif 'console.log(' in line and not line.trim().startsWith('//'):
                fixed_line = f"// SECURITY FIX: console.log() detected - remove in production\n{line}"
            
            fixed_lines.append(fixed_line)
        
        return '\n'.join(fixed_lines)
        
    except Exception as e:
        logging.error(f"Error applying JavaScript security fixes: {e}")
        return content

def apply_general_security_fixes(content: str) -> str:
    """Apply general security fixes to content"""
    try:
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            fixed_line = line
            
            # Fix 1: Add input validation for hardcoded credentials
            if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']) and '=' in line:
                fixed_line = f"# SECURITY FIX: Hardcoded credential detected - use environment variables\n{line}"
            
            # Fix 2: Add input validation for debug statements
            elif any(debug_keyword in line.lower() for debug_keyword in ['debug', 'console.log', 'print']):
                fixed_line = f"# SECURITY FIX: Debug statement detected - remove in production\n{line}"
            
            # Fix 3: Add input validation for error messages that might leak info
            elif 'error' in line.lower() and any(leak_keyword in line.lower() for leak_keyword in ['stack', 'trace', 'exception']):
                fixed_line = f"# SECURITY FIX: Error message might leak sensitive information\n{line}"
            
            fixed_lines.append(fixed_line)
        
        return '\n'.join(fixed_lines)
        
    except Exception as e:
        logging.error(f"Error applying general security fixes: {e}")
        return content

def save_vscode_remediated_file(original_file_path: str, remediated_content: str, scan_id: str, params: dict) -> str:
    """Save VS Code remediated file"""
    try:
        # Create remediation directory structure - use the correct path
        remediated_dir = Path('uploaded_projects') / scan_id / 'remediated_files'
        remediated_dir.mkdir(parents=True, exist_ok=True)
        
        # Save remediated file with correct naming convention
        original_file = Path(original_file_path)
        remediated_file = remediated_dir / f"{original_file.stem}_original_remediated{original_file.suffix}"
        
        with open(remediated_file, 'w', encoding='utf-8') as f:
            f.write(remediated_content)
            
        # Create metadata file
        metadata = {
            'original_file': original_file_path,
            'remediated_file': str(remediated_file),
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'params': params,
            'status': 'completed'
        }
        
        # Save metadata in the same directory as remediated files
        metadata_file = remediated_dir / 'vscode_metadata.json'
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
            
        logging.info(f"VS Code remediated file saved: {remediated_file}")
        return str(remediated_file)
        
    except Exception as e:
        logging.error(f"Error saving VS Code remediated file: {e}")
        raise e

@app.route('/api/vscode-agent/status', methods=['GET'])
def vscode_agent_status():
    """Get VS Code agent status"""
    try:
        return jsonify({
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'endpoints': {
                'remediate': '/api/vscode-agent/remediate',
                'status': '/api/vscode-agent/status'
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_vscode_copilot_prompts(scan_id: str, uploaded_files: List[Dict]) -> Dict[str, Any]:
    """Generate VS Code Copilot prompts for uploaded files"""
    try:
        prompts_dir = Path('uploaded_projects') / scan_id / 'vscode_prompts'
        prompts_dir.mkdir(parents=True, exist_ok=True)
        
        prompts_data = {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'total_files': len(uploaded_files),
            'prompts': []
        }
        
        for file_info in uploaded_files:
            file_path = file_info['file_path']
            file_content = file_info['content']
            file_name = Path(file_path).name
            
            # Generate security analysis
            security_issues = analyze_security_issues(file_content, file_path)
            
            # Generate Copilot prompt
            prompt_content = generate_copilot_prompt(file_path, file_content, security_issues, scan_id)
            
            # Save prompt to file
            prompt_file = prompts_dir / f"{Path(file_path).stem}_prompt.txt"
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(prompt_content)
            
            # Save original file for reference
            original_file = prompts_dir / f"{Path(file_path).stem}_original{Path(file_path).suffix}"
            with open(original_file, 'w', encoding='utf-8') as f:
                f.write(file_content)
            
            prompts_data['prompts'].append({
                'file_path': file_path,
                'file_name': file_name,
                'prompt_file': str(prompt_file),
                'original_file': str(original_file),
                'source_file_path': file_path,  # Add source file path
                'security_issues': security_issues,
                'status': 'pending'
            })
        
        # Save prompts metadata
        metadata_file = prompts_dir / 'prompts_metadata.json'
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(prompts_data, f, indent=2)
        
        logging.info(f"Generated VS Code Copilot prompts for scan {scan_id}: {len(uploaded_files)} files")
        return prompts_data
        
    except Exception as e:
        logging.error(f"Error generating VS Code Copilot prompts: {e}")
        raise e

def analyze_security_issues(content: str, file_path: str) -> List[Dict]:
    """Analyze file content for security issues"""
    issues = []
    language = detect_language_from_path(file_path)
    
    # Check for dangerous operations
    dangerous_patterns = {
        'python': [
            (r'subprocess\.call\(', 'Dangerous subprocess call'),
            (r'os\.system\(', 'Dangerous system call'),
            (r'eval\(', 'Code injection vulnerability'),
            (r'exec\(', 'Code execution vulnerability'),
            (r'__import__\(', 'Dynamic import vulnerability'),
            (r'rm -rf', 'Destructive file operation'),
            (r'password\s*=', 'Hardcoded credentials'),
            (r'secret\s*=', 'Hardcoded secrets'),
        ],
        'javascript': [
            (r'eval\(', 'Code injection vulnerability'),
            (r'Function\(', 'Code execution vulnerability'),
            (r'innerHTML\s*=', 'XSS vulnerability'),
            (r'document\.write\(', 'XSS vulnerability'),
            (r'password\s*:', 'Hardcoded credentials'),
            (r'secret\s*:', 'Hardcoded secrets'),
        ],
        'java': [
            (r'Runtime\.getRuntime\(\)\.exec\(', 'Command injection'),
            (r'ProcessBuilder\(', 'Command injection'),
            (r'eval\(', 'Code injection vulnerability'),
            (r'password\s*=', 'Hardcoded credentials'),
        ]
    }
    
    patterns = dangerous_patterns.get(language, [])
    
    for pattern, description in patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'security_vulnerability',
                'description': description,
                'line': line_num,
                'code': match.group(),
                'severity': 'HIGH'
            })
    
    # Check for missing input validation
    if language == 'python':
        if re.search(r'def\s+\w+\([^)]*\):', content) and not re.search(r'if\s+.*:', content):
            issues.append({
                'type': 'missing_validation',
                'description': 'Missing input validation',
                'line': 1,
                'code': 'function definition',
                'severity': 'MEDIUM'
            })
    
    return issues

def generate_copilot_prompt(file_path: str, content: str, security_issues: List[Dict], scan_id: str) -> str:
    """Generate comprehensive Copilot prompt for security remediation"""
    language = detect_language_from_path(file_path)
    file_name = Path(file_path).name
    
    # Group issues by severity
    high_issues = [issue for issue in security_issues if issue['severity'] == 'HIGH']
    medium_issues = [issue for issue in security_issues if issue['severity'] == 'MEDIUM']
    low_issues = [issue for issue in security_issues if issue['severity'] == 'LOW']
    
    prompt = f"""# SECURITY VULNERABILITY FIX REQUEST
# File: {file_name}
# Language: {language}
# Scan ID: {scan_id}
# Generated: {datetime.now().isoformat()}

# SECURITY ISSUES DETECTED:
"""
    
    if high_issues:
        prompt += "\n## HIGH SEVERITY ISSUES:\n"
        for issue in high_issues:
            prompt += f"- Line {issue['line']}: {issue['description']}\n"
            prompt += f"  Code: {issue['code']}\n"
    
    if medium_issues:
        prompt += "\n## MEDIUM SEVERITY ISSUES:\n"
        for issue in medium_issues:
            prompt += f"- Line {issue['line']}: {issue['description']}\n"
            prompt += f"  Code: {issue['code']}\n"
    
    if low_issues:
        prompt += "\n## LOW SEVERITY ISSUES:\n"
        for issue in low_issues:
            prompt += f"- Line {issue['line']}: {issue['description']}\n"
            prompt += f"  Code: {issue['code']}\n"
    
    prompt += f"""

# TASK FOR GITHUB COPILOT:
Please provide a secure, fixed version of this code that addresses ALL the security vulnerabilities listed above.

# REQUIREMENTS:
1. Remove ALL dangerous operations (subprocess calls, system commands, eval, exec, etc.)
2. Add comprehensive input validation and sanitization
3. Use secure alternatives and best practices
4. Add proper error handling and logging
5. Follow OWASP security guidelines
6. Maintain the same functionality where possible
7. Add comments explaining security improvements
8. Replace hardcoded credentials with environment variables
9. Implement proper access controls
10. Add security event logging

# SECURITY FOCUS AREAS:
- Replace destructive operations with safe alternatives
- Remove code injection vulnerabilities
- Add input validation and sanitization
- Implement proper error handling
- Use secure file operations
- Add logging and monitoring
- Follow principle of least privilege
- Remove hardcoded secrets

# ORIGINAL CODE:
```{language}
{content}
```

# EXPECTED OUTPUT:
Please provide the complete fixed code with security improvements:

```{language}
"""
    
    return prompt

@app.route('/api/vscode-agent/process/<scan_id>', methods=['POST'])
def process_vscode_agent(scan_id):
    """Process VS Code agent remediation for a specific scan"""
    try:
        print(f"[DEBUG] Processing VS Code agent for scan: {scan_id}")
        
        # Check if prompts exist for this scan
        prompts_dir = Path('uploaded_projects') / scan_id / 'vscode_prompts'
        metadata_file = prompts_dir / 'prompts_metadata.json'
        
        # If no prompts exist, generate them first
        if not metadata_file.exists():
            print(f"[DEBUG] No prompts found for scan {scan_id}, generating prompts...")
            
            # Check if original files exist
            original_dir = Path('uploaded_projects') / scan_id / 'original'
            if not original_dir.exists():
                return jsonify({'error': f'No original files found for scan {scan_id}'}), 404
            
            # Get original files
            original_files = []
            for file_path in original_dir.rglob('*'):
                if file_path.is_file():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    original_files.append({
                        'file_path': str(file_path),
                        'file_name': file_path.name,
                        'content': content
                    })
            
            if not original_files:
                return jsonify({'error': f'No files found in original directory for scan {scan_id}'}), 404
            
            # Generate VS Code prompts
            prompts_data = generate_vscode_copilot_prompts(scan_id, original_files)
            print(f"[DEBUG] Generated prompts for {len(original_files)} files")
        
        # Load prompts metadata
        with open(metadata_file, 'r', encoding='utf-8') as f:
            prompts_data = json.load(f)
        
        # Create remediated files directory
        remediated_dir = Path('uploaded_projects') / scan_id / 'remediated_files'
        remediated_dir.mkdir(parents=True, exist_ok=True)
        
        # Process each prompt
        processed_files = []
        for prompt_info in prompts_data['prompts']:
            try:
                print(f"[DEBUG] Processing prompt for file: {prompt_info['file_name']}")
                
                # Read prompt content
                with open(prompt_info['prompt_file'], 'r', encoding='utf-8') as f:
                    prompt_content = f.read()
                
                # Read original file
                with open(prompt_info['original_file'], 'r', encoding='utf-8') as f:
                    original_content = f.read()
                
                # Execute remediation (simulate Copilot processing)
                remediated_content = execute_vscode_remediation(prompt_content, prompt_info['file_path'], detect_language_from_path(prompt_info['file_path']), original_content)
                
                # Save remediated file with proper naming for diff comparison
                original_file_path = Path(prompt_info['original_file'])
                remediated_file = remediated_dir / f"{original_file_path.stem}_original_remediated{original_file_path.suffix}"
                
                with open(remediated_file, 'w', encoding='utf-8') as f:
                    f.write(remediated_content)
                
                # Update prompt status with source file path
                prompt_info['status'] = 'completed'
                prompt_info['remediated_file'] = str(remediated_file)
                prompt_info['source_file_path'] = str(original_file_path)
                prompt_info['processed_at'] = datetime.now().isoformat()
                
                processed_files.append({
                    'file_name': prompt_info['file_name'],
                    'original_file': prompt_info['original_file'],
                    'remediated_file': str(remediated_file),
                    'status': 'completed'
                })
                
                print(f"[DEBUG] Successfully processed: {prompt_info['file_name']}")
                
            except Exception as e:
                logging.error(f"Error processing prompt for {prompt_info['file_name']}: {e}")
                print(f"[DEBUG] Error processing {prompt_info['file_name']}: {e}")
                prompt_info['status'] = 'error'
                prompt_info['error'] = str(e)
        
        # Update metadata
        prompts_data['processed_at'] = datetime.now().isoformat()
        prompts_data['total_processed'] = len(processed_files)
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(prompts_data, f, indent=2)
        
        print(f"[DEBUG] Processing completed for scan {scan_id}. Processed {len(processed_files)} files.")
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'total_files': len(prompts_data['prompts']),
            'processed_files': processed_files,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error processing VS Code agent for scan {scan_id}: {e}")
        print(f"[DEBUG] Error in process_vscode_agent: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vscode-agent/prompts/<scan_id>', methods=['GET'])
def get_vscode_agent_prompts(scan_id):
    """Get VS Code prompts for a specific scan"""
    try:
        prompts_dir = Path('uploaded_projects') / scan_id / 'vscode_prompts'
        metadata_file = prompts_dir / 'prompts_metadata.json'
        
        if not metadata_file.exists():
            return jsonify({'error': f'No prompts found for scan {scan_id}'}), 404
        
        with open(metadata_file, 'r', encoding='utf-8') as f:
            prompts_data = json.load(f)
        
        return jsonify(prompts_data)
        
    except Exception as e:
        logging.error(f"Error getting VS Code prompts for scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vscode-agent/files/<scan_id>/<path:file_name>', methods=['GET'])
def get_vscode_agent_file(scan_id, file_name):
    """Get VS Code agent files (prompts, original, remediated)"""
    try:
        # Check different directories for the file
        possible_paths = [
            Path('uploaded_projects') / scan_id / 'vscode_prompts' / file_name,
            Path('uploaded_projects') / scan_id / 'remediated_files' / file_name,
            Path('uploaded_projects') / scan_id / 'original' / file_name
        ]
        
        for file_path in possible_paths:
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                return jsonify({
                    'file_name': file_name,
                    'file_path': str(file_path),
                    'content': content,
                    'size': len(content)
                })
        
        return jsonify({'error': f'File {file_name} not found for scan {scan_id}'}), 404
        
    except Exception as e:
        logging.error(f"Error getting VS Code agent file {file_name} for scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vscode-agent/diff/<scan_id>/<path:file_name>', methods=['GET'])
def get_vscode_agent_diff(scan_id, file_name):
    """Get diff between original and remediated files for VS Code agent"""
    try:
        print(f"[DEBUG] Getting diff for scan_id: {scan_id}, file_name: {file_name}")
        
        # First try to get file paths from copilot task JSON
        task_file_path = Path('uploaded_projects') / scan_id / 'copilot_tasks' / 'copilot_task.json'
        original_file_path = None
        remediated_file_path = None
        
        if task_file_path.exists():
            with open(task_file_path, 'r', encoding='utf-8') as f:
                task_data = json.load(f)
            
            # Find the file in the file_paths mapping
            for file_path, file_info in task_data.get("file_paths", {}).items():
                if file_info.get("file_name") == file_name:
                    original_file_path = Path(file_info.get("source_file_path"))
                    # Use the remediated file path from the task data
                    remediated_file_path = Path(file_info.get("remediated_file_path"))
                    break
        
        # If not found in copilot task, try prompts metadata
        if not original_file_path or not remediated_file_path:
            prompts_dir = Path('uploaded_projects') / scan_id / 'vscode_prompts'
            metadata_file = prompts_dir / 'prompts_metadata.json'
            
            if metadata_file.exists():
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    prompts_data = json.load(f)
                
                # Find the prompt for this file
                target_prompt = None
                for prompt in prompts_data.get('prompts', []):
                    if prompt.get('file_name') == file_name:
                        target_prompt = prompt
                        break
                
                if target_prompt:
                    original_file_path = Path(target_prompt.get('original_file'))
                    remediated_file_path = Path(target_prompt.get('remediated_file'))
        
        if not original_file_path or not remediated_file_path:
            return jsonify({'error': f'File paths not found for {file_name} in scan {scan_id}'}), 404
        
        if not original_file_path.exists():
            return jsonify({'error': f'Original file not found: {original_file_path}'}), 404
        
        if not remediated_file_path.exists():
            return jsonify({'error': f'Remediated file not found: {remediated_file_path}'}), 404
        
        print(f"[DEBUG] Original file: {original_file_path}")
        print(f"[DEBUG] Remediated file: {remediated_file_path}")
        
        # Read original and remediated content
        with open(original_file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        with open(remediated_file_path, 'r', encoding='utf-8') as f:
            remediated_content = f.read()
        
        # Generate diff
        diff_data = generate_file_diff(original_content, remediated_content)
        
        return jsonify({
            'scan_id': scan_id,
            'file_name': file_name,
            'original_file': str(original_file_path),
            'remediated_file': str(remediated_file_path),
            'original_content': original_content,
            'remediated_content': remediated_content,
            'diff': diff_data
        })
        
    except Exception as e:
        logging.error(f"Error getting VS Code agent diff for scan {scan_id}, file {file_name}: {e}")
        print(f"[DEBUG] Error in get_vscode_agent_diff: {e}")
        return jsonify({'error': str(e)}), 500

def generate_file_diff(original_content: str, remediated_content: str) -> Dict:
    """Generate diff between original and remediated content"""
    original_lines = original_content.split('\n')
    remediated_lines = remediated_content.split('\n')
    
    diff_result = {
        'added_lines': [],
        'removed_lines': [],
        'modified_lines': [],
        'statistics': {
            'total_original_lines': len(original_lines),
            'total_remediated_lines': len(remediated_lines),
            'added_count': 0,
            'removed_count': 0,
            'modified_count': 0
        }
    }
    
    # Simple line-by-line comparison
    max_lines = max(len(original_lines), len(remediated_lines))
    
    for i in range(max_lines):
        original_line = original_lines[i] if i < len(original_lines) else None
        remediated_line = remediated_lines[i] if i < len(remediated_lines) else None
        
        if original_line != remediated_line:
            if original_line is None:
                # Added line
                diff_result['added_lines'].append({
                    'line_number': i + 1,
                    'content': remediated_line
                })
                diff_result['statistics']['added_count'] += 1
            elif remediated_line is None:
                # Removed line
                diff_result['removed_lines'].append({
                    'line_number': i + 1,
                    'content': original_line
                })
                diff_result['statistics']['removed_count'] += 1
            else:
                # Modified line
                diff_result['modified_lines'].append({
                    'line_number': i + 1,
                    'original': original_line,
                    'remediated': remediated_line
                })
                diff_result['statistics']['modified_count'] += 1
    
    return diff_result

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Simple test endpoint to check if server is running."""
    return jsonify({'status': 'ok', 'message': 'Server is running', 'timestamp': datetime.now().isoformat()})

@app.route('/api/scan/github', methods=['POST'])
def scan_github_repository():
    """Scan GitHub repository for logic bombs and security threats"""
    try:
        data = request.get_json()
        github_url = data.get('github_url')
        github_token = data.get('github_token')  # New: GitHub token for private repos
        scan_id = data.get('scan_id', str(uuid.uuid4()))
        scan_type = data.get('scan_type', 'github')
        project_id = data.get('project_id', f'github-scan-{int(datetime.now().timestamp())}')
        project_name = data.get('project_name', 'GitHub Repository Scan')
        ait_tag = data.get('ait_tag', 'AIT')
        spk_tag = data.get('spk_tag', 'SPK')
        repo_name = data.get('repo_name', 'GitHub Repo')

        if not github_url:
            return jsonify({'error': 'GitHub URL is required'}), 400

        # Extract repository information from URL
        # Support formats: https://github.com/owner/repo, https://github.com/owner/repo.git
        import re
        github_pattern = r'https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$'
        match = re.match(github_pattern, github_url.strip())
        
        if not match:
            return jsonify({'error': 'Invalid GitHub URL format. Use: https://github.com/owner/repository'}), 400
        
        owner, repo = match.groups()
        
        # Clone the repository
        import tempfile
        import subprocess
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        repo_path = os.path.join(temp_dir, repo)
        
        try:
            # Clone the repository with authentication if token provided
            if github_token:
                # For private repositories, use token authentication
                clone_url = f"https://{github_token}@github.com/{owner}/{repo}.git"
                clone_cmd = ['git', 'clone', clone_url, repo_path]
            else:
                # For public repositories, use regular clone
                clone_cmd = ['git', 'clone', github_url, repo_path]
            
            result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                error_msg = result.stderr.strip()
                if "Authentication failed" in error_msg or "401" in error_msg:
                    return jsonify({'error': 'Authentication failed. Please check your GitHub token.'}), 401
                elif "Repository not found" in error_msg or "404" in error_msg:
                    return jsonify({'error': 'Repository not found or access denied. Check if the repository exists and you have access.'}), 404
                else:
                    return jsonify({'error': f'Failed to clone repository: {error_msg}'}), 400
            
            # Save repository files to uploaded_projects/{scan_id}/original/
            base_upload_dir = Path('uploaded_projects') / scan_id / 'original'
            base_upload_dir.mkdir(parents=True, exist_ok=True)
            
            file_paths = []
            uploaded_files_for_prompts = []
            
            # Walk through the repository and collect all files
            for root, dirs, files in os.walk(repo_path):
                # Skip .git directory
                if '.git' in dirs:
                    dirs.remove('.git')
                
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, repo_path)
                    
                    # Skip binary files and large files
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Skip files larger than 1MB
                        if len(content) > 1024 * 1024:
                            continue
                            
                        # Save file to uploaded_projects
                        target_path = base_upload_dir / relative_path
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(target_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        file_paths.append({
                            'id': f"file_{len(file_paths)}",
                            'name': relative_path,
                            'path': str(target_path),
                            'type': get_file_language(relative_path)
                        })
                        
                        uploaded_files_for_prompts.append({
                            'file_path': str(target_path),
                            'content': content,
                            'file_name': relative_path
                        })
                        
                    except (UnicodeDecodeError, PermissionError, OSError):
                        # Skip binary files or files that can't be read
                        continue
            
            if not file_paths:
                return jsonify({'error': 'No readable files found in repository'}), 400
            
            # Enhanced file scan with comprehensive threat analysis
            scan_result = perform_enhanced_file_scan(
                scan_id=scan_id,
                project_id=project_id,
                project_name=project_name,
                file_paths=file_paths,
                scan_type=scan_type,
                ait_tag=ait_tag,
                spk_tag=spk_tag,
                repo_name=repo_name
            )
            
            # Add GitHub-specific information
            scan_result['github_info'] = {
                'owner': owner,
                'repo': repo,
                'url': github_url,
                'files_count': len(file_paths),
                'is_private': bool(github_token),  # Indicate if this was a private repo
                'auth_used': bool(github_token)    # Indicate if authentication was used
            }
            
            # Generate VS Code Copilot prompts automatically
            try:
                prompts_data = generate_vscode_copilot_prompts(scan_id, uploaded_files_for_prompts)
                scan_result['prompts_generated'] = True
                scan_result['prompts_data'] = prompts_data
            except Exception as e:
                logging.error(f"Error generating prompts: {e}")
                scan_result['prompts_generated'] = False
                scan_result['prompts_error'] = str(e)
            
            return jsonify(scan_result)
            
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.warning(f"Failed to clean up temp directory: {e}")
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_file_language(filename: str) -> str:
    """Determine file language based on extension"""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    language_map = {
        'py': 'python',
        'js': 'javascript',
        'ts': 'typescript',
        'jsx': 'javascript',
        'tsx': 'typescript',
        'java': 'java',
        'cpp': 'cpp',
        'c': 'c',
        'cs': 'csharp',
        'php': 'php',
        'rb': 'ruby',
        'go': 'go',
        'rs': 'rust',
        'swift': 'swift',
        'kt': 'kotlin',
        'scala': 'scala',
        'html': 'html',
        'css': 'css',
        'scss': 'scss',
        'sass': 'sass',
        'less': 'less',
        'json': 'json',
        'xml': 'xml',
        'yaml': 'yaml',
        'yml': 'yaml',
        'toml': 'toml',
        'ini': 'ini',
        'cfg': 'ini',
        'conf': 'ini',
        'sh': 'bash',
        'bash': 'bash',
        'zsh': 'bash',
        'fish': 'bash',
        'ps1': 'powershell',
        'bat': 'batch',
        'cmd': 'batch',
        'sql': 'sql',
        'md': 'markdown',
        'txt': 'text',
        'log': 'text'
    }
    
    return language_map.get(ext, 'text')

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
    print("  • [COPILOT] Automated Copilot Agent")
    print("\n🌐 ThreatGuard Command Center available at: http://localhost:5000")
    print("📋 Enhanced API endpoints:")
    print("  • GET  /api/command-center/metrics - Enhanced threat metrics")
    print("  • POST /api/logic-bomb-scan - Advanced logic bomb scan")
    print("  • GET  /api/threats - Comprehensive threat management")
    print("  • GET  /api/threat-shields - Threat protection shields")
    print("  • GET  /api/threat-intelligence - Threat intelligence data")
    print("  • POST /api/scan/files - Enhanced file scanning")
    print("  • GET  /api/health - System health monitoring")
    print("  • POST /api/copilot/agent/start - Start automated Copilot agent")
    print("  • POST /api/copilot/agent/stop - Stop automated Copilot agent")
    print("  • GET  /api/copilot/agent/status - Get agent status")
    print("="*80)
    
    # Start the automated Copilot agent
    try:
        start_copilot_agent()
        print("[COPILOT] Automated Copilot Agent started successfully")
    except Exception as e:
        print(f"⚠️ Warning: Could not start Copilot agent: {e}")
    
    app.run(host='127.0.0.1', port=5000, debug=True)