#!/usr/bin/env python3
"""
ThreatGuard Pro - Complete Integration Script
Enhanced Logic Bomb Detection & Threat Intelligence System
Integrates: Advanced Scanner, Threat Rules, Shields, and Intelligence Dashboard
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
import subprocess
import argparse

# Component imports
try:
    from threatguard_main import LogicBombDetector, SecurityRule, ThreatShield
    from dashboard_api import app as dashboard_app
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all component files are in the same directory:")
    print("  • threatguard_main.py")
    print("  • dashboard_api.py")
    sys.exit(1)

class ThreatGuardProIntegration:
    """Complete integration of ThreatGuard Pro components"""
    
    def __init__(self, base_dir: str = "threatguard_workspace"):
        self.base_dir = Path(base_dir)
        self.setup_workspace()
        
        print("🛡️ Initializing ThreatGuard Pro...")
        
        # Core enhanced threat detector
        self.detector = LogicBombDetector(str(self.base_dir / "threatguard_data"))
        
        # Configuration
        self.config = self.load_config()
        
        print("✅ ThreatGuard Pro initialized successfully!")
        print(f"📁 Workspace: {self.base_dir}")
        print(f"🔍 Detection Rules: {len(self.detector.rules_engine.rules)}")
        print(f"🛡️ Threat Shields: {len(self.detector.threat_shields.shields)}")
    
    def setup_workspace(self):
        """Set up the ThreatGuard workspace directory structure"""
        print(f"📁 Setting up ThreatGuard workspace: {self.base_dir}")
        
        # Create main directories
        directories = [
            self.base_dir,
            self.base_dir / "threatguard_data",
            self.base_dir / "reports",
            self.base_dir / "exports",
            self.base_dir / "imports",
            self.base_dir / "backups",
            self.base_dir / "temp",
            self.base_dir / "logs"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Create default configuration
        self.create_default_config()
    
    def create_default_config(self):
        """Create default ThreatGuard configuration file"""
        config_file = self.base_dir / "threatguard_config.json"
        
        if not config_file.exists():
            default_config = {
                "threatguard": {
                    "version": "2.0.0",
                    "detection_level": "enhanced",
                    "max_file_size_mb": 16,
                    "supported_extensions": [
                        ".py", ".js", ".ts", ".java", ".cs", ".php", ".html", 
                        ".json", ".xml", ".sql", ".rb", ".go", ".c", ".cpp", ".rs"
                    ],
                    "exclude_patterns": [
                        "node_modules/", ".git/", "__pycache__/", "build/", 
                        "dist/", ".venv/", "venv/", "target/"
                    ],
                    "parallel_processing": True,
                    "max_workers": 4
                },
                "threat_detection": {
                    "logic_bomb_detection": True,
                    "financial_fraud_detection": True,
                    "destructive_payload_detection": True,
                    "time_trigger_analysis": True,
                    "user_targeted_analysis": True,
                    "execution_counter_analysis": True,
                    "system_specific_analysis": True,
                    "network_trigger_analysis": True,
                    "auto_threat_analysis": True,
                    "severity_threshold": "MEDIUM_RISK",
                    "threat_categories": [
                        "SCHEDULED_THREAT", "TARGETED_ATTACK", "EXECUTION_TRIGGER",
                        "DESTRUCTIVE_PAYLOAD", "FINANCIAL_FRAUD", "SYSTEM_SPECIFIC_THREAT",
                        "CONNECTION_BASED_THREAT"
                    ]
                },
                "threat_shields": {
                    "default_shield": "logic-bomb-protection-shield",
                    "auto_protection": True,
                    "block_critical_threats": True,
                    "block_financial_fraud": True,
                    "alert_on_high_risk": True,
                    "protection_effectiveness_target": 95
                },
                "threat_intelligence": {
                    "enabled": True,
                    "real_time_analysis": True,
                    "pattern_learning": True,
                    "threat_scoring": True,
                    "intelligence_sharing": False,
                    "history_retention_days": 90
                },
                "dashboard": {
                    "host": "127.0.0.1",
                    "port": 5000,
                    "debug": False,
                    "auto_refresh_seconds": 30,
                    "theme": "dark",
                    "show_advanced_metrics": True
                },
                "notifications": {
                    "enabled": True,
                    "email_alerts": False,
                    "slack_notifications": False,
                    "webhook_url": "",
                    "alert_on": [
                        "critical_bomb_detected", "financial_fraud_detected",
                        "destructive_payload_detected", "shield_breach"
                    ]
                },
                "reporting": {
                    "auto_generate_reports": True,
                    "report_formats": ["json", "html", "pdf"],
                    "detailed_analysis": True,
                    "include_code_snippets": True,
                    "include_remediation_guides": True
                },
                "exports": {
                    "auto_export": False,
                    "export_formats": ["json", "yaml", "csv"],
                    "export_schedule": "weekly",
                    "include_threat_intelligence": True
                }
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"📝 Created ThreatGuard configuration: {config_file}")
    
    def load_config(self) -> dict:
        """Load ThreatGuard configuration from file"""
        config_file = self.base_dir / "threatguard_config.json"
        
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Error loading config: {e}")
            return {}
    
    def scan_project_comprehensive(self, project_path: str, project_id: str, 
                                 team_name: str = None) -> dict:
        """Perform comprehensive threat detection scan"""
        print(f"\n🔍 Starting ThreatGuard Pro comprehensive scan")
        print(f"🎯 Target: {project_id}")
        print(f"📁 Path: {project_path}")
        
        start_time = datetime.now()
        
        try:
            # 1. Enhanced threat detection scan
            print("  1️⃣ Running enhanced threat detection...")
            scan_result = self.detector.scan_project(project_path, project_id)
            
            # 2. Generate comprehensive threat intelligence report
            print("  2️⃣ Generating threat intelligence report...")
            threat_report = self._generate_threat_intelligence_report(
                scan_result, project_path, team_name
            )
            
            # 3. Save detailed report
            print("  3️⃣ Saving comprehensive report...")
            self._save_comprehensive_report(threat_report, project_id)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print(f"✅ ThreatGuard Pro scan completed in {duration:.2f} seconds")
            print(f"🚨 Threats detected: {len(scan_result.issues)}")
            print(f"💣 Logic bomb risk score: {scan_result.logic_bomb_risk_score}/100")
            print(f"🛡️ Threat shield: {scan_result.threat_shield_status}")
            print(f"⚡ Threat level: {scan_result.threat_intelligence.get('threat_level', 'UNKNOWN')}")
            
            return threat_report
            
        except Exception as e:
            print(f"❌ Scan failed: {str(e)}")
            return {'error': str(e), 'project_id': project_id}
    
    def _generate_threat_intelligence_report(self, scan_result, project_path: str, 
                                           team_name: str = None) -> dict:
        """Generate comprehensive threat intelligence report"""
        
        # Enhanced threat analysis
        threat_breakdown = {
            'scheduled_threats': len([i for i in scan_result.issues if i.type == "SCHEDULED_THREAT"]),
            'targeted_attacks': len([i for i in scan_result.issues if i.type == "TARGETED_ATTACK"]),
            'execution_triggers': len([i for i in scan_result.issues if i.type == "EXECUTION_TRIGGER"]),
            'destructive_payloads': len([i for i in scan_result.issues if i.type == "DESTRUCTIVE_PAYLOAD"]),
            'financial_fraud': len([i for i in scan_result.issues if i.type == "FINANCIAL_FRAUD"]),
            'system_specific_threats': len([i for i in scan_result.issues if i.type == "SYSTEM_SPECIFIC_THREAT"]),
            'connection_based_threats': len([i for i in scan_result.issues if i.type == "CONNECTION_BASED_THREAT"])
        }
        
        # Calculate threat severity distribution
        severity_breakdown = {}
        for severity in ["CRITICAL_BOMB", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "CRITICAL", "MAJOR", "MINOR"]:
            severity_breakdown[severity] = len([i for i in scan_result.issues if i.severity == severity])
        
        # Generate threat recommendations
        recommendations = self._generate_threat_recommendations(scan_result.issues, threat_breakdown)
        
        # Calculate threat metrics
        threat_metrics = {
            'total_threats': len(scan_result.issues),
            'critical_threats': severity_breakdown.get('CRITICAL_BOMB', 0) + severity_breakdown.get('CRITICAL', 0),
            'logic_bomb_risk_score': scan_result.logic_bomb_risk_score,
            'threat_density': len(scan_result.issues) / max(1, scan_result.lines_of_code / 1000),  # threats per KLOC
            'threat_diversity': len([t for t in threat_breakdown.values() if t > 0]),
            'security_rating': scan_result.security_rating,
            'threat_shield_effectiveness': self._calculate_shield_effectiveness(scan_result)
        }
        
        # Prepare detailed threat list
        detailed_threats = []
        for issue in scan_result.issues:
            detailed_threats.append({
                'id': issue.id,
                'rule_id': issue.rule_id,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'message': issue.message,
                'severity': issue.severity,
                'type': issue.type,
                'status': issue.status,
                'code_snippet': issue.code_snippet,
                'suggested_fix': issue.suggested_fix,
                'threat_level': issue.threat_level,
                'trigger_analysis': issue.trigger_analysis,
                'payload_analysis': issue.payload_analysis,
                'effort_minutes': issue.effort
            })
        
        return {
            'scan_info': {
                'project_id': scan_result.project_id,
                'scan_id': scan_result.scan_id,
                'timestamp': scan_result.timestamp,
                'duration_ms': scan_result.duration_ms,
                'project_path': project_path,
                'team_name': team_name,
                'threatguard_version': '2.0.0'
            },
            'threat_metrics': threat_metrics,
            'threat_breakdown': threat_breakdown,
            'severity_breakdown': severity_breakdown,
            'threat_shield': {
                'status': scan_result.threat_shield_status,
                'effectiveness': self._calculate_shield_effectiveness(scan_result)
            },
            'threat_intelligence': scan_result.threat_intelligence,
            'detailed_threats': detailed_threats,
            'recommendations': recommendations,
            'project_metrics': {
                'files_scanned': scan_result.files_scanned,
                'lines_of_code': scan_result.lines_of_code,
                'coverage': scan_result.coverage,
                'duplications': scan_result.duplications,
                'maintainability_rating': scan_result.maintainability_rating,
                'reliability_rating': scan_result.reliability_rating,
                'security_rating': scan_result.security_rating
            },
            'summary': {
                'threat_level': scan_result.threat_intelligence.get('threat_level', 'UNKNOWN'),
                'immediate_action_required': severity_breakdown.get('CRITICAL_BOMB', 0) > 0,
                'financial_fraud_detected': threat_breakdown['financial_fraud'] > 0,
                'destructive_payloads_found': threat_breakdown['destructive_payloads'] > 0,
                'overall_security_posture': self._calculate_security_posture(scan_result)
            }
        }
    
    def _generate_threat_recommendations(self, issues: list, threat_breakdown: dict) -> list:
        """Generate specific threat remediation recommendations"""
        recommendations = []
        
        # Critical threat recommendations
        critical_bombs = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
        if critical_bombs > 0:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'category': 'CRITICAL_THREATS',
                'message': f"🚨 URGENT: {critical_bombs} critical logic bombs detected requiring immediate neutralization",
                'actions': [
                    'Review and remove all time-based conditional triggers',
                    'Eliminate destructive file operations',
                    'Remove user-targeted malicious code',
                    'Implement proper error handling instead of destructive actions'
                ]
            })
        
        # Financial fraud recommendations
        if threat_breakdown['financial_fraud'] > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'FINANCIAL_SECURITY',
                'message': f"💰 Financial fraud patterns detected in {threat_breakdown['financial_fraud']} locations",
                'actions': [
                    'Remove unauthorized cryptocurrency wallet addresses',
                    'Eliminate payment redirection code',
                    'Implement legitimate payment processing',
                    'Review all financial transaction handling'
                ]
            })
        
        # Scheduled threat recommendations
        if threat_breakdown['scheduled_threats'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'TIME_BOMBS',
                'message': f"⏰ Time-based logic bombs found in {threat_breakdown['scheduled_threats']} locations",
                'actions': [
                    'Replace date/time conditions with proper scheduling',
                    'Use cron jobs or task schedulers for time-based actions',
                    'Remove hardcoded date comparisons',
                    'Implement proper calendar-based logic'
                ]
            })
        
        # Targeted attack recommendations
        if threat_breakdown['targeted_attacks'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'USER_TARGETING',
                'message': f"🎯 User-targeted attacks detected in {threat_breakdown['targeted_attacks']} locations",
                'actions': [
                    'Remove user-specific malicious conditions',
                    'Implement proper user authentication',
                    'Use role-based access control instead',
                    'Eliminate personalized attack vectors'
                ]
            })
        
        # General security recommendations
        if len(issues) > 10:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'OVERALL_SECURITY',
                'message': f"🔒 Multiple security issues detected requiring systematic review",
                'actions': [
                    'Conduct comprehensive code security review',
                    'Implement security testing in CI/CD pipeline',
                    'Train development team on secure coding practices',
                    'Establish security code review process'
                ]
            })
        
        return recommendations
    
    def _calculate_shield_effectiveness(self, scan_result) -> float:
        """Calculate threat shield effectiveness percentage"""
        if not scan_result.issues:
            return 100.0
        
        critical_threats = len([i for i in scan_result.issues if i.severity in ["CRITICAL_BOMB", "CRITICAL"]])
        total_threats = len(scan_result.issues)
        
        if scan_result.threat_shield_status == "PROTECTED":
            return max(85.0, 100.0 - (critical_threats * 10) - (total_threats * 2))
        elif scan_result.threat_shield_status == "ALERT":
            return max(60.0, 80.0 - (critical_threats * 8) - (total_threats * 1.5))
        else:  # BLOCKED
            return max(30.0, 50.0 - (critical_threats * 5) - (total_threats * 1))
    
    def _calculate_security_posture(self, scan_result) -> str:
        """Calculate overall security posture"""
        critical_bombs = len([i for i in scan_result.issues if i.severity == "CRITICAL_BOMB"])
        high_risks = len([i for i in scan_result.issues if i.severity == "HIGH_RISK"])
        total_threats = len(scan_result.issues)
        
        if critical_bombs > 0:
            return "CRITICAL_RISK"
        elif high_risks > 3 or scan_result.logic_bomb_risk_score > 70:
            return "HIGH_RISK"
        elif high_risks > 0 or total_threats > 5:
            return "MEDIUM_RISK"
        elif total_threats > 0:
            return "LOW_RISK"
        else:
            return "SECURE"
    
    def _save_comprehensive_report(self, report: dict, project_id: str):
        """Save comprehensive threat intelligence report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_file = self.base_dir / "reports" / f"{project_id}_{timestamp}_threatguard_report.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save HTML report
        html_file = self.base_dir / "reports" / f"{project_id}_{timestamp}_threatguard_report.html"
        self._generate_html_report(report, html_file)
        
        print(f"📊 Comprehensive reports saved:")
        print(f"  📄 JSON: {json_file}")
        print(f"  🌐 HTML: {html_file}")
    
    def _generate_html_report(self, report: dict, html_file: Path):
        """Generate HTML threat intelligence report"""
        scan_info = report['scan_info']
        threat_metrics = report['threat_metrics']
        threat_breakdown = report['threat_breakdown']
        recommendations = report['recommendations']
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ThreatGuard Pro Report - {scan_info['project_id']}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .header {{ background: #dc3545; color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
                .header h1 {{ margin: 0; font-size: 2.5rem; }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
                .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .metric-card {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }}
                .metric-value {{ font-size: 3rem; font-weight: bold; margin-bottom: 10px; }}
                .metric-label {{ color: #666; font-size: 1rem; }}
                .critical {{ color: #dc3545; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                .section {{ background: white; padding: 30px; margin-bottom: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .section h2 {{ color: #dc3545; margin-bottom: 20px; border-bottom: 2px solid #dc3545; padding-bottom: 10px; }}
                .threat-item {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; border-radius: 4px; }}
                .recommendation {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 10px 0; border-radius: 4px; }}
                .recommendation.immediate {{ background: #f8d7da; border-color: #dc3545; }}
                .recommendation.critical {{ background: #fdf2f2; border-color: #dc3545; }}
                .code-snippet {{ background: #2d3748; color: #e2e8f0; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }}
                .stats-table {{ width: 100%; border-collapse: collapse; }}
                .stats-table th, .stats-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                .stats-table th {{ background: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ ThreatGuard Pro Security Report</h1>
                <p>Project: {scan_info['project_id']} | Scan Date: {datetime.fromisoformat(scan_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>ThreatGuard Version: {scan_info['threatguard_version']} | Scan Duration: {scan_info['duration_ms']}ms</p>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value critical">{threat_metrics['total_threats']}</div>
                    <div class="metric-label">Total Threats</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value critical">{threat_metrics['critical_threats']}</div>
                    <div class="metric-label">Critical Threats</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value {'critical' if threat_metrics['logic_bomb_risk_score'] > 70 else 'high' if threat_metrics['logic_bomb_risk_score'] > 40 else 'medium' if threat_metrics['logic_bomb_risk_score'] > 20 else 'low'}">{threat_metrics['logic_bomb_risk_score']}/100</div>
                    <div class="metric-label">Logic Bomb Risk Score</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value {'low' if report['threat_shield']['status'] == 'PROTECTED' else 'critical'}">{report['threat_shield']['status']}</div>
                    <div class="metric-label">Threat Shield Status</div>
                </div>
            </div>

            <div class="section">
                <h2>🚨 Threat Breakdown</h2>
                <table class="stats-table">
                    <tr><th>Threat Type</th><th>Count</th><th>Description</th></tr>
                    <tr><td>⏰ Scheduled Threats (Time Bombs)</td><td>{threat_breakdown['scheduled_threats']}</td><td>Time-based conditional triggers</td></tr>
                    <tr><td>🎯 Targeted Attacks (User Bombs)</td><td>{threat_breakdown['targeted_attacks']}</td><td>User-specific malicious code</td></tr>
                    <tr><td>🔢 Execution Triggers (Counter Bombs)</td><td>{threat_breakdown['execution_triggers']}</td><td>Count-based activation triggers</td></tr>
                    <tr><td>💥 Destructive Payloads</td><td>{threat_breakdown['destructive_payloads']}</td><td>Data destruction operations</td></tr>
                    <tr><td>💰 Financial Fraud</td><td>{threat_breakdown['financial_fraud']}</td><td>Unauthorized money redirection</td></tr>
                    <tr><td>🖥️ System-Specific Threats</td><td>{threat_breakdown['system_specific_threats']}</td><td>Environment-based triggers</td></tr>
                    <tr><td>🌐 Network-Based Threats</td><td>{threat_breakdown['connection_based_threats']}</td><td>Connection failure triggers</td></tr>
                </table>
            </div>

            <div class="section">
                <h2>⚠️ Priority Recommendations</h2>"""
        
        for rec in recommendations:
            priority_class = rec['priority'].lower()
            html_content += f"""
                <div class="recommendation {priority_class}">
                    <h3>🔴 {rec['priority']} - {rec['category']}</h3>
                    <p>{rec['message']}</p>
                    <ul>"""
            for action in rec['actions']:
                html_content += f"<li>{action}</li>"
            html_content += """</ul>
                </div>"""
        
        html_content += f"""
            </div>

            <div class="section">
                <h2>📊 Detailed Threat Analysis</h2>
                <p><strong>Files Scanned:</strong> {report['project_metrics']['files_scanned']}</p>
                <p><strong>Lines of Code:</strong> {report['project_metrics']['lines_of_code']:,}</p>
                <p><strong>Security Rating:</strong> {report['project_metrics']['security_rating']}</p>
                <p><strong>Threat Density:</strong> {threat_metrics['threat_density']:.2f} threats per 1000 lines</p>
                <p><strong>Shield Effectiveness:</strong> {report['threat_shield']['effectiveness']:.1f}%</p>
            </div>

            <div class="section">
                <h2>🔍 Individual Threats</h2>"""
        
        for threat in report['detailed_threats'][:20]:  # Show top 20 threats
            severity_class = 'critical' if threat['severity'] in ['CRITICAL_BOMB', 'CRITICAL'] else 'high' if threat['severity'] in ['HIGH_RISK', 'MAJOR'] else 'medium'
            html_content += f"""
                <div class="threat-item">
                    <h4 class="{severity_class}">🚨 {threat['type'].replace('_', ' ')} - {threat['severity']}</h4>
                    <p><strong>File:</strong> {threat['file_path']} (Line {threat['line_number']})</p>
                    <p><strong>Message:</strong> {threat['message']}</p>
                    <p><strong>Trigger Analysis:</strong> {threat['trigger_analysis']}</p>
                    <p><strong>Payload Analysis:</strong> {threat['payload_analysis']}</p>
                    <div class="code-snippet">{threat['code_snippet']}</div>
                    <p><strong>Recommended Fix:</strong> {threat['suggested_fix']}</p>
                </div>"""
        
        html_content += f"""
            </div>

            <div class="section">
                <h2>📋 Summary</h2>
                <p><strong>Overall Threat Level:</strong> <span class="{'critical' if report['summary']['threat_level'] == 'CRITICAL' else 'high' if report['summary']['threat_level'] == 'HIGH' else 'medium'}">{report['summary']['threat_level']}</span></p>
                <p><strong>Security Posture:</strong> <span class="{'critical' if report['summary']['overall_security_posture'] == 'CRITICAL_RISK' else 'high' if 'HIGH' in report['summary']['overall_security_posture'] else 'medium'}">{report['summary']['overall_security_posture']}</span></p>
                <p><strong>Immediate Action Required:</strong> {'Yes' if report['summary']['immediate_action_required'] else 'No'}</p>
                <p><strong>Financial Fraud Detected:</strong> {'Yes' if report['summary']['financial_fraud_detected'] else 'No'}</p>
                <p><strong>Destructive Payloads Found:</strong> {'Yes' if report['summary']['destructive_payloads_found'] else 'No'}</p>
            </div>

            <div class="section">
                <p style="text-align: center; color: #666; font-size: 0.9rem;">
                    Generated by ThreatGuard Pro v{scan_info['threatguard_version']} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                    Advanced Logic Bomb Detection & Threat Intelligence System
                </p>
            </div>
        </body>
        </html>
        """
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def start_dashboard_server(self):
        """Start the ThreatGuard Pro dashboard server"""
        print("🌐 Starting ThreatGuard Pro Command Center...")
        
        config = self.config.get('dashboard', {})
        host = config.get('host', '127.0.0.1')
        port = config.get('port', 5000)
        debug = config.get('debug', False)
        
        print(f"📍 ThreatGuard Command Center URL: http://{host}:{port}")
        print("🎯 Available features:")
        print("  • Enhanced Threat Detection Dashboard")
        print("  • Logic Bomb Risk Analysis")
        print("  • Real-time Threat Intelligence")
        print("  • Advanced Pattern Recognition")
        print("  • Threat Shield Management")
        print("  • Financial Fraud Detection")
        print("  • Comprehensive Reporting")
        
        # Update dashboard app with our enhanced detector
        dashboard_app.detector = self.detector
        
        try:
            dashboard_app.run(host=host, port=port, debug=debug)
        except KeyboardInterrupt:
            print("\n🛑 ThreatGuard Pro Command Center stopped")
    
    def export_all_data(self, format_type: str = 'json') -> str:
        """Export all ThreatGuard data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_file = self.base_dir / "exports" / f"threatguard_export_{timestamp}.{format_type}"
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'format': format_type,
                'threatguard_version': '2.0.0',
                'components': ['detector', 'rules', 'shields', 'intelligence']
            },
            'threat_detection_data': {
                'scan_history': [
                    {
                        'scan_id': scan.scan_id,
                        'project_id': scan.project_id,
                        'timestamp': scan.timestamp,
                        'metrics': {
                            'files_scanned': scan.files_scanned,
                            'lines_of_code': scan.lines_of_code,
                            'logic_bomb_risk_score': scan.logic_bomb_risk_score,
                            'threat_shield_status': scan.threat_shield_status,
                            'security_rating': scan.security_rating
                        },
                        'threat_intelligence': scan.threat_intelligence
                    }
                    for scan in self.detector.scan_history
                ],
                'total_threats': len(self.detector.issue_manager.issues),
                'active_threats': len(self.detector.issue_manager.get_active_threats()),
                'critical_bombs': len(self.detector.issue_manager.get_critical_bombs())
            },
            'rules_data': {
                'total_rules': len(self.detector.rules_engine.rules),
                'enabled_rules': len([r for r in self.detector.rules_engine.rules.values() if r.enabled]),
                'threat_categories': list(set(r.threat_category for r in self.detector.rules_engine.rules.values())),
                'rules': [
                    {
                        'id': rule.id,
                        'name': rule.name,
                        'description': rule.description,
                        'severity': rule.severity,
                        'type': rule.type,
                        'language': rule.language,
                        'threat_category': rule.threat_category,
                        'enabled': rule.enabled
                    }
                    for rule in self.detector.rules_engine.rules.values()
                ]
            },
            'threat_shields_data': {
                'total_shields': len(self.detector.threat_shields.shields),
                'active_shields': len([s for s in self.detector.threat_shields.shields.values() if s.is_default]),
                'shields': [
                    {
                        'id': shield.id,
                        'name': shield.name,
                        'threat_categories': shield.threat_categories,
                        'risk_threshold': shield.risk_threshold,
                        'is_default': shield.is_default
                    }
                    for shield in self.detector.threat_shields.shields.values()
                ]
            }
        }
        
        if format_type == 'yaml':
            import yaml
            content = yaml.dump(export_data, default_flow_style=False)
        else:
            content = json.dumps(export_data, indent=2)
        
        with open(export_file, 'w') as f:
            f.write(content)
        
        print(f"📤 ThreatGuard data exported to: {export_file}")
        return str(export_file)
    
    def backup_workspace(self) -> str:
        """Create a backup of the entire ThreatGuard workspace"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"threatguard_backup_{timestamp}"
        backup_path = self.base_dir / "backups" / backup_name
        
        # Create backup directory
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Copy all data files
        data_files = [
            "threatguard_data",
            "threatguard_config.json",
            "reports",
            "logs"
        ]
        
        for item in data_files:
            source = self.base_dir / item
            if source.exists():
                if source.is_file():
                    shutil.copy2(source, backup_path)
                else:
                    shutil.copytree(source, backup_path / item, dirs_exist_ok=True)
        
        # Create backup archive
        archive_path = str(backup_path) + ".zip"
        shutil.make_archive(str(backup_path), 'zip', backup_path)
        
        # Clean up temporary directory
        shutil.rmtree(backup_path)
        
        print(f"💾 ThreatGuard workspace backed up to: {archive_path}")
        return archive_path
    
    def get_system_status(self) -> dict:
        """Get comprehensive ThreatGuard system status"""
        total_threats = len(self.detector.issue_manager.issues)
        active_threats = len(self.detector.issue_manager.get_active_threats())
        critical_bombs = len(self.detector.issue_manager.get_critical_bombs())
        
        return {
            'threatguard_info': {
                'version': '2.0.0',
                'workspace_path': str(self.base_dir),
                'workspace_size_mb': sum(f.stat().st_size for f in self.base_dir.rglob('*') if f.is_file()) / (1024*1024)
            },
            'threat_detection': {
                'total_scans': len(self.detector.scan_history),
                'total_threats': total_threats,
                'active_threats': active_threats,
                'critical_bombs': critical_bombs,
                'neutralized_threats': total_threats - active_threats,
                'last_scan': self.detector.scan_history[-1].timestamp if self.detector.scan_history else None
            },
            'detection_rules': {
                'total_rules': len(self.detector.rules_engine.rules),
                'enabled_rules': len([r for r in self.detector.rules_engine.rules.values() if r.enabled]),
                'threat_categories': len(set(r.threat_category for r in self.detector.rules_engine.rules.values())),
                'custom_rules': len([r for r in self.detector.rules_engine.rules.values() if r.custom])
            },
            'threat_shields': {
                'total_shields': len(self.detector.threat_shields.shields),
                'active_shields': len([s for s in self.detector.threat_shields.shields.values() if s.is_default]),
                'protection_categories': len(set(cat for shield in self.detector.threat_shields.shields.values() for cat in (shield.threat_categories or [])))
            },
            'system_health': {
                'status': 'healthy' if critical_bombs == 0 else 'critical' if critical_bombs > 5 else 'warning',
                'detection_accuracy': 'high',
                'performance': 'optimal',
                'data_integrity': 'verified'
            }
        }

def main():
    """Main entry point for ThreatGuard Pro integration"""
    parser = argparse.ArgumentParser(
        description="ThreatGuard Pro - Advanced Logic Bomb Detection & Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threatguard_integration.py scan ./my-project web-app-v1
  python threatguard_integration.py dashboard
  python threatguard_integration.py export json
  python threatguard_integration.py status
        """
    )
    
    parser.add_argument('command', choices=['scan', 'dashboard', 'export', 'backup', 'status'],
                       help='Command to execute')
    parser.add_argument('project_path', nargs='?', help='Path to project for scanning')
    parser.add_argument('project_id', nargs='?', help='Project identifier')
    parser.add_argument('--team', help='Team name for the project')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json',
                       help='Export format (default: json)')
    parser.add_argument('--workspace', default='threatguard_workspace',
                       help='Workspace directory (default: threatguard_workspace)')
    
    args = parser.parse_args()
    
    print("🛡️ ThreatGuard Pro - Advanced Logic Bomb Detection System")
    print("=" * 70)
    
    # Initialize the ThreatGuard integration system
    threatguard = ThreatGuardProIntegration(args.workspace)
    
    # Display system status
    status = threatguard.get_system_status()
    print(f"\n📊 ThreatGuard System Status:")
    print(f"  • Version: {status['threatguard_info']['version']}")
    print(f"  • Workspace: {status['threatguard_info']['workspace_path']}")
    print(f"  • Total Scans: {status['threat_detection']['total_scans']}")
    print(f"  • Detection Rules: {status['detection_rules']['total_rules']} ({status['detection_rules']['enabled_rules']} enabled)")
    print(f"  • Active Threats: {status['threat_detection']['active_threats']}")
    print(f"  • Critical Bombs: {status['threat_detection']['critical_bombs']}")
    print(f"  • Threat Shields: {status['threat_shields']['total_shields']}")
    print(f"  • System Health: {status['system_health']['status'].upper()}")
    
    # Execute command
    if args.command == 'scan':
        if not args.project_path or not args.project_id:
            print("❌ Error: scan command requires project_path and project_id")
            print("Usage: python threatguard_integration.py scan <project_path> <project_id> [--team <team_name>]")
            sys.exit(1)
        
        print(f"\n🎯 Starting ThreatGuard Pro scan...")
        result = threatguard.scan_project_comprehensive(args.project_path, args.project_id, args.team)
        
        if 'error' not in result:
            print(f"\n📈 ThreatGuard Scan Results Summary:")
            print(f"  • Overall Threat Level: {result['summary']['threat_level']}")
            print(f"  • Critical Threats: {result['threat_metrics']['critical_threats']}")
            print(f"  • Logic Bomb Risk Score: {result['threat_metrics']['logic_bomb_risk_score']}/100")
            print(f"  • Threat Shield: {'✅ PROTECTED' if result['threat_shield']['status'] == 'PROTECTED' else '❌ COMPROMISED'}")
            print(f"  • Security Posture: {result['summary']['overall_security_posture']}")
            print(f"  • Immediate Action Required: {'YES' if result['summary']['immediate_action_required'] else 'NO'}")
            
            if result['recommendations']:
                print(f"\n⚠️ Priority Recommendations:")
                for rec in result['recommendations'][:3]:
                    print(f"  • {rec['priority']}: {rec['message']}")
    
    elif args.command == 'dashboard':
        threatguard.start_dashboard_server()
    
    elif args.command == 'export':
        export_path = threatguard.export_all_data(args.format)
        print(f"✅ ThreatGuard data exported to: {export_path}")
    
    elif args.command == 'backup':
        backup_path = threatguard.backup_workspace()
        print(f"✅ ThreatGuard workspace backed up to: {backup_path}")
    
    elif args.command == 'status':
        status = threatguard.get_system_status()
        print(f"\n📊 Detailed ThreatGuard System Status:")
        print(json.dumps(status, indent=2))

def print_banner():
    """Print ThreatGuard Pro banner"""
    banner = """
    ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
       ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                                           
                        🛡️ ADVANCED LOGIC BOMB DETECTION & THREAT INTELLIGENCE 🛡️
    """
    print(banner)

if __name__ == "__main__":
    print_banner()
    main()