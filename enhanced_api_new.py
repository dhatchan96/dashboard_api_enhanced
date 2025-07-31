# Modified dashboard_api_enhanced.py - Add these sections

@app.route('/api/security-tech-debt')
def get_security_tech_debt():
    """Get security technical debt issues"""
    try:
        tech_debt_issues = []
        for issue in detector.issue_manager.issues.values():
            if issue.type == 'SECURITY_TECH_DEBT':
                tech_debt_issues.append({
                    'id': issue.id,
                    'rule_id': issue.rule_id,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'message': issue.message,
                    'severity': issue.severity,
                    'debt_category': getattr(issue, 'debt_category', 'UNKNOWN'),
                    'code_snippet': issue.code_snippet,
                    'suggested_fix': issue.suggested_fix,
                    'business_impact': getattr(issue, 'business_impact', 'Medium'),
                    'remediation_effort': getattr(issue, 'effort', 30),
                    'creation_date': issue.creation_date,
                    'ait_tag': getattr(issue, 'ait_tag', 'AIT'),
                    'spk_tag': getattr(issue, 'spk_tag', 'SPK-DEFAULT'),
                    'repo_name': getattr(issue, 'repo_name', 'unknown-repo'),
                    'scan_id': getattr(issue, 'scan_id', 'unknown-scan')
                })
        
        # Group by categories
        categories = {}
        for issue in tech_debt_issues:
            category = issue['debt_category']
            if category not in categories:
                categories[category] = []
            categories[category].append(issue)
        
        return jsonify({
            'total_tech_debt': len(tech_debt_issues),
            'by_category': categories,
            'summary': {
                'hardcoded_credentials': len([i for i in tech_debt_issues if 'CREDENTIAL' in i['debt_category']]),
                'hardcoded_urls': len([i for i in tech_debt_issues if 'URL' in i['debt_category']]),
                'input_validation': len([i for i in tech_debt_issues if 'VALIDATION' in i['debt_category']]),
                'vulnerable_libraries': len([i for i in tech_debt_issues if 'LIBRARY' in i['debt_category']]),
                'encryption_issues': len([i for i in tech_debt_issues if 'ENCRYPTION' in i['debt_category']]),
                'access_control': len([i for i in tech_debt_issues if 'ACCESS' in i['debt_category']]),
                'total_effort_hours': sum(i['remediation_effort'] for i in tech_debt_issues) / 60
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Enhanced scan function for hierarchical tagging
def perform_enhanced_file_scan(scan_id: str, project_id: str, project_name: str, 
                              file_paths: list, scan_type: str = 'quick', 
                              ait_tag: str = 'AIT', spk_tag: str = 'SPK-DEFAULT',
                              repo_name: str = 'unknown-repo') -> dict:
    """Enhanced file scan with hierarchical tagging"""
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
            file_issues = scan_file_content_with_tagging(
                file_name, content, applicable_rules, file_id, 
                scan_id, ait_tag, spk_tag, repo_name
            )

            # Advanced threat pattern detection
            threat_matches = advanced_detector.analyze_file(file_path)
            threat_issues = []
            for pattern in threat_matches:
                issue = detector.issue_manager.create_issue(
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
                # Add hierarchical tags
                issue.ait_tag = ait_tag
                issue.spk_tag = spk_tag
                issue.repo_name = repo_name
                issue.scan_id = scan_id
                threat_issues.append(issue)

            all_issues = file_issues + threat_issues
            total_issues.extend(all_issues)
            total_threat_patterns.extend(threat_matches)

        except Exception as e:
            print(f"Error scanning file {file_info['name']}: {e}")

    # Rest of the function remains the same...
    return scan_result

def scan_file_content_with_tagging(file_name: str, content: str, rules: list, 
                                  file_id: str, scan_id: str, ait_tag: str, 
                                  spk_tag: str, repo_name: str) -> list:
    """Enhanced file scanning with hierarchical tagging"""
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
                    # Add hierarchical tags
                    issue.ait_tag = ait_tag
                    issue.spk_tag = spk_tag
                    issue.repo_name = repo_name
                    issue.scan_id = scan_id
                    issue.effort = rule.remediation_effort
                    
                    # Add tech debt categorization
                    if rule.threat_category == 'SECURITY_TECH_DEBT':
                        issue.debt_category = getattr(rule, 'debt_category', 'UNKNOWN')
                        issue.business_impact = getattr(rule, 'business_impact', 'Medium')
                    
                    issues.append(issue)

        except re.error as e:
            print(f"⚠️ Invalid regex in rule {rule.id}: {e}")

    return issues