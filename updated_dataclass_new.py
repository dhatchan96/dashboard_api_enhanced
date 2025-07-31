# Enhanced SecurityIssue and SecurityRule dataclasses for threatguard_main_enhanced.py

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

# Enhanced ThreatIssueManager with better categorization
class ThreatIssueManager:
    """Enhanced threat issue management with comprehensive categorization"""
    
    def create_issue(self, rule_id: str, file_path: str, line_number: int,
                    column: int, message: str, severity: str, issue_type: str,
                    code_snippet: str = "", suggested_fix: str = "") -> SecurityIssue:
        """Create a new enhanced security issue with comprehensive analysis"""
        issue_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        # Enhanced analysis
        trigger_analysis = self._analyze_trigger(code_snippet, issue_type)
        payload_analysis = self._analyze_payload(code_snippet, severity)
        threat_level = self._calculate_threat_level(severity, issue_type)
        
        # Calculate priority score
        priority_score = self._calculate_priority_score(severity, issue_type, code_snippet)
        
        # Determine security domain
        security_domain = self._determine_security_domain(file_path, code_snippet)
        
        # Extract component name from file path
        component_name = self._extract_component_name(file_path)
        
        issue = SecurityIssue(
            id=issue_id,
            rule_id=rule_id,
            file_path=file_path,
            file_name=os.path.basename(file_path),
            line_number=line_number,
            column=column,
            message=message,
            severity=severity,
            type=issue_type,
            status="ACTIVE_THREAT",
            creation_date=current_time,
            update_date=current_time,
            code_snippet=code_snippet,
            suggested_fix=suggested_fix,
            threat_level=threat_level,
            trigger_analysis=trigger_analysis,
            payload_analysis=payload_analysis,
            priority_score=priority_score,
            security_domain=security_domain,
            component_name=component_name
        )
        
        self.issues[issue_id] = issue
        return issue
    
    def _calculate_priority_score(self, severity: str, issue_type: str, code_snippet: str) -> int:
        """Calculate priority score (1-100) based on multiple factors"""
        base_scores = {
            "CRITICAL_BOMB": 90,
            "CRITICAL": 80,
            "HIGH_RISK": 70,
            "MAJOR": 60,
            "MEDIUM_RISK": 40,
            "MINOR": 20,
            "LOW_RISK": 10
        }
        
        score = base_scores.get(severity, 30)
        
        # Increase score for certain keywords
        if any(keyword in code_snippet.lower() for keyword in ['password', 'secret', 'key', 'token']):
            score += 15
        if any(keyword in code_snippet.lower() for keyword in ['delete', 'remove', 'destroy']):
            score += 20
        if 'production' in code_snippet.lower():
            score += 10
            
        return min(100, score)
    
    def _determine_security_domain(self, file_path: str, code_snippet: str) -> str:
        """Determine the security domain based on file path and code"""
        if any(keyword in file_path.lower() for keyword in ['config', 'settings', 'env']):
            return "INFRASTRUCTURE"
        if any(keyword in file_path.lower() for keyword in ['database', 'db', 'sql']):
            return "DATA"
        if any(keyword in file_path.lower() for keyword in ['network', 'socket', 'http']):
            return "NETWORK"
        return "APPLICATION"
    
    def _extract_component_name(self, file_path: str) -> str:
        """Extract component name from file path"""
        parts = file_path.split('/')
        if len(parts) > 1:
            return parts[-2]  # Return parent directory name
        return "unknown"
    
    def get_tech_debt_summary(self) -> Dict[str, Any]:
        """Get comprehensive tech debt summary"""
        tech_debt_issues = [i for i in self.issues.values() if i.type == "SECURITY_TECH_DEBT"]
        
        return {
            "total_issues": len(tech_debt_issues),
            "by_category": self._group_by_field(tech_debt_issues, "debt_category"),
            "by_severity": self._group_by_field(tech_debt_issues, "severity"),
            "by_business_impact": self._group_by_field(tech_debt_issues, "business_impact"),
            "by_security_domain": self._group_by_field(tech_debt_issues, "security_domain"),
            "by_ait_tag": self._group_by_field(tech_debt_issues, "ait_tag"),
            "by_spk_tag": self._group_by_field(tech_debt_issues, "spk_tag"),
            "by_repo": self._group_by_field(tech_debt_issues, "repo_name"),
            "total_effort_hours": sum(i.effort for i in tech_debt_issues) // 60,
            "high_priority_count": len([i for i in tech_debt_issues if i.priority_score >= 70])
        }
    
    def _group_by_field(self, issues: List[SecurityIssue], field: str) -> Dict[str, int]:
        """Group issues by a specific field"""
        groups = {}
        for issue in issues:
            value = getattr(issue, field, "UNKNOWN")
            groups[value] = groups.get(value, 0) + 1
        return groups