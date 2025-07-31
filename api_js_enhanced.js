// Enhanced API client for ThreatGuard Pro
// Advanced Threat Detection & Intelligence API

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// Create axios instance with enhanced configuration
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 seconds for large file scans
  headers: {
    'Content-Type': 'application/json',
    'X-ThreatGuard-Client': 'ThreatGuard-Pro-UI',
    'X-Client-Version': '2.0.0'
  }
});

// Enhanced request interceptor for threat scanning
api.interceptors.request.use(
  (config) => {
    // Add scan timestamp for tracking
    if (config.url.includes('/scan')) {
      config.headers['X-Scan-Timestamp'] = new Date().toISOString();
    }
    
    // Add threat detection headers
    if (config.url.includes('/threat')) {
      config.headers['X-Threat-Detection'] = 'enhanced';
    }
    
    console.log(`🔍 ThreatGuard API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('❌ ThreatGuard API Request Error:', error);
    return Promise.reject(error);
  }
);

// Enhanced response interceptor with threat intelligence
api.interceptors.response.use(
  (response) => {
    // Log successful threat detection responses
    if (response.config.url.includes('/scan') || response.config.url.includes('/threat')) {
      const threatCount = response.data?.summary?.total_issues || 
                         response.data?.threats?.total || 
                         (Array.isArray(response.data) ? response.data.length : 0);
      console.log(`✅ ThreatGuard Response: ${threatCount} threats detected`);
    }
    
    return response;
  },
  (error) => {
    console.error('❌ ThreatGuard API Response Error:', error.response?.data || error.message);
    
    // Enhanced error handling for threat detection
    if (error.response?.status === 429) {
      console.warn('⚠️ Rate limit exceeded for threat scanning');
    } else if (error.response?.status >= 500) {
      console.error('🚨 ThreatGuard server error - threat detection may be affected');
    }
    
    return Promise.reject(error);
  }
);

// Enhanced ThreatGuard Pro API methods
const ThreatGuardAPI = {
  
  // ===== ENHANCED THREAT DETECTION =====
  
  /**
   * Get enhanced command center metrics with threat intelligence
   */
  getCommandCenterMetrics: () => {
    return api.get('/api/command-center/metrics');
  },
  
  /**
   * Start advanced logic bomb detection scan
   */
  startLogicBombScan: (projectPath, projectId) => {
    return api.post('/api/logic-bomb-scan', {
      project_path: projectPath,
      project_id: projectId,
      scan_type: 'comprehensive',
      threat_detection: 'enhanced'
    });
  },
  
  /**
   * Enhanced file scanning with advanced threat pattern detection
   */
  scanFiles: (fileContents, scanOptions = {}) => {
    const scanPayload = {
      scan_id: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      scan_type: scanOptions.scanType || 'comprehensive',
      project_id: scanOptions.projectId || `threat-scan-${Date.now()}`,
      project_name: scanOptions.projectName || 'ThreatGuard File Scan',
      timestamp: new Date().toISOString(),
      file_contents: fileContents,
      detection_level: 'enhanced',
      include_threat_intelligence: true,
      ait_tag: scanOptions.aitTag || 'AIT',
      spk_tag: scanOptions.spkTag || 'SPK-SECURITY',
      repo_name: scanOptions.repoName || 'threatguard-repo'
    };
    
    return api.post('/api/scan/files', scanPayload);
  },
  
  /**
   * Scan GitHub repository for logic bombs and security threats
   */
  scanGithubRepository: (githubUrl, scanOptions = {}) => {
    const scanPayload = {
      scan_id: `github_scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      scan_type: scanOptions.scanType || 'github',
      project_id: scanOptions.projectId || `github-scan-${Date.now()}`,
      project_name: scanOptions.projectName || 'GitHub Repository Scan',
      timestamp: new Date().toISOString(),
      github_url: githubUrl,
      detection_level: 'enhanced',
      include_threat_intelligence: true,
      ait_tag: scanOptions.aitTag || 'AIT',
      spk_tag: scanOptions.spkTag || 'SPK-SECURITY',
      repo_name: scanOptions.repoName || 'github-repo'
    };
    
    return api.post('/api/scan/github', scanPayload);
  },
  
  // ===== THREAT MANAGEMENT =====
  
  /**
   * Get all detected threats with enhanced analysis
   */
  getThreats: () => {
    return api.get('/api/threats');
  },
  
  /**
   * Get threat by ID with detailed analysis
   */
  getThreat: (threatId) => {
    return api.get(`/api/threats/${threatId}`);
  },
  
  /**
   * Update threat status (ACTIVE_THREAT, NEUTRALIZED, UNDER_REVIEW, FALSE_POSITIVE)
   */
  updateThreatStatus: (threatId, status, assignee = null) => {
    return api.put(`/api/threats/${threatId}/status`, { 
      status, 
      assignee,
      updated_by: 'ThreatGuard-UI',
      update_timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Neutralize a specific threat
   */
  neutralizeThreat: (threatId) => {
    return api.post(`/api/threats/${threatId}/neutralize`, {
      action: 'neutralize',
      neutralized_by: 'ThreatGuard-UI',
      neutralization_timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Delete a threat
   */
  deleteThreat: (threatId) => {
    return api.delete(`/api/threats/${threatId}`);
  },
  
  /**
   * Delete all threats (admin operation)
   */
  deleteAllThreats: () => {
    return api.delete('/api/threats');
  },
  
  // ===== THREAT SHIELDS (Enhanced Quality Gates) =====
  
  /**
   * Get all threat protection shields
   */
  getThreatShields: () => {
    return api.get('/api/threat-shields');
  },
  
  /**
   * Create new threat shield
   */
  createThreatShield: (shieldData) => {
    return api.post('/api/threat-shields', {
      ...shieldData,
      created_by: 'ThreatGuard-UI',
      creation_timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Update threat shield
   */
  updateThreatShield: (shieldId, updates) => {
    return api.put(`/api/threat-shields/${shieldId}`, {
      ...updates,
      updated_by: 'ThreatGuard-UI',
      update_timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Delete threat shield
   */
  deleteThreatShield: (shieldId) => {
    return api.delete(`/api/threat-shields/${shieldId}`);
  },
  
  // ===== THREAT INTELLIGENCE =====
  
  /**
   * Get comprehensive threat intelligence data
   */
  getThreatIntelligence: () => {
    return api.get('/api/threat-intelligence');
  },
  
  /**
   * Get threat intelligence for specific project
   */
  getProjectThreatIntelligence: (projectId) => {
    return api.get(`/api/threat-intelligence/${projectId}`);
  },
  
  // ===== DETECTION RULES =====
  
  /**
   * Get all detection rules with threat categories
   */
  getRules: () => {
    return api.get('/api/rules');
  },
  
  /**
   * Create new detection rule
   */
  createRule: (ruleData) => {
    return api.post('/api/rules', {
      ...ruleData,
      created_by: 'ThreatGuard-UI',
      creation_timestamp: new Date().toISOString(),
      custom: true,
      enabled: true
    });
  },
  
  /**
   * Update detection rule
   */
  updateRule: (ruleId, updates) => {
    return api.put(`/api/rules/${ruleId}`, {
      ...updates,
      updated_by: 'ThreatGuard-UI',
      update_timestamp: new Date().toISOString()
    });
  },
  
  /**
   * Delete detection rule
   */
  deleteRule: (ruleId) => {
    return api.delete(`/api/rules/${ruleId}`);
  },
  
  /**
   * Test rule against sample code
   */
  testRule: (ruleId, testCode) => {
    return api.post(`/api/rules/${ruleId}/test`, {
      test_code: testCode,
      test_timestamp: new Date().toISOString()
    });
  },
  
  // ===== SYSTEM HEALTH & MONITORING =====
  
  /**
   * Get enhanced system health status
   */
  getSystemHealth: () => {
    return api.get('/api/health');
  },
  
  /**
   * Get system performance metrics
   */
  getSystemMetrics: () => {
    return api.get('/api/system/metrics');
  },
  
  // ===== DATA MANAGEMENT =====
  
  /**
   * Export all ThreatGuard data
   */
  exportData: (format = 'json') => {
    return api.get('/api/export', {
      params: { format },
      responseType: 'blob'
    });
  },
  
  /**
   * Import ThreatGuard data
   */
  importData: (fileData) => {
    return api.post('/api/import', fileData);
  },
  
  /**
   * Clear scan history
   */
  clearScanHistory: () => {
    return api.delete('/api/scan-history');
  },
  
  /**
   * Backup system data
   */
  backupData: () => {
    return api.post('/api/backup', {
      backup_timestamp: new Date().toISOString(),
      backup_type: 'full'
    });
  },
  
  // ===== BACKWARD COMPATIBILITY =====
  
  /**
   * Legacy dashboard metrics (for backward compatibility)
   */
  getDashboardMetrics: () => {
    return api.get('/api/dashboard/metrics');
  },
  
  /**
   * Legacy scan endpoint (for backward compatibility)
   */
  startScan: (projectPath, projectId) => {
    return api.post('/api/scan', {
      project_path: projectPath,
      project_id: projectId
    });
  },
  
  /**
   * Legacy issues endpoint (for backward compatibility)
   */
  getIssues: () => {
    return api.get('/api/issues');
  },
  
  /**
   * Legacy issue status update (for backward compatibility)
   */
  updateIssueStatus: (issueId, status, assignee = null) => {
    return api.put(`/api/issues/${issueId}/status`, { status, assignee });
  },
  
  /**
   * Legacy quality gates endpoint (for backward compatibility)
   */
  getQualityGates: () => {
    return api.get('/api/quality-gates');
  },
  
  /**
   * Legacy scan history (for backward compatibility)
   */
  getScanHistory: () => {
    return api.get('/api/scan-history');
  },
  
  // ===== UTILITY METHODS =====
  
  /**
   * Check if ThreatGuard API is accessible
   */
  ping: () => {
    return api.get('/api/health');
  },
  
  /**
   * Get API version and capabilities
   */
  getVersion: () => {
    return api.get('/api/version');
  },
  
  /**
   * Validate file for scanning
   */
  validateFile: (fileName, fileSize, fileType) => {
    const MAX_FILE_SIZE = 16 * 1024 * 1024; // 16MB
    const SUPPORTED_EXTENSIONS = [
      '.py', '.js', '.ts', '.java', '.cs', '.php', '.html', '.json',
      '.xml', '.sql', '.rb', '.go', '.c', '.cpp', '.rs', '.jsx', '.tsx'
    ];
    
    if (fileSize > MAX_FILE_SIZE) {
      return { valid: false, error: 'File too large (max 16MB)' };
    }
    
    const extension = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.includes(extension)) {
      return { valid: false, error: `Unsupported file type: ${extension}` };
    }
    
    return { valid: true };
  },
  
  /**
   * Generate unique scan ID
   */
  generateScanId: () => {
    return `threatguard_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  },
  
  /**
   * Format threat severity for display
   */
  formatThreatSeverity: (severity) => {
    const severityMap = {
      'CRITICAL_BOMB': 'Critical Bomb',
      'HIGH_RISK': 'High Risk',
      'MEDIUM_RISK': 'Medium Risk',
      'LOW_RISK': 'Low Risk',
      'CRITICAL': 'Critical',
      'MAJOR': 'Major',
      'MINOR': 'Minor',
      'INFO': 'Info'
    };
    return severityMap[severity] || severity;
  },
  
  /**
   * Format threat type for display
   */
  formatThreatType: (type) => {
    const typeMap = {
      'SCHEDULED_THREAT': 'Time Bomb',
      'TARGETED_ATTACK': 'User Bomb',
      'EXECUTION_TRIGGER': 'Counter Bomb',
      'DESTRUCTIVE_PAYLOAD': 'Destructive Code',
      'FINANCIAL_FRAUD': 'Financial Fraud',
      'SYSTEM_SPECIFIC_THREAT': 'System Bomb',
      'CONNECTION_BASED_THREAT': 'Network Bomb',
      'VULNERABILITY': 'Security Vulnerability',
      'BUG': 'Code Bug',
      'CODE_SMELL': 'Code Smell'
    };
    return typeMap[type] || type.replace('_', ' ');
  },
  
  /**
   * Get threat priority level
   */
  getThreatPriority: (severity, type) => {
    if (severity === 'CRITICAL_BOMB' || type === 'DESTRUCTIVE_PAYLOAD') {
      return 'IMMEDIATE';
    } else if (severity === 'HIGH_RISK' || severity === 'CRITICAL') {
      return 'HIGH';
    } else if (severity === 'MEDIUM_RISK' || severity === 'MAJOR') {
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  },
  
  /**
   * Calculate overall threat level
   */
  calculateThreatLevel: (threats) => {
    if (!threats || threats.length === 0) return 'MINIMAL';
    
    const criticalCount = threats.filter(t => 
      t.severity === 'CRITICAL_BOMB' || t.severity === 'CRITICAL'
    ).length;
    
    const highCount = threats.filter(t => 
      t.severity === 'HIGH_RISK' || t.severity === 'MAJOR'
    ).length;
    
    if (criticalCount > 0) return 'CRITICAL';
    if (highCount > 2) return 'HIGH';
    if (highCount > 0) return 'ELEVATED';
    return 'MODERATE';
  }
};

// Enhanced error handling wrapper
const withErrorHandling = (apiMethod) => {
  return async (...args) => {
    try {
      const response = await apiMethod(...args);
      return response;
    } catch (error) {
      console.error('ThreatGuard API Error:', error);
      
      // Enhanced error information
      const enhancedError = {
        message: error.response?.data?.error || error.message,
        status: error.response?.status,
        timestamp: new Date().toISOString(),
        endpoint: error.config?.url,
        method: error.config?.method?.toUpperCase()
      };
      
      throw enhancedError;
    }
  };
};

// Wrap all API methods with error handling
Object.keys(ThreatGuardAPI).forEach(key => {
  if (typeof ThreatGuardAPI[key] === 'function') {
    ThreatGuardAPI[key] = withErrorHandling(ThreatGuardAPI[key]);
  }
});

export default ThreatGuardAPI;