import React, { useEffect, useState } from 'react';
import API from '../api';
import '../style.css';

const HealthCheck = () => {
  const [health, setHealth] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  useEffect(() => {
    fetchHealth();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await API.get('/api/health');
      setHealth(res.data);
      setLastRefresh(new Date());
    } catch (error) {
      console.error('Error fetching health check:', error);
      setHealth({
        status: 'unhealthy',
        error: 'Unable to connect to ThreatGuard services'
      });
    }
  };

  if (!health) return (
    <div className="text-center mt-5">
      <div className="spinner-border text-danger" role="status">
        <span className="visually-hidden">Checking system health...</span>
      </div>
      <p className="mt-3">Checking ThreatGuard system health...</p>
    </div>
  );

  const getStatusColor = (status) => {
    return status === 'healthy' ? '#198754' : '#dc3545';
  };

  const getStatusIcon = (status) => {
    return status === 'healthy' ? '🟢' : '🔴';
  };

  return (
    <div className="container mt-4" style={{ background: '#fff', color: '#222' }}>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 style={{ color: '#dc3545' }}>🏥 ThreatGuard System Health</h2>
        <div>
          <button className="btn btn-outline-primary btn-sm me-2" onClick={fetchHealth}>
            🔄 Refresh
          </button>
          <small style={{ color: '#888' }}>
            Last updated: {lastRefresh.toLocaleTimeString()}
          </small>
        </div>
      </div>

      {/* Main Status Card */}
      <div className="row g-4 mb-4">
        <div className="col-12">
          <div 
            className={`alert ${health.status === 'healthy' ? 'alert-success' : 'alert-danger'} d-flex align-items-center`}
            style={{ border: `2px solid ${getStatusColor(health.status)}` }}
          >
            <div style={{ fontSize: '2rem', marginRight: '1rem' }}>
              {getStatusIcon(health.status)}
            </div>
            <div>
              <h4 className="mb-1">
                System Status: {health.status?.toUpperCase()}
              </h4>
              <p className="mb-0">
                {health.status === 'healthy' 
                  ? 'All ThreatGuard systems are operational and ready to detect threats.'
                  : health.error || 'Some ThreatGuard services may be experiencing issues.'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Core Metrics */}
      <div className="row g-4 mb-4">
        <div className="col-md-3">
          <div className="card text-center" style={{ border: '2px solid #198754' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', color: '#198754', marginBottom: '0.5rem' }}>🛡️</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: getStatusColor(health.status), fontWeight: 'bold' }}>
                {health.status?.toUpperCase()}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>System Status</div>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card text-center" style={{ border: '2px solid #0d6efd' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', color: '#0d6efd', marginBottom: '0.5rem' }}>🔧</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: '#0d6efd', fontWeight: 'bold' }}>
                {health.version || 'Unknown'}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Version</div>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card text-center" style={{ border: '2px solid #fd7e14' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', color: '#fd7e14', marginBottom: '0.5rem' }}>⏰</div>
              <div className="metric-value" style={{ fontSize: '1.2rem', color: '#fd7e14', fontWeight: 'bold' }}>
                {new Date(health.timestamp).toLocaleString()}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Last Check</div>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card text-center" style={{ border: '2px solid #6f42c1' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', color: '#6f42c1', marginBottom: '0.5rem' }}>⚡</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: '#6f42c1', fontWeight: 'bold' }}>
                {health.scanner_status?.toUpperCase() || 'UNKNOWN'}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Scanner Engine</div>
            </div>
          </div>
        </div>
      </div>

      {/* Component Status */}
      <div className="row g-4 mb-4">
        <div className="col-md-4">
          <div className="card text-center" style={{ border: '1px solid #e5e7eb' }}>
            <div className="card-body">
              <div style={{ fontSize: '1.5rem', color: '#dc3545', marginBottom: '0.5rem' }}>📋</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: '#dc3545', fontWeight: 'bold' }}>
                {health.rules_count || 0}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Detection Rules</div>
            </div>
          </div>
        </div>

        <div className="col-md-4">
          <div className="card text-center" style={{ border: '1px solid #e5e7eb' }}>
            <div className="card-body">
              <div style={{ fontSize: '1.5rem', color: '#198754', marginBottom: '0.5rem' }}>🛡️</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: '#198754', fontWeight: 'bold' }}>
                {health.quality_gates_count || 0}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Threat Shields</div>
            </div>
          </div>
        </div>

        <div className="col-md-4">
          <div className="card text-center" style={{ border: '1px solid #e5e7eb' }}>
            <div className="card-body">
              <div style={{ fontSize: '1.5rem', color: '#fd7e14', marginBottom: '0.5rem' }}>🚨</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: '#fd7e14', fontWeight: 'bold' }}>
                {health.total_issues || 0}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Threats Detected</div>
            </div>
          </div>
        </div>
      </div>

      {/* Advanced Metrics */}
      <div className="row g-4 mb-4">
        <div className="col-md-6">
          <div className="card text-center" style={{ border: '1px solid #e5e7eb' }}>
            <div className="card-body">
              <div style={{ fontSize: '1.5rem', color: '#6f42c1', marginBottom: '0.5rem' }}>📊</div>
              <div className="metric-value" style={{ fontSize: '2rem', color: '#6f42c1', fontWeight: 'bold' }}>
                {health.scan_history_count || 0}
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Scan Records</div>
            </div>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card text-center" style={{ border: '1px solid #e5e7eb' }}>
            <div className="card-body">
              <div style={{ fontSize: '1.5rem', color: '#0d6efd', marginBottom: '0.5rem' }}>🌐</div>
              <div className="metric-value" style={{ fontSize: '1.2rem', color: '#0d6efd', fontWeight: 'bold' }}>
                {health.supported_languages?.length || 0} Languages
              </div>
              <div className="metric-label" style={{ color: '#888' }}>Language Support</div>
            </div>
          </div>
        </div>
      </div>

      {/* System Features */}
      <div className="section" style={{ background: '#f8f9fa', border: '2px solid #e5e7eb', borderRadius: '8px', padding: '1.5rem' }}>
        <h5 style={{ color: '#dc3545', marginBottom: '1rem' }}>🔧 System Features</h5>
        <div className="row">
          <div className="col-md-6">
            <ul style={{ listStyle: 'none', padding: 0 }}>
              <li style={{ padding: '0.5rem 0', borderBottom: '1px solid #e5e7eb' }}>
                <span style={{ color: health.malware_detection === 'enabled' ? '#198754' : '#dc3545' }}>
                  {health.malware_detection === 'enabled' ? '✅' : '❌'}
                </span>
                <strong style={{ marginLeft: '0.5rem' }}>Malware Detection:</strong> 
                <span style={{ marginLeft: '0.5rem', color: health.malware_detection === 'enabled' ? '#198754' : '#dc3545' }}>
                  {health.malware_detection || 'Unknown'}
                </span>
              </li>
              <li style={{ padding: '0.5rem 0', borderBottom: '1px solid #e5e7eb' }}>
                <span style={{ color: '#198754' }}>✅</span>
                <strong style={{ marginLeft: '0.5rem' }}>Logic Bomb Detection:</strong> 
                <span style={{ marginLeft: '0.5rem', color: '#198754' }}>Active</span>
              </li>
              <li style={{ padding: '0.5rem 0', borderBottom: '1px solid #e5e7eb' }}>
                <span style={{ color: '#198754' }}>✅</span>
                <strong style={{ marginLeft: '0.5rem' }}>Real-time Scanning:</strong> 
                <span style={{ marginLeft: '0.5rem', color: '#198754' }}>Enabled</span>
              </li>
            </ul>
          </div>
          <div className="col-md-6">
            <ul style={{ listStyle: 'none', padding: 0 }}>
              <li style={{ padding: '0.5rem 0', borderBottom: '1px solid #e5e7eb' }}>
                <span style={{ color: '#198754' }}>✅</span>
                <strong style={{ marginLeft: '0.5rem' }}>Threat Intelligence:</strong> 
                <span style={{ marginLeft: '0.5rem', color: '#198754' }}>Active</span>
              </li>
              <li style={{ padding: '0.5rem 0', borderBottom: '1px solid #e5e7eb' }}>
                <span style={{ color: '#198754' }}>✅</span>
                <strong style={{ marginLeft: '0.5rem' }}>Auto-neutralization:</strong> 
                <span style={{ marginLeft: '0.5rem', color: '#198754' }}>Available</span>
              </li>
              <li style={{ padding: '0.5rem 0', borderBottom: '1px solid #e5e7eb' }}>
                <span style={{ color: '#198754' }}>✅</span>
                <strong style={{ marginLeft: '0.5rem' }}>API Endpoints:</strong> 
                <span style={{ marginLeft: '0.5rem', color: '#198754' }}>Operational</span>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* System Information */}
      <div className="mt-4 section" style={{ background: '#f8f9fa', border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1.5rem' }}>
        <h5 style={{ color: '#dc3545' }}>📁 System Configuration</h5>
        <div className="row g-3">
          <div className="col-md-6">
            <strong>Data Directory:</strong>
            <p className="text-monospace" style={{ fontSize: '0.9rem', color: '#666', marginTop: '0.25rem' }}>
              {health.data_directory || 'Not specified'}
            </p>
          </div>
          <div className="col-md-6">
            <strong>Supported Languages:</strong>
            <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '0.25rem' }}>
              {health.supported_languages?.join(', ') || 'Python, JavaScript, Java, C#, PHP, etc.'}
            </p>
          </div>
          <div className="col-md-6">
            <strong>Scanner Version:</strong>
            <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '0.25rem' }}>
              ThreatGuard Pro {health.version || '1.0.0'}
            </p>
          </div>
          <div className="col-md-6">
            <strong>Uptime:</strong>
            <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '0.25rem' }}>
              {health.timestamp ? `Since ${new Date(health.timestamp).toLocaleDateString()}` : 'Unknown'}
            </p>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-4 pt-3" style={{ borderTop: '1px solid #e5e7eb', color: '#888', fontSize: '0.9rem', textAlign: 'center' }}>
        <p>
          ThreatGuard Pro - Advanced Logic Bomb & Malware Detection System<br/>
          Monitoring system health every 30 seconds for optimal threat protection
        </p>
      </div>
    </div>
  );
};

export default HealthCheck;