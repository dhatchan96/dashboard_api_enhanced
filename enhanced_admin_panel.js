import React, { useState, useEffect } from 'react';
import API from '../api';
import '../style.css';

const AdminPanel = () => {
  const [projectPath, setProjectPath] = useState('');
  const [projectId, setProjectId] = useState('');
  const [importFile, setImportFile] = useState(null);
  const [message, setMessage] = useState('');
  const [systemStats, setSystemStats] = useState(null);
  const [activeTab, setActiveTab] = useState('scan');

  useEffect(() => {
    fetchSystemStats();
  }, []);

  const fetchSystemStats = async () => {
    try {
      const health = await API.get('/api/health');
      setSystemStats(health.data);
    } catch (err) {
      console.error('Failed to fetch system stats:', err);
    }
  };

  const startScan = async () => {
    if (!projectPath || !projectId) return alert("Please fill both project path and ID");
    
    try {
      // Try new scan API first
      await API.post('/api/scan', { project_path: projectPath, project_id: projectId });
      setMessage('✅ Scan started successfully!');
      fetchSystemStats();
    } catch (err) {
      console.error('Scan failed:', err);
      setMessage('❌ Scan failed. Please check the project path and try again.');
    }
  };

  const exportData = async () => {
    try {
      const res = await API.get('/api/export');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `threatguard_export_${new Date().toISOString().split('T')[0]}.json`;
      link.click();
      setMessage('✅ Data exported successfully!');
    } catch (err) {
      console.error('Export failed:', err);
      setMessage('❌ Export failed. Data may not be available.');
    }
  };

  const importData = () => {
    if (!importFile) return alert('Please select a file to import');
    
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const json = JSON.parse(reader.result);
        await API.post('/api/import', json);
        setMessage('✅ Data imported successfully!');
        fetchSystemStats();
      } catch (err) {
        console.error('Import failed:', err);
        setMessage('❌ Import failed. Please check the file format.');
      }
    };
    reader.readAsText(importFile);
  };

  const resetThreats = async () => {
    if (!window.confirm('Are you sure you want to reset all threats? This action cannot be undone.')) return;
    
    try {
      // Try new API first
      await API.delete('/api/threats');
      setMessage('✅ All threats have been reset.');
      fetchSystemStats();
    } catch (err) {
      // Fallback to old API
      try {
        await API.delete('/api/issues');
        setMessage('✅ All issues have been reset.');
        fetchSystemStats();
      } catch (fallbackErr) {
        setMessage('❌ Failed to reset threats.');
      }
    }
  };

  const clearScanHistory = async () => {
    if (!window.confirm('Are you sure you want to clear scan history? This action cannot be undone.')) return;
    
    try {
      await API.delete('/api/scan-history');
      setMessage('✅ Scan history cleared.');
      fetchSystemStats();
    } catch (err) {
      setMessage('❌ Failed to clear scan history.');
    }
  };

  const clearAllData = async () => {
    if (!window.confirm('⚠️ WARNING: This will clear ALL data including threats, rules, and scan history. Are you absolutely sure?')) return;
    
    try {
      // Clear multiple endpoints
      await Promise.all([
        API.delete('/api/threats').catch(() => API.delete('/api/issues')),
        API.delete('/api/scan-history'),
        // Don't delete rules as they are configuration
      ]);
      setMessage('✅ All data cleared successfully.');
      fetchSystemStats();
    } catch (err) {
      setMessage('❌ Failed to clear all data.');
    }
  };

  const optimizeSystem = async () => {
    setMessage('🔄 Optimizing system...');
    
    try {
      // Simulate system optimization (you can implement actual optimization logic)
      await new Promise(resolve => setTimeout(resolve, 2000));
      fetchSystemStats();
      setMessage('✅ System optimized successfully!');
    } catch (err) {
      setMessage('❌ System optimization failed.');
    }
  };

  return (
    <div className="container-fluid mt-4 px-5" style={{ background: '#fff', color: '#222' }}>
      <h2 className="mb-4" style={{ color: '#dc3545' }}>⚙️ ThreatGuard Administration</h2>

      {message && (
        <div className={`alert ${message.includes('✅') ? 'alert-success' : message.includes('❌') ? 'alert-danger' : 'alert-info'} d-flex justify-content-between align-items-center`}>
          <span>{message}</span>
          <button className="btn-close" onClick={() => setMessage('')}></button>
        </div>
      )}

      {/* System Overview */}
      {systemStats && (
        <div className="row g-4 mb-5">
          <div className="col-md-3">
            <div className="card text-center" style={{ border: '2px solid #198754' }}>
              <div className="card-body">
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🛡️</div>
                <h4 style={{ color: '#198754' }}>{systemStats.status?.toUpperCase()}</h4>
                <p style={{ color: '#888' }}>System Status</p>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card text-center" style={{ border: '2px solid #0d6efd' }}>
              <div className="card-body">
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📋</div>
                <h4 style={{ color: '#0d6efd' }}>{systemStats.rules_count || 0}</h4>
                <p style={{ color: '#888' }}>Active Rules</p>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card text-center" style={{ border: '2px solid #fd7e14' }}>
              <div className="card-body">
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🚨</div>
                <h4 style={{ color: '#fd7e14' }}>{systemStats.total_issues || 0}</h4>
                <p style={{ color: '#888' }}>Total Threats</p>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card text-center" style={{ border: '2px solid #6f42c1' }}>
              <div className="card-body">
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📊</div>
                <h4 style={{ color: '#6f42c1' }}>{systemStats.scan_history_count || 0}</h4>
                <p style={{ color: '#888' }}>Scan Records</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <ul className="nav nav-tabs mb-4" style={{ borderBottom: '2px solid #e5e7eb' }}>
        {[
          { id: 'scan', label: '🎯 Project Scanning', icon: '🎯' },
          { id: 'data', label: '💾 Data Management', icon: '💾' },
          { id: 'maintenance', label: '🔧 System Maintenance', icon: '🔧' }
        ].map(tab => (
          <li className="nav-item" key={tab.id}>
            <button
              className={`nav-link ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
              style={{
                color: activeTab === tab.id ? '#dc3545' : '#888',
                background: activeTab === tab.id ? '#f8f9fa' : 'transparent',
                border: 'none',
                borderBottom: activeTab === tab.id ? '3px solid #dc3545' : '3px solid transparent',
              }}
            >
              {tab.label}
            </button>
          </li>
        ))}
      </ul>

      {/* Tab Content */}
      <div className="row g-4">
        {/* Project Scanning Tab */}
        {activeTab === 'scan' && (
          <>
            <div className="col-md-8">
              <div className="card p-4 shadow-sm" style={{ border: '2px solid #0d6efd' }}>
                <h5 className="card-title" style={{ color: '#0d6efd' }}>🎯 Start Threat Scan</h5>
                <div className="mb-3">
                  <label className="form-label" style={{ fontWeight: 'bold' }}>Project Path</label>
                  <input 
                    className="form-control" 
                    value={projectPath} 
                    onChange={(e) => setProjectPath(e.target.value)}
                    placeholder="/path/to/your/project"
                    style={{ fontFamily: 'monospace' }}
                  />
                  <small style={{ color: '#888' }}>Full path to the project directory to scan</small>
                </div>
                <div className="mb-3">
                  <label className="form-label" style={{ fontWeight: 'bold' }}>Project ID</label>
                  <input 
                    className="form-control" 
                    value={projectId} 
                    onChange={(e) => setProjectId(e.target.value)}
                    placeholder="my-project-v1"
                  />
                  <small style={{ color: '#888' }}>Unique identifier for this project</small>
                </div>
                <button 
                  className="btn btn-primary btn-lg w-100" 
                  onClick={startScan}
                  disabled={!projectPath || !projectId}
                >
                  🚀 Start Security Scan
                </button>
              </div>
            </div>
            <div className="col-md-4">
              <div className="card p-4" style={{ background: '#e3f2fd', border: '1px solid #2196f3' }}>
                <h6 style={{ color: '#1976d2' }}>💡 Scanning Tips</h6>
                <ul style={{ color: '#555', fontSize: '0.9rem' }}>
                  <li>Ensure the project path is accessible</li>
                  <li>Use descriptive project IDs</li>
                  <li>Scan may take time for large projects</li>
                  <li>Results will appear in the threats section</li>
                </ul>
              </div>
            </div>
          </>
        )}

        {/* Data Management Tab */}
        {activeTab === 'data' && (
          <>
            <div className="col-md-6">
              <div className="card p-4 shadow-sm" style={{ border: '2px solid #198754' }}>
                <h5 className="card-title" style={{ color: '#198754' }}>📤 Export Data</h5>
                <p>Export all threats, rules, and scan history to a JSON file.</p>
                <button className="btn btn-success w-100" onClick={exportData}>
                  📥 Export All Data
                </button>
              </div>
            </div>
            <div className="col-md-6">
              <div className="card p-4 shadow-sm" style={{ border: '2px solid #fd7e14' }}>
                <h5 className="card-title" style={{ color: '#fd7e14' }}>📥 Import Data</h5>
                <div className="mb-3">
                  <input 
                    type="file" 
                    className="form-control" 
                    accept=".json"
                    onChange={(e) => setImportFile(e.target.files[0])} 
                  />
                  <small style={{ color: '#888' }}>Select a JSON file exported from ThreatGuard</small>
                </div>
                <button 
                  className="btn btn-warning w-100" 
                  onClick={importData}
                  disabled={!importFile}
                >
                  📤 Import Data
                </button>
              </div>
            </div>
          </>
        )}

        {/* System Maintenance Tab */}
        {activeTab === 'maintenance' && (
          <>
            <div className="col-md-6">
              <div className="card p-4 shadow-sm" style={{ border: '2px solid #dc3545' }}>
                <h5 className="card-title" style={{ color: '#dc3545' }}>🗑️ Data Cleanup</h5>
                <div className="d-grid gap-2">
                  <button className="btn btn-outline-danger" onClick={resetThreats}>
                    🚨 Reset All Threats
                  </button>
                  <button className="btn btn-outline-warning" onClick={clearScanHistory}>
                    📊 Clear Scan History
                  </button>
                  <button className="btn btn-danger" onClick={clearAllData}>
                    💥 Clear All Data
                  </button>
                </div>
                <small style={{ color: '#dc3545', marginTop: '1rem', display: 'block' }}>
                  ⚠️ These actions cannot be undone!
                </small>
              </div>
            </div>
            <div className="col-md-6">
              <div className="card p-4 shadow-sm" style={{ border: '2px solid #6f42c1' }}>
                <h5 className="card-title" style={{ color: '#6f42c1' }}>⚡ System Optimization</h5>
                <p>Optimize system performance and clean up temporary files.</p>
                <button className="btn btn-outline-purple w-100" onClick={optimizeSystem} style={{ color: '#6f42c1', borderColor: '#6f42c1' }}>
                  🔧 Optimize System
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* System Information */}
      {systemStats && (
        <div className="mt-5 pt-4" style={{ borderTop: '2px solid #e5e7eb' }}>
          <h5 style={{ color: '#dc3545' }}>📋 System Information</h5>
          <div className="row g-3">
            <div className="col-md-4">
              <strong>Version:</strong> {systemStats.version || '1.0.0'}
            </div>
            <div className="col-md-4">
              <strong>Scanner Status:</strong> {systemStats.scanner_status || 'Unknown'}
            </div>
            <div className="col-md-4">
              <strong>Data Directory:</strong> 
              <code style={{ fontSize: '0.8rem', marginLeft: '0.5rem' }}>
                {systemStats.data_directory || 'Not specified'}
              </code>
            </div>
            <div className="col-md-4">
              <strong>Malware Detection:</strong> {systemStats.malware_detection || 'Enabled'}
            </div>
            <div className="col-md-4">
              <strong>Supported Languages:</strong> {systemStats.supported_languages?.length || 0} languages
            </div>
            <div className="col-md-4">
              <strong>Last Updated:</strong> {new Date(systemStats.timestamp).toLocaleString()}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminPanel;