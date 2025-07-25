import React, { useEffect, useState } from 'react';
import API from '../api';
import '../style.css';

const ThreatIssues = () => {
  const [threats, setThreats] = useState([]);
  const [filter, setFilter] = useState('all');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchThreats();
  }, []);

  const fetchThreats = async () => {
    try {
      // Try new API first
      const res = await API.get('/api/threats');
      setThreats(res.data || []);
    } catch (err) {
      // Fallback to old API
      try {
        const res = await API.get('/api/issues');
        setThreats(res.data || []);
      } catch (fallbackErr) {
        console.error('Failed to fetch threats:', fallbackErr);
      }
    }
  };

  const handleStatusToggle = async (id) => {
    const threat = threats.find(t => t.id === id);
    const newStatus = threat.status === 'ACTIVE_THREAT' || threat.status === 'OPEN' ? 'NEUTRALIZED' : 'ACTIVE_THREAT';
    
    try {
      // Try new API first
      await API.put(`/api/threats/${id}/status`, { status: newStatus });
      fetchThreats();
    } catch (err) {
      // Fallback to old API
      try {
        const oldStatus = newStatus === 'NEUTRALIZED' ? 'RESOLVED' : 'OPEN';
        await API.put(`/api/issues/${id}/status`, { status: oldStatus });
        fetchThreats();
      } catch (fallbackErr) {
        console.error('Failed to update threat status:', fallbackErr);
      }
    }
  };

  const neutralizeThreat = async (id) => {
    if (!window.confirm('Are you sure you want to neutralize this threat?')) return;
    
    try {
      await API.post(`/api/threats/${id}/neutralize`);
      fetchThreats();
    } catch (err) {
      // Fallback to old API
      try {
        await API.put(`/api/issues/${id}/status`, { status: 'RESOLVED' });
        fetchThreats();
      } catch (fallbackErr) {
        console.error('Failed to neutralize threat:', fallbackErr);
      }
    }
  };

  const deleteThreat = async (id) => {
    if (!window.confirm('Are you sure you want to delete this threat?')) return;
    
    try {
      await API.delete(`/api/threats/${id}`);
      fetchThreats();
    } catch (err) {
      // Fallback to old API
      try {
        await API.delete(`/api/issues/${id}`);
        fetchThreats();
      } catch (fallbackErr) {
        console.error('Failed to delete threat:', fallbackErr);
      }
    }
  };

  const showThreatDetails = (threat) => {
    setSelectedThreat(threat);
    setShowModal(true);
  };

  const getThreatPriority = (threat) => {
    if (threat.severity === 'CRITICAL_BOMB' || threat.severity === 'CRITICAL') return 'IMMEDIATE';
    if (threat.severity === 'HIGH_RISK' || threat.severity === 'MAJOR') return 'HIGH';
    if (threat.severity === 'MEDIUM_RISK' || threat.severity === 'MINOR') return 'MEDIUM';
    return 'LOW';
  };

  const getThreatSolution = (threat) => {
    const solutions = {
      'TIME_BOMB': 'Remove time-based conditions or use proper scheduling systems like cron jobs',
      'USER_BOMB': 'Replace hardcoded user checks with proper authentication systems',
      'COUNTER_BOMB': 'Remove execution counters or implement proper rate limiting',
      'DESTRUCTIVE_PAYLOAD': 'Remove destructive operations and implement proper error handling',
      'MALWARE_TIME_BOMB': 'Remove date-based logic bombs immediately',
      'MALWARE_FINANCIAL_FRAUD': 'Remove unauthorized financial redirections',
      'python-hardcoded-secrets': 'Move secrets to environment variables using os.getenv()',
      'python-sql-injection': 'Use parameterized queries or ORM methods',
      'javascript-eval-usage': 'Replace eval() with JSON.parse() or safer alternatives'
    };
    
    return solutions[threat.rule_id] || threat.suggested_fix || 'Review and fix according to security best practices';
  };

  const getFilteredThreats = () => {
    let filtered = threats;

    // Apply status filter
    if (filter === 'logicbombs') {
      filtered = filtered.filter(threat => 
        threat.type?.includes('BOMB') || 
        threat.rule_id?.startsWith('LOGIC_BOMB_') || 
        threat.rule_id?.startsWith('MALWARE_')
      );
    } else if (filter === 'active') {
      filtered = filtered.filter(threat => 
        threat.status === 'ACTIVE_THREAT' || threat.status === 'OPEN'
      );
    } else if (filter === 'critical') {
      filtered = filtered.filter(threat => 
        threat.severity === 'CRITICAL_BOMB' || threat.severity === 'CRITICAL'
      );
    } else if (filter === 'resolved') {
      filtered = filtered.filter(threat => 
        threat.status === 'NEUTRALIZED' || threat.status === 'RESOLVED'
      );
    }

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(threat =>
        threat.file_path?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        threat.message?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        threat.rule_id?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    return filtered;
  };

  const filteredThreats = getFilteredThreats();

  return (
    <div className="container-fluid mt-4 px-5" style={{ background: '#fff', color: '#222', minHeight: '100vh' }}>
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 style={{ color: '#dc3545' }}>🚨 Threat Management Center</h2>
        <div className="d-flex gap-3">
          <input
            type="text"
            className="form-control"
            placeholder="Search threats by file, message, or rule..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: '300px' }}
          />
          <select 
            className="form-select" 
            value={filter} 
            onChange={(e) => setFilter(e.target.value)}
            style={{ background: '#f8f9fa', color: '#222', border: '1px solid #b0b0b0', width: '200px' }}
          >
            <option value="all">All Threats</option>
            <option value="logicbombs">Logic Bomb Threats</option>
            <option value="active">Active Threats</option>
            <option value="critical">Critical Threats</option>
            <option value="resolved">Resolved Threats</option>
          </select>
        </div>
      </div>

      {/* Threat Statistics Cards */}
      <div className="row g-4 mb-4">
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '2px solid #dc3545' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>💣</div>
              <h3 style={{ color: '#dc3545' }}>
                {threats.filter(t => t.severity === 'CRITICAL_BOMB' || t.severity === 'CRITICAL').length}
              </h3>
              <p style={{ color: '#888' }}>Critical Threats</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '2px solid #fd7e14' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🔥</div>
              <h3 style={{ color: '#fd7e14' }}>
                {threats.filter(t => t.status === 'ACTIVE_THREAT' || t.status === 'OPEN').length}
              </h3>
              <p style={{ color: '#888' }}>Active Threats</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '2px solid #198754' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>✅</div>
              <h3 style={{ color: '#198754' }}>
                {threats.filter(t => t.status === 'NEUTRALIZED' || t.status === 'RESOLVED').length}
              </h3>
              <p style={{ color: '#888' }}>Neutralized</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '2px solid #0d6efd' }}>
            <div className="card-body">
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🎯</div>
              <h3 style={{ color: '#0d6efd' }}>{threats.length}</h3>
              <p style={{ color: '#888' }}>Total Threats</p>
            </div>
          </div>
        </div>
      </div>

      {/* Threats Table */}
      <div className="section" style={{ background: '#f8f9fa', border: '2px solid #e5e7eb', borderRadius: '8px' }}>
        <div className="table-responsive w-100">
          <table className="table table-bordered table-hover align-middle table-sm" style={{ minWidth: '1200px', background: '#fff' }}>
            <thead className="table-light">
              <tr>
                <th style={{ color: '#dc3545' }}>#</th>
                <th style={{ color: '#dc3545' }}>Priority</th>
                <th style={{ color: '#dc3545' }}>Threat Type</th>
                <th style={{ color: '#dc3545' }}>File Affected</th>
                <th style={{ color: '#dc3545' }}>Line</th>
                <th style={{ color: '#dc3545' }}>Code Location</th>
                <th style={{ color: '#dc3545' }}>Status</th>
                <th style={{ color: '#dc3545' }} className="text-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.length > 0 ? filteredThreats.map((threat, index) => (
                <tr key={threat.id}>
                  <td style={{ color: '#888' }}>{index + 1}</td>
                  <td>
                    <span className={`badge ${
                      getThreatPriority(threat) === 'IMMEDIATE' ? 'bg-danger' :
                      getThreatPriority(threat) === 'HIGH' ? 'bg-warning' :
                      getThreatPriority(threat) === 'MEDIUM' ? 'bg-info' :
                      'bg-secondary'
                    }`}>
                      {getThreatPriority(threat)}
                    </span>
                  </td>
                  <td style={{ color: '#222', fontWeight: 'bold' }}>
                    {threat.rule_id?.replace('MALWARE_', '').replace('_', ' ') || threat.type}
                  </td>
                  <td style={{ 
                    wordBreak: 'break-word', 
                    maxWidth: '200px', 
                    color: '#0d6efd',
                    fontFamily: 'monospace',
                    fontSize: '0.9rem'
                  }}>
                    📁 {threat.file_path?.split('/').pop() || threat.file_path}
                  </td>
                  <td 
                    className="text-center" 
                    style={{ 
                      color: '#dc3545', 
                      fontWeight: 'bold',
                      fontSize: '1.1rem'
                    }}
                  >
                    {threat.line_number}
                  </td>
                  <td style={{ 
                    whiteSpace: 'pre-wrap', 
                    maxWidth: '250px', 
                    color: '#222', 
                    fontSize: '0.85rem'
                  }}>
                    {threat.message || threat.trigger_analysis || 'Threat detected'}
                  </td>
                  <td>
                    <span className={`badge ${
                      (threat.status === 'NEUTRALIZED' || threat.status === 'RESOLVED') ? 'bg-success' :
                      (threat.status === 'ACTIVE_THREAT' || threat.status === 'OPEN') ? 'bg-danger' :
                      threat.status === 'UNDER_REVIEW' ? 'bg-warning' :
                      'bg-secondary'
                    }`}>
                      {threat.status === 'NEUTRALIZED' ? 'NEUTRALIZED' :
                       threat.status === 'RESOLVED' ? 'NEUTRALIZED' :
                       threat.status === 'ACTIVE_THREAT' ? 'ACTIVE' :
                       threat.status === 'OPEN' ? 'ACTIVE' :
                       threat.status}
                    </span>
                  </td>
                  <td className="text-center">
                    <div className="d-flex justify-content-center gap-1">
                      <button 
                        className="btn btn-sm btn-info" 
                        onClick={() => showThreatDetails(threat)}
                        title="View threat details"
                      >
                        🔍
                      </button>
                      <button 
                        className="btn btn-sm btn-success" 
                        onClick={() => neutralizeThreat(threat.id)}
                        disabled={threat.status === 'NEUTRALIZED' || threat.status === 'RESOLVED'}
                        title="Neutralize threat"
                      >
                        {(threat.status === 'NEUTRALIZED' || threat.status === 'RESOLVED') ? '✅' : '🛡️'}
                      </button>
                      <button 
                        className="btn btn-sm btn-warning" 
                        onClick={() => handleStatusToggle(threat.id)}
                        title="Toggle status"
                      >
                        🔄
                      </button>
                      <button 
                        className="btn btn-sm btn-danger" 
                        onClick={() => deleteThreat(threat.id)}
                        title="Delete threat"
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="8" className="text-center" style={{ color: '#888', padding: '2rem' }}>
                    {searchTerm || filter !== 'all' 
                      ? 'No threats found matching your criteria.' 
                      : '🎉 No threats detected! Your code appears to be secure.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Details Modal */}
      {showModal && selectedThreat && (
        <div className="modal show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content" style={{ background: '#fff', color: '#222' }}>
              <div className="modal-header" style={{ borderBottom: '2px solid #e5e7eb' }}>
                <h5 className="modal-title" style={{ color: '#dc3545' }}>
                  🚨 Detailed Threat Analysis
                </h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => setShowModal(false)}
                ></button>
              </div>
              <div className="modal-body">
                <div className="row g-3">
                  <div className="col-md-6">
                    <strong style={{ color: '#dc3545' }}>Threat Type:</strong>
                    <p>{selectedThreat.rule_id?.replace('MALWARE_', '').replace('_', ' ') || selectedThreat.type}</p>
                  </div>
                  <div className="col-md-6">
                    <strong style={{ color: '#dc3545' }}>Priority Level:</strong>
                    <p>
                      <span className={`badge ${
                        getThreatPriority(selectedThreat) === 'IMMEDIATE' ? 'bg-danger' :
                        getThreatPriority(selectedThreat) === 'HIGH' ? 'bg-warning' :
                        getThreatPriority(selectedThreat) === 'MEDIUM' ? 'bg-info' : 'bg-secondary'
                      }`}>
                        {getThreatPriority(selectedThreat)}
                      </span>
                    </p>
                  </div>
                  <div className="col-md-6">
                    <strong style={{ color: '#dc3545' }}>Current Status:</strong>
                    <p>
                      <span className={`badge ${
                        (selectedThreat.status === 'NEUTRALIZED' || selectedThreat.status === 'RESOLVED') ? 'bg-success' :
                        (selectedThreat.status === 'ACTIVE_THREAT' || selectedThreat.status === 'OPEN') ? 'bg-danger' :
                        'bg-warning'
                      }`}>
                        {selectedThreat.status === 'NEUTRALIZED' ? 'NEUTRALIZED' :
                         selectedThreat.status === 'RESOLVED' ? 'NEUTRALIZED' :
                         selectedThreat.status === 'ACTIVE_THREAT' ? 'ACTIVE THREAT' :
                         selectedThreat.status === 'OPEN' ? 'ACTIVE THREAT' :
                         selectedThreat.status}
                      </span>
                    </p>
                  </div>
                  <div className="col-md-6">
                    <strong style={{ color: '#dc3545' }}>Severity:</strong>
                    <p>
                      <span className={`badge ${
                        (selectedThreat.severity === 'CRITICAL_BOMB' || selectedThreat.severity === 'CRITICAL') ? 'bg-danger' :
                        (selectedThreat.severity === 'HIGH_RISK' || selectedThreat.severity === 'MAJOR') ? 'bg-warning' :
                        'bg-info'
                      }`}>
                        {selectedThreat.severity === 'CRITICAL_BOMB' ? 'CRITICAL' : selectedThreat.severity}
                      </span>
                    </p>
                  </div>
                  <div className="col-12">
                    <strong style={{ color: '#dc3545' }}>File Location:</strong>
                    <p style={{ 
                      fontFamily: 'monospace', 
                      background: '#f8f9fa', 
                      padding: '0.5rem', 
                      borderRadius: '4px',
                      border: '1px solid #e5e7eb'
                    }}>
                      📁 {selectedThreat.file_path} : Line {selectedThreat.line_number}
                    </p>
                  </div>
                  <div className="col-12">
                    <strong style={{ color: '#dc3545' }}>Code Snippet:</strong>
                    <pre style={{ 
                      background: '#2d3748', 
                      color: '#e2e8f0', 
                      padding: '1rem', 
                      borderRadius: '4px',
                      fontSize: '0.9rem',
                      border: '1px solid #4a5568',
                      overflow: 'auto'
                    }}>
                      {selectedThreat.code_snippet || 'Code snippet not available'}
                    </pre>
                  </div>
                  <div className="col-12">
                    <strong style={{ color: '#dc3545' }}>Threat Description:</strong>
                    <p>{selectedThreat.message || selectedThreat.trigger_analysis || 'Potential security threat detected'}</p>
                  </div>
                  <div className="col-12">
                    <strong style={{ color: '#198754' }}>Recommended Solution:</strong>
                    <div style={{ 
                      background: '#d1e7dd', 
                      border: '1px solid #badbcc',
                      borderRadius: '4px',
                      padding: '1rem'
                    }}>
                      <p style={{ margin: 0, color: '#0f5132' }}>
                        💡 {getThreatSolution(selectedThreat)}
                      </p>
                    </div>
                  </div>
                  {selectedThreat.payload_analysis && (
                    <div className="col-12">
                      <strong style={{ color: '#dc3545' }}>Payload Risk:</strong>
                      <p style={{ color: '#dc3545' }}>{selectedThreat.payload_analysis}</p>
                    </div>
                  )}
                </div>
              </div>
              <div className="modal-footer" style={{ borderTop: '2px solid #e5e7eb' }}>
                <button
                  type="button"
                  className="btn btn-success"
                  onClick={() => {
                    neutralizeThreat(selectedThreat.id);
                    setShowModal(false);
                  }}
                  disabled={selectedThreat.status === 'NEUTRALIZED' || selectedThreat.status === 'RESOLVED'}
                >
                  🛡️ Neutralize Threat
                </button>
                <button
                  type="button"
                  className="btn btn-warning"
                  onClick={() => {
                    handleStatusToggle(selectedThreat.id);
                    setShowModal(false);
                  }}
                >
                  🔄 Toggle Status
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowModal(false)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIssues;