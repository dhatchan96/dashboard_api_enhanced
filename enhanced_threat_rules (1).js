import React, { useEffect, useState } from 'react';
import API from '../api';
import '../style.css';

const ThreatRules = () => {
  const [rules, setRules] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [formMode, setFormMode] = useState('create');
  const [formData, setFormData] = useState({
    id: '', name: '', description: '', severity: 'CRITICAL', type: 'VULNERABILITY',
    language: '*', pattern: '', remediation_effort: 30
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await API.get('/api/rules');
      setRules(Object.values(res.data || {}));
    } catch (err) {
      console.error('Failed to fetch rules:', err);
      // Initialize with some default threat detection rules if none exist
      setRules([]);
    }
  };

  const openCreateModal = () => {
    setFormMode('create');
    setFormData({
      id: '', name: '', description: '', severity: 'CRITICAL', type: 'VULNERABILITY',
      language: '*', pattern: '', remediation_effort: 30
    });
    setShowModal(true);
  };

  const openEditModal = (rule) => {
    setFormMode('edit');
    setFormData({ ...rule });
    setShowModal(true);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (formMode === 'create') {
        await API.post('/api/rules', {
          ...formData,
          enabled: true,
          custom: true,
          tags: ['threat-detection', 'custom'],
          remediation_effort: parseInt(formData.remediation_effort),
        });
      } else {
        await API.put(`/api/rules/${formData.id}`, {
          ...formData,
          remediation_effort: parseInt(formData.remediation_effort),
        });
      }
      fetchRules();
      setShowModal(false);
    } catch (err) {
      console.error('Failed to submit rule:', err);
      alert('Failed to save rule. Please check your input and try again.');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm(`Are you sure you want to delete rule: ${id}?`)) return;
    try {
      await API.delete(`/api/rules/${id}`);
      fetchRules();
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  const handleToggle = async (id, enabled) => {
    try {
      await API.put(`/api/rules/${id}`, { enabled });
      fetchRules();
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  const createPresetRule = async (preset) => {
    const presets = {
      logicBomb: {
        id: `logic-bomb-${Date.now()}`,
        name: 'Logic Bomb Detection',
        description: 'Detects time-based logic bombs and conditional triggers',
        severity: 'CRITICAL',
        type: 'VULNERABILITY',
        language: '*',
        pattern: '(if.*date.*>.*\\d{4}|if.*time.*>|if.*datetime)',
        remediation_effort: 120
      },
      malwarePattern: {
        id: `malware-pattern-${Date.now()}`,
        name: 'Malware Pattern Detection',
        description: 'Detects common malware patterns and suspicious code',
        severity: 'CRITICAL',
        type: 'VULNERABILITY',
        language: '*',
        pattern: '(exec\\s*\\(|eval\\s*\\(|system\\s*\\()',
        remediation_effort: 60
      },
      financialFraud: {
        id: `financial-fraud-${Date.now()}`,
        name: 'Financial Fraud Detection',
        description: 'Detects potential financial fraud patterns',
        severity: 'CRITICAL',
        type: 'VULNERABILITY',
        language: '*',
        pattern: '(bitcoin.*address|crypto.*wallet|paypal\\.me)',
        remediation_effort: 90
      }
    };

    const ruleData = presets[preset];
    if (ruleData) {
      try {
        await API.post('/api/rules', {
          ...ruleData,
          enabled: true,
          custom: true,
          tags: ['threat-detection', 'preset']
        });
        fetchRules();
      } catch (err) {
        console.error('Failed to create preset rule:', err);
      }
    }
  };

  const getFilteredRules = () => {
    let filtered = rules;

    // Apply type filter
    if (filter === 'threats') {
      filtered = filtered.filter(rule => 
        rule.tags?.includes('threat-detection') || 
        rule.name?.toLowerCase().includes('bomb') ||
        rule.name?.toLowerCase().includes('malware') ||
        rule.severity === 'CRITICAL'
      );
    } else if (filter === 'enabled') {
      filtered = filtered.filter(rule => rule.enabled);
    } else if (filter === 'disabled') {
      filtered = filtered.filter(rule => !rule.enabled);
    } else if (filter === 'custom') {
      filtered = filtered.filter(rule => rule.custom);
    }

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(rule =>
        rule.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        rule.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        rule.id?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    return filtered;
  };

  const filteredRules = getFilteredRules();

  return (
    <div className="container-fluid mt-4 px-5" style={{ background: '#fff', color: '#222', minHeight: '100vh' }}>
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 style={{ color: '#dc3545' }}>🛡️ Threat Detection Rules</h2>
        <div className="d-flex gap-3">
          <input
            type="text"
            className="form-control"
            placeholder="Search rules..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: '250px' }}
          />
          <select 
            className="form-select" 
            value={filter} 
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: '150px' }}
          >
            <option value="all">All Rules</option>
            <option value="threats">Threat Rules</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
            <option value="custom">Custom</option>
          </select>
          <button className="btn btn-primary" onClick={openCreateModal}>
            ➕ Create Rule
          </button>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="row g-3 mb-4">
        <div className="col-md-4">
          <div className="card" style={{ border: '2px solid #dc3545' }}>
            <div className="card-body text-center">
              <h5 style={{ color: '#dc3545' }}>💣 Logic Bomb Detection</h5>
              <p>Detect time-based threats and conditional triggers</p>
              <button 
                className="btn btn-outline-danger btn-sm"
                onClick={() => createPresetRule('logicBomb')}
              >
                Add Rule
              </button>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card" style={{ border: '2px solid #fd7e14' }}>
            <div className="card-body text-center">
              <h5 style={{ color: '#fd7e14' }}>🦠 Malware Patterns</h5>
              <p>Detect suspicious code execution patterns</p>
              <button 
                className="btn btn-outline-warning btn-sm"
                onClick={() => createPresetRule('malwarePattern')}
              >
                Add Rule
              </button>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card" style={{ border: '2px solid #0d6efd' }}>
            <div className="card-body text-center">
              <h5 style={{ color: '#0d6efd' }}>💰 Financial Fraud</h5>
              <p>Detect financial redirection patterns</p>
              <button 
                className="btn btn-outline-primary btn-sm"
                onClick={() => createPresetRule('financialFraud')}
              >
                Add Rule
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="row g-4 mb-4">
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '1px solid #e5e7eb' }}>
            <div className="card-body">
              <h3 style={{ color: '#0d6efd' }}>{rules.length}</h3>
              <p style={{ color: '#888' }}>Total Rules</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '1px solid #198754' }}>
            <div className="card-body">
              <h3 style={{ color: '#198754' }}>{rules.filter(r => r.enabled).length}</h3>
              <p style={{ color: '#888' }}>Active Rules</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '1px solid #dc3545' }}>
            <div className="card-body">
              <h3 style={{ color: '#dc3545' }}>{rules.filter(r => r.severity === 'CRITICAL').length}</h3>
              <p style={{ color: '#888' }}>Critical Rules</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card text-center" style={{ background: '#fff', border: '1px solid #fd7e14' }}>
            <div className="card-body">
              <h3 style={{ color: '#fd7e14' }}>{rules.filter(r => r.custom).length}</h3>
              <p style={{ color: '#888' }}>Custom Rules</p>
            </div>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="section" style={{ background: '#f8f9fa', border: '2px solid #e5e7eb', borderRadius: '8px' }}>
        <div className="table-responsive">
          <table className="table table-bordered table-hover" style={{ background: '#fff' }}>
            <thead className="table-light">
              <tr>
                <th style={{ color: '#dc3545' }}>Rule ID</th>
                <th style={{ color: '#dc3545' }}>Name</th>
                <th style={{ color: '#dc3545' }}>Language</th>
                <th style={{ color: '#dc3545' }}>Severity</th>
                <th style={{ color: '#dc3545' }}>Type</th>
                <th style={{ color: '#dc3545' }}>Status</th>
                <th style={{ color: '#dc3545' }} className="text-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map((rule) => (
                <tr key={rule.id}>
                  <td style={{ 
                    color: '#0d6efd', 
                    fontFamily: 'monospace', 
                    fontSize: '0.9rem',
                    maxWidth: '200px',
                    wordBreak: 'break-word'
                  }}>
                    {rule.id}
                  </td>
                  <td style={{ color: '#222', fontWeight: 'bold' }}>{rule.name}</td>
                  <td>
                    <span className="badge bg-secondary">
                      {rule.language === '*' ? 'ALL' : rule.language?.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${
                      rule.severity === 'CRITICAL' ? 'bg-danger' :
                      rule.severity === 'MAJOR' ? 'bg-warning' :
                      rule.severity === 'MINOR' ? 'bg-info' :
                      'bg-secondary'
                    }`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td>{rule.type}</td>
                  <td>
                    <span className={`badge ${rule.enabled ? 'bg-success' : 'bg-secondary'}`}>
                      {rule.enabled ? '✅ ACTIVE' : '❌ DISABLED'}
                    </span>
                  </td>
                  <td className="text-center">
                    <div className="d-flex gap-1 justify-content-center">
                      <button 
                        className="btn btn-sm btn-info" 
                        onClick={() => openEditModal(rule)}
                        title="Edit rule"
                      >
                        ✏️
                      </button>
                      <button 
                        className="btn btn-sm btn-danger" 
                        onClick={() => handleDelete(rule.id)}
                        title="Delete rule"
                      >
                        🗑️
                      </button>
                      <button
                        className={`btn btn-sm ${rule.enabled ? 'btn-warning' : 'btn-success'}`}
                        onClick={() => handleToggle(rule.id, !rule.enabled)}
                        title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                      >
                        {rule.enabled ? '⏸️' : '▶️'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredRules.length === 0 && (
                <tr>
                  <td colSpan="7" className="text-center" style={{ color: '#888', padding: '2rem' }}>
                    {searchTerm || filter !== 'all' 
                      ? 'No rules found matching your criteria.' 
                      : 'No rules configured. Create your first threat detection rule!'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Rule Creation/Edit Modal */}
      {showModal && (
        <div className="modal show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-lg">
            <div className="modal-content" style={{ background: '#fff', color: '#222' }}>
              <form onSubmit={handleSubmit}>
                <div className="modal-header" style={{ borderBottom: '2px solid #e5e7eb' }}>
                  <h5 className="modal-title" style={{ color: '#dc3545' }}>
                    {formMode === 'create' ? '➕ Create Threat Detection Rule' : '✏️ Edit Threat Rule'}
                  </h5>
                  <button type="button" className="btn-close" onClick={() => setShowModal(false)}></button>
                </div>
                <div className="modal-body">
                  <div className="row g-3">
                    <div className="col-md-6">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Rule ID</label>
                      <input
                        type="text"
                        className="form-control"
                        name="id"
                        required
                        value={formData.id}
                        disabled={formMode === 'edit'}
                        onChange={handleChange}
                        placeholder="e.g., threat-logic-bomb-detection"
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Rule Name</label>
                      <input 
                        type="text" 
                        className="form-control" 
                        name="name" 
                        required 
                        value={formData.name} 
                        onChange={handleChange}
                        placeholder="e.g., Logic Bomb Detection"
                      />
                    </div>
                    <div className="col-12">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Description</label>
                      <textarea 
                        className="form-control" 
                        name="description" 
                        required 
                        value={formData.description} 
                        onChange={handleChange}
                        rows="3"
                        placeholder="Describe what this rule detects and why it's important..."
                      ></textarea>
                    </div>
                    <div className="col-md-4">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Severity</label>
                      <select className="form-select" name="severity" value={formData.severity} onChange={handleChange}>
                        <option value="CRITICAL">🚨 Critical</option>
                        <option value="MAJOR">⚠️ Major</option>
                        <option value="MINOR">ℹ️ Minor</option>
                        <option value="INFO">📝 Info</option>
                      </select>
                    </div>
                    <div className="col-md-4">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Type</label>
                      <select className="form-select" name="type" value={formData.type} onChange={handleChange}>
                        <option value="VULNERABILITY">🛡️ Vulnerability</option>
                        <option value="BUG">🐛 Bug</option>
                        <option value="CODE_SMELL">👃 Code Smell</option>
                        <option value="SECURITY_HOTSPOT">🔥 Security Hotspot</option>
                      </select>
                    </div>
                    <div className="col-md-4">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Language</label>
                      <select className="form-select" name="language" value={formData.language} onChange={handleChange}>
                        <option value="*">All Languages</option>
                        <option value="python">Python</option>
                        <option value="javascript">JavaScript</option>
                        <option value="java">Java</option>
                        <option value="csharp">C#</option>
                        <option value="php">PHP</option>
                        <option value="cpp">C++</option>
                        <option value="go">Go</option>
                      </select>
                    </div>
                    <div className="col-md-8">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Detection Pattern (Regex)</label>
                      <input 
                        type="text" 
                        className="form-control" 
                        name="pattern" 
                        required 
                        value={formData.pattern} 
                        onChange={handleChange}
                        placeholder="e.g., if.*date.*>.*\d{4}"
                        style={{ fontFamily: 'monospace' }}
                      />
                      <small style={{ color: '#888' }}>
                        Regular expression pattern to detect threats in code
                      </small>
                    </div>
                    <div className="col-md-4">
                      <label className="form-label" style={{ color: '#dc3545', fontWeight: 'bold' }}>Fix Time (mins)</label>
                      <input 
                        type="number" 
                        className="form-control" 
                        name="remediation_effort" 
                        value={formData.remediation_effort} 
                        onChange={handleChange}
                        min="1"
                        max="480"
                      />
                      <small style={{ color: '#888' }}>
                        Estimated time to fix this issue
                      </small>
                    </div>
                  </div>
                </div>
                <div className="modal-footer" style={{ borderTop: '2px solid #e5e7eb' }}>
                  <button type="submit" className="btn btn-success">
                    {formMode === 'create' ? '➕ Create Rule' : '💾 Update Rule'}
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatRules;