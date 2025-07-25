import React, { useEffect, useState } from "react";
import API from "../api";
import "../style.css";
import { Toast } from "bootstrap";
import JSZip from "jszip";

const ThreatGuardDashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [recentThreats, setRecentThreats] = useState([]);
  const [health, setHealth] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [logicBombStats, setLogicBombStats] = useState(null);
  const [activeTab, setActiveTab] = useState("logicbombs");
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [showThreatModal, setShowThreatModal] = useState(false);

  const logicBombThreats = recentThreats.filter(
    (t) => t.type?.includes("BOMB") || t.rule_id?.startsWith("LOGIC_BOMB_") || t.rule_id?.startsWith("MALWARE_")
  );
  const otherThreats = recentThreats.filter(
    (t) => !t.type?.includes("BOMB") && !t.rule_id?.startsWith("LOGIC_BOMB_") && !t.rule_id?.startsWith("MALWARE_")
  );

  useEffect(() => {
    fetchMetrics();
    fetchHealth();
  }, []);

  const fetchMetrics = async () => {
    try {
      const res = await API.get("/api/command-center/metrics");
      if (res.data && !res.data.error) {
        setMetrics(res.data);
        setRecentThreats(res.data.recent_threats || []);
        if (res.data.logic_bomb_analysis) {
          setLogicBombStats({
            count: Object.values(res.data.logic_bomb_analysis.by_type).reduce(
              (a, b) => a + b,
              0
            ),
            details: Object.entries(
              res.data.logic_bomb_analysis.by_type || {}
            ).map(([type, count]) => `${type.replace("_", " ")}: ${count}`),
          });
        }
      }
    } catch (error) {
      // Fallback to older API if command center doesn't exist
      try {
        const res = await API.get("/api/dashboard/metrics");
        if (res.data && !res.data.error) {
          setMetrics({
            threat_ratings: {
              logic_bomb_risk_score: calculateRiskScore(res.data),
            },
            scan_info: res.data.scan_info,
            threat_shield: { status: "PROTECTED", protection_effectiveness: 85 },
            threats: { critical_bombs: res.data.issues?.by_severity?.CRITICAL || 0 },
            threat_intelligence: { threat_level: "MEDIUM" },
            logic_bomb_metrics: {
              time_bomb_count: 0,
              user_bomb_count: 0,
              counter_bomb_count: 0,
              destructive_payload_count: 0,
            }
          });
          setRecentThreats(res.data.recent_issues || []);
        }
      } catch (fallbackError) {
        console.error("Failed to fetch metrics:", fallbackError);
      }
    }
  };

  const calculateRiskScore = (data) => {
    const totalIssues = data.issues?.total || 0;
    const criticalIssues = data.issues?.by_severity?.CRITICAL || 0;
    return Math.min(100, (criticalIssues * 20) + (totalIssues * 2));
  };

  const fetchHealth = async () => {
    try {
      const res = await API.get("/api/health");
      setHealth(res.data);
    } catch (err) {
      console.error("Failed to fetch health info:", err);
    }
  };

  const neutralizeThreat = async (id) => {
    try {
      await API.post(`/api/threats/${id}/neutralize`);
      fetchMetrics();
      showToast("Threat neutralized successfully!", "success");
    } catch (error) {
      // Fallback to older API
      try {
        await API.put(`/api/issues/${id}/status`, { status: "RESOLVED" });
        fetchMetrics();
        showToast("Issue resolved successfully!", "success");
      } catch (fallbackError) {
        console.error("Failed to neutralize threat:", fallbackError);
        showToast("Failed to neutralize threat", "error");
      }
    }
  };

  const showThreatDetails = (threat) => {
    setSelectedThreat(threat);
    setShowThreatModal(true);
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

  const getThreatPriority = (threat) => {
    if (threat.severity === 'CRITICAL_BOMB' || threat.severity === 'CRITICAL') return 'IMMEDIATE';
    if (threat.severity === 'HIGH_RISK' || threat.severity === 'MAJOR') return 'HIGH';
    if (threat.severity === 'MEDIUM_RISK' || threat.severity === 'MINOR') return 'MEDIUM';
    return 'LOW';
  };

  const handleFileDrop = async (e) => {
    e.preventDefault();
    setDragOver(false);
    const items = e.dataTransfer.items;
    const files = await extractFilesFromItems(items);
    handleUpload(files);
  };

  const handleFileSelect = async (e) => {
    const files = Array.from(e.target.files);
    handleUpload(files);
  };

  const extractFilesFromItems = async (items) => {
    const traverseFileTree = (item, path = "") => {
      return new Promise((resolve) => {
        if (item.isFile) {
          item.file((file) => {
            file.fullPath = path + file.name;
            resolve([file]);
          });
        } else if (item.isDirectory) {
          const dirReader = item.createReader();
          dirReader.readEntries(async (entries) => {
            const results = await Promise.all(
              entries.map((entry) =>
                traverseFileTree(entry, path + item.name + "/")
              )
            );
            resolve(results.flat());
          });
        }
      });
    };

    const entries = Array.from(items).map((item) => item.webkitGetAsEntry());
    const all = await Promise.all(
      entries.map((entry) => traverseFileTree(entry))
    );
    return all.flat();
  };

  const handleUpload = async (files) => {
    if (!files.length) return;

    const fileContents = [];

    for (const file of files) {
      const ext = file.name.split(".").pop().toLowerCase();

      if (ext === "zip") {
        const zip = new JSZip();
        const zipData = await zip.loadAsync(file);
        for (const [relativePath, zipEntry] of Object.entries(zipData.files)) {
          if (!zipEntry.dir) {
            const content = await zipEntry.async("text");
            fileContents.push({
              id: generateId(),
              name: zipEntry.name,
              type: getFileLanguage(zipEntry.name),
              content: content,
            });
          }
        }
      } else {
        const content = await readFileContent(file);
        fileContents.push({
          id: generateId(),
          name: file.fullPath || file.webkitRelativePath || file.name,
          type: getFileLanguage(file.name),
          content: content,
        });
      }
    }

    const payload = {
      scan_id: generateId(),
      scan_type: "manual",
      project_id: `logic-bomb-scan-${Date.now()}`,
      project_name: "Logic Bomb Detection Scan",
      timestamp: new Date().toISOString(),
      file_contents: fileContents,
    };

    try {
      setUploading(true);
      const response = await API.post("/api/scan/files", payload);
      fetchMetrics();
      fetchHealth();

      const scanData = response.data;
      const threatCount = scanData.summary?.logic_bomb_patterns_found || scanData.summary?.total_issues || 0;
      const riskScore = scanData.logic_bomb_metrics?.logic_bomb_risk_score || 0;

      showToast(
        `Scan completed! Found ${threatCount} threats. Risk Score: ${riskScore}/100`,
        threatCount > 0 ? "warning" : "success"
      );
    } catch (err) {
      console.error(err);
      showToast("Scan failed. Please try again.", "error");
    } finally {
      setUploading(false);
    }
  };

  const readFileContent = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });

  const generateId = () => "id_" + Math.random().toString(36).substr(2, 9);

  const getFileLanguage = (filename) => {
    const ext = filename.split(".").pop().toLowerCase();
    const map = {
      py: "python",
      js: "javascript",
      ts: "typescript",
      java: "java",
      html: "html",
      css: "css",
      json: "json",
      xml: "xml",
      sql: "sql",
      cpp: "cpp",
      cs: "csharp",
      rb: "ruby",
      php: "php",
      go: "golang",
      rs: "rust",
      c: "c",
    };
    return map[ext] || "unknown";
  };

  const showToast = (message, type) => {
    const toastEl = document.getElementById(`${type}Toast`);
    if (toastEl) {
      toastEl.querySelector(".toast-body").textContent = message;
      new Toast(toastEl).show();
    }
  };

  const timeAgo = (isoTime) => {
    const diffMs = Date.now() - new Date(isoTime).getTime();
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return "just now";
    if (diffMin === 1) return "1 minute ago";
    return `${diffMin} minutes ago`;
  };

  if (!metrics)
    return <p className="text-center mt-5">Loading ThreatGuard metrics...</p>;

  const {
    threat_ratings = {},
    scan_info = {},
    threat_shield = {},
    threats = {},
    threat_intelligence = {},
    logic_bomb_metrics = {}
  } = metrics;

  return (
    <div className="container-fluid mt-4 px-5" style={{ background: "#fff", color: "#222" }}>
      {/* System Status Header */}
      {health && (
        <div
          className={`alert ${health.status === "healthy" ? "alert-success" : "alert-danger"} mb-4`}
        >
          {health.status === "healthy"
            ? `🛡️ ThreatGuard Pro operational. Logic bomb detection active. Last scan: ${timeAgo(
                health.timestamp
              )}.`
            : `⚠️ ThreatGuard Pro experiencing issues. Last checked: ${timeAgo(
                health.timestamp
              )}.`}
        </div>
      )}

      {/* Quick Logic Bomb Scan */}
      <div className="card mb-5 shadow" style={{ background: "#fff", border: "1px solid #e5e7eb" }}>
        <div
          className="card-header d-flex justify-content-between align-items-center"
          style={{ background: "#f8f9fa", borderBottom: "1px solid #e5e7eb" }}
        >
          <h5 className="mb-0" style={{ color: "#222" }}>
            <i className="bi bi-shield-exclamation"></i> 🚨 Threat Detection Scanner
          </h5>
          <div>
            <span className="badge bg-danger me-2">THREAT FOCUSED</span>
          </div>
        </div>
        <div
          className={`card-body text-center ${dragOver ? "bg-info bg-opacity-25" : "bg-light"}`}
          style={{ padding: "50px", transition: "background 0.3s ease", border: "2px dashed #0d6efd" }}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleFileDrop}
        >
          <input
            type="file"
            id="fileInput"
            hidden
            multiple
            webkitdirectory="true"
            mozdirectory="true"
            directory="true"
            onChange={handleFileSelect}
          />
          <div className="mb-3">
            <i
              className="bi bi-shield-exclamation"
              style={{ fontSize: "3rem", color: "#dc3545" }}
            ></i>
            <h5 className="mt-3" style={{ color: "#222" }}>
              Drop your source code here for instant threat detection
            </h5>
            <small style={{ color: "#666" }}>
              Detects logic bombs, malware patterns, security vulnerabilities & more
            </small>
          </div>
          <div className="d-flex justify-content-center gap-3 mt-4">
            <button
              className="btn btn-danger"
              onClick={() => document.getElementById("fileInput").click()}
              disabled={uploading}
            >
              {uploading
                ? "🔍 Scanning for Threats..."
                : "🎯 Scan for Threats"}
            </button>
          </div>
        </div>
      </div>

      {/* Toast Notifications */}
      <div className="position-fixed bottom-0 end-0 p-3" style={{ zIndex: 1055 }}>
        <div id="successToast" className="toast align-items-center text-white bg-success border-0" role="alert">
          <div className="d-flex">
            <div className="toast-body">✅ Operation completed successfully!</div>
            <button type="button" className="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
          </div>
        </div>
        <div id="warningToast" className="toast align-items-center text-white bg-warning border-0" role="alert">
          <div className="d-flex">
            <div className="toast-body">⚠️ Threats detected!</div>
            <button type="button" className="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
          </div>
        </div>
        <div id="errorToast" className="toast align-items-center text-white bg-danger border-0" role="alert">
          <div className="d-flex">
            <div className="toast-body">❌ Operation failed. Please try again.</div>
            <button type="button" className="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
          </div>
        </div>
      </div>

      {/* Threat Overview Metrics */}
      <h2 className="mb-4" style={{ color: "#dc3545" }}>
        🛡️ Threat Detection Overview
      </h2>
      <div className="row g-4 mb-4">
        {[
          {
            label: "Threat Risk Score",
            value: `${threat_ratings?.logic_bomb_risk_score || 0}/100`,
            className: `${
              (threat_ratings?.logic_bomb_risk_score || 0) >= 70
                ? "text-danger"
                : (threat_ratings?.logic_bomb_risk_score || 0) >= 40
                ? "text-warning"
                : "text-success"
            }`,
            icon: "🚨"
          },
          {
            label: "Critical Threats",
            value: threats?.critical_bombs || logicBombThreats.filter(t => 
              t.severity === 'CRITICAL_BOMB' || t.severity === 'CRITICAL'
            ).length || 0,
            className: "text-danger",
            icon: "💣"
          },
          {
            label: "Shield Status",
            value: threat_shield?.status || "PROTECTED",
            className: `${
              threat_shield?.status === "PROTECTED"
                ? "text-success"
                : threat_shield?.status === "BLOCKED"
                ? "text-danger"
                : "text-warning"
            }`,
            icon: "🛡️"
          },
          {
            label: "Total Threats",
            value: recentThreats.length,
            className: recentThreats.length > 0 ? "text-warning" : "text-success",
            icon: "🎯"
          },
        ].map((item, i) => (
          <div className="col-md-3" key={i}>
            <div
              className="metric-card text-center"
              style={{
                background: "#fff",
                border: "2px solid #e5e7eb",
                color: "#222",
                padding: "1.5rem",
                borderRadius: "8px",
                boxShadow: "0 2px 4px rgba(0,0,0,0.1)"
              }}
            >
              <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>{item.icon}</div>
              <div
                className={`metric-value ${item.className}`}
                style={{ fontSize: "2.5rem", fontWeight: "bold" }}
              >
                {item.value}
              </div>
              <div className="metric-label" style={{ color: "#888" }}>
                {item.label}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Threat Tabs */}
      <ul className="nav nav-tabs mb-3" style={{ borderBottom: "2px solid #e5e7eb" }}>
        <li className="nav-item">
          <button
            className={`nav-link ${activeTab === "logicbombs" ? "active" : ""}`}
            onClick={() => setActiveTab("logicbombs")}
            style={{
              color: activeTab === "logicbombs" ? "#dc3545" : "#888",
              background: activeTab === "logicbombs" ? "#f8f9fa" : "transparent",
              border: "none",
              borderBottom:
                activeTab === "logicbombs"
                  ? "3px solid #dc3545"
                  : "3px solid transparent",
            }}
          >
            🚨 Critical Threats ({logicBombThreats.length})
          </button>
        </li>
        <li className="nav-item">
          <button
            className={`nav-link ${activeTab === "other" ? "active" : ""}`}
            onClick={() => setActiveTab("other")}
            style={{
              color: activeTab === "other" ? "#0d6efd" : "#888",
              background: activeTab === "other" ? "#f8f9fa" : "transparent",
              border: "none",
              borderBottom:
                activeTab === "other"
                  ? "3px solid #0d6efd"
                  : "3px solid transparent",
            }}
          >
            📄 Other Issues ({otherThreats.length})
          </button>
        </li>
      </ul>

      {/* Enhanced Threat Analysis Table */}
      <div
        className="section"
        style={{
          background: "#fff",
          border: "2px solid #e5e7eb",
          padding: "1.5rem",
          borderRadius: "8px",
        }}
      >
        <div className="d-flex justify-content-between align-items-center mb-3">
          <h2 className="mb-0" style={{ color: activeTab === "logicbombs" ? "#dc3545" : "#0d6efd" }}>
            {activeTab === "logicbombs"
              ? "🚨 Critical Threats Detected"
              : "📄 Other Security Issues"}
          </h2>
        </div>

        <div className="table-responsive w-100">
          <table className="table table-bordered table-hover align-middle">
            <thead className="table-light">
              <tr>
                <th style={{ color: "#222" }}>Priority</th>
                <th style={{ color: "#222" }}>Threat Type</th>
                <th style={{ color: "#222" }}>File Affected</th>
                <th style={{ color: "#222" }}>Line</th>
                <th style={{ color: "#222" }}>Code Location</th>
                <th style={{ color: "#222" }}>Risk Level</th>
                <th className="text-center" style={{ color: "#222" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(activeTab === "logicbombs" ? logicBombThreats : otherThreats)
                .length > 0 ? (
                (activeTab === "logicbombs" ? logicBombThreats : otherThreats).map((threat) => (
                  <tr key={threat.id}>
                    <td>
                      <span
                        className={`badge ${
                          getThreatPriority(threat) === 'IMMEDIATE'
                            ? "bg-danger"
                            : getThreatPriority(threat) === 'HIGH'
                            ? "bg-warning"
                            : getThreatPriority(threat) === 'MEDIUM'
                            ? "bg-info"
                            : "bg-secondary"
                        }`}
                        style={{ fontSize: "0.8rem", fontWeight: "bold" }}
                      >
                        {getThreatPriority(threat)}
                      </span>
                    </td>
                    <td style={{ color: "#222", fontWeight: "bold" }}>
                      {threat.rule_id?.replace('MALWARE_', '').replace('_', ' ') || threat.type}
                    </td>
                    <td
                      style={{
                        color: "#0d6efd",
                        fontFamily: "monospace",
                        fontSize: "0.9rem",
                        maxWidth: "200px",
                        wordBreak: "break-word"
                      }}
                    >
                      📁 {threat.file_path?.split("/").pop() || threat.file_path}
                    </td>
                    <td 
                      className="text-center" 
                      style={{ 
                        color: "#dc3545", 
                        fontWeight: "bold",
                        fontSize: "1.1rem"
                      }}
                    >
                      {threat.line_number}
                    </td>
                    <td
                      style={{
                        color: "#222",
                        fontSize: "0.85rem",
                        maxWidth: "300px"
                      }}
                    >
                      {threat.message || threat.trigger_analysis || "Threat detected"}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          threat.severity === "CRITICAL_BOMB" || threat.severity === "CRITICAL"
                            ? "bg-danger"
                            : threat.severity === "HIGH_RISK" || threat.severity === "MAJOR"
                            ? "bg-warning"
                            : threat.severity === "MEDIUM_RISK" || threat.severity === "MINOR"
                            ? "bg-info"
                            : "bg-secondary"
                        }`}
                      >
                        {threat.severity === "CRITICAL_BOMB" ? "CRITICAL" : threat.severity}
                      </span>
                    </td>
                    <td className="text-center">
                      <div className="d-flex justify-content-center gap-2">
                        <button
                          className="btn btn-sm btn-info"
                          onClick={() => showThreatDetails(threat)}
                        >
                          🔍 Details
                        </button>
                        <button
                          className="btn btn-sm btn-success"
                          onClick={() => neutralizeThreat(threat.id)}
                        >
                          ✅ Fix
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan="7"
                    className="text-center"
                    style={{ color: "#888", padding: "2rem" }}
                  >
                    {activeTab === "logicbombs" 
                      ? "🎉 No critical threats found! Your code appears to be clean." 
                      : "No other security issues detected."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Details Modal */}
      {showThreatModal && selectedThreat && (
        <div className="modal show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content" style={{ background: '#fff', color: '#222' }}>
              <div className="modal-header" style={{ borderBottom: '2px solid #e5e7eb' }}>
                <h5 className="modal-title" style={{ color: '#dc3545' }}>
                  🚨 Threat Analysis Details
                </h5>
                <button 
                  type="button" 
                  className="btn-close" 
                  onClick={() => setShowThreatModal(false)}
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
                      border: '1px solid #4a5568'
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
                </div>
              </div>
              <div className="modal-footer" style={{ borderTop: '2px solid #e5e7eb' }}>
                <button
                  type="button"
                  className="btn btn-success"
                  onClick={() => {
                    neutralizeThreat(selectedThreat.id);
                    setShowThreatModal(false);
                  }}
                >
                  ✅ Apply Fix
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowThreatModal(false)}
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

export default ThreatGuardDashboard;