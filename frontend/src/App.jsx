import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
  Activity, UploadCloud, Files, ShieldCheck, LogOut, Search,
  RefreshCw, Users, FileSearch, Clock3, Hash, AlertTriangle,
  CheckCircle2, XCircle, Code, Archive, ShieldAlert, FileCode,
  Layers, ChevronRight, Bug, Key, Terminal, Settings, HardDrive,
  Trash2, User, FolderX, FileText, Download, Check, X, Edit2, Eye, EyeOff, Copy,
  Lock, Globe, ScrollText, PauseCircle, PlayCircle
} from 'lucide-react';

const api = axios.create({ baseURL: '/api' });
const fmt = n => n == null ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(2)} MB`;
const date = v => v ? new Date(v).toLocaleString() : '—';
const ACTION_LABELS = {
  LOGIN_SUCCESS: 'Đăng nhập thành công',
  LOGIN_FAILED: 'Đăng nhập thất bại',
  LOGOUT: 'Đăng xuất',
  UPLOAD_SCAN: 'Tải lên tệp quét',
  DELETE_SCAN: 'Xóa tệp quét',
  BATCH_DELETE_SCANS: 'Xóa hàng loạt tệp',
  EXPORT_PDF: 'Xuất báo cáo PDF',
  USER_CREATE: 'Tạo tài khoản',
  USER_UPDATE_LIMIT: 'Sửa giới hạn upload',
  USER_RESET_PASSWORD: 'Đặt lại mật khẩu',
  USER_SUSPEND: 'Tạm dừng tài khoản',
  USER_ACTIVATE: 'Kích hoạt tài khoản',
  USER_DELETE: 'Xóa tài khoản',
  SETTINGS_UPDATE: 'Cập nhật cài đặt',
  ADMIN_CLEANUP: 'Dọn dẹp lưu trữ',
  EXPORT_LOGS: 'Xuất nhật ký',
  CLEAR_LOGS: 'Xóa nhật ký cũ',
};

function Login({ onLogin }) {
  const [username, setUsername] = useState('admin'), [password, setPassword] = useState(''), [error, setError] = useState('');
  async function submit(e) {
    e.preventDefault(); setError('');
    try {
      const form = new URLSearchParams();
      form.set('username', username);
      form.set('password', password);
      const { data } = await api.post('/auth/login', form);
      localStorage.setItem('token', data.access_token);
      onLogin(data.user);
    } catch (err) {
      setError(err.response?.data?.detail && err.response?.status === 403
        ? err.response.data.detail
        : 'Đăng nhập thất bại. Vui lòng kiểm tra lại tài khoản hoặc mật khẩu.');
    }
  }
  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="brand-mark"><ShieldCheck size={26}/></div>
        <h1>DIE Web Analyzer</h1>
        <p>Phân tích tệp tin nhị phân &amp; Đánh giá an toàn Source Code</p>
        <label>Tên đăng nhập</label>
        <input value={username} onChange={e => setUsername(e.target.value)} required/>
        <label>Mật khẩu</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} required/>
        <button className="primary full">Đăng nhập</button>
        {error && <div className="error">{error}</div>}
      </form>
    </div>
  );
}

function FormattedOutput({ text }) {
  if (!text) return null;
  const lines = text.split('\n');
  return (
    <div className="formatted-output-wrap">
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        const upper = trimmed.toUpperCase();
        const isCritical = upper.includes('CRITICAL');
        const isWarning = upper.includes('WARNING') || upper.includes('WARN');
        const isHeader = trimmed.startsWith('===') || trimmed.startsWith('---');

        if (isCritical) {
          return (
            <div key={idx} className="output-line line-critical">
              <span className="output-badge badge-critical">CRITICAL</span>
              <strong className="output-text-bold">{line}</strong>
            </div>
          );
        }
        if (isWarning) {
          return (
            <div key={idx} className="output-line line-warning">
              <span className="output-badge badge-warning">WARNING</span>
              <strong className="output-text-bold">{line}</strong>
            </div>
          );
        }
        if (isHeader) {
          return (
            <div key={idx} className="output-line line-header">
              <strong>{line}</strong>
            </div>
          );
        }
        return <div key={idx} className="output-line">{line}</div>;
      })}
    </div>
  );
}

function RiskPill({ level, score }) {
  if (!level) return null;
  const cls = level.toLowerCase();
  const labelMap = {
    clean: 'AN TOÀN',
    low: 'RỦI RO THẤP',
    medium: 'RỦI RO VỪA',
    high: 'RỦI RO CAO',
    critical: 'NGHIÊM TRỌNG'
  };
  return (
    <span className={`risk-pill ${cls}`}>
      <span className="dot" />
      {labelMap[cls] || level} {score != null ? `(${score}/100)` : ''}
    </span>
  );
}

function SourceEvaluationView({ evaluation }) {
  const [sevFilter, setSevFilter] = useState('ALL');
  const [query, setQuery] = useState('');

  if (!evaluation) return null;

  const {
    total_source_files = 0,
    total_lines = 0,
    languages = [],
    risk_level = 'CLEAN',
    risk_score = 0,
    summary = '',
    findings_count = {},
    findings = []
  } = evaluation;

  const filteredFindings = findings.filter(f => {
    if (sevFilter !== 'ALL' && f.severity !== sevFilter) return false;
    if (query) {
      const q = query.toLowerCase();
      return f.title.toLowerCase().includes(q) ||
             f.file.toLowerCase().includes(q) ||
             (f.snippet && f.snippet.toLowerCase().includes(q));
    }
    return true;
  });

  const langColors = ['#38bdf8', '#34d399', '#f59e0b', '#ec4899', '#a78bfa', '#f87171', '#fb923c'];

  return (
    <div className="source-eval-wrap">
      {/* Risk Summary Banner */}
      <div className={`risk-banner ${risk_level.toLowerCase()}`}>
        <div className="risk-banner-left">
          <div className="risk-score-circle">
            <span className="score-num">{risk_score}</span>
            <span className="score-label">ĐIỂM RỦI RO</span>
          </div>
          <div>
            <div className="risk-header-row">
              <RiskPill level={risk_level} />
              <span className="risk-metrics-text">{total_source_files} file mã nguồn &bull; {total_lines.toLocaleString()} dòng code</span>
            </div>
            <p className="risk-summary-text">{summary}</p>
          </div>
        </div>
        <div className="sev-counters">
          <div className="sev-counter crit">
            <b>{findings_count.critical || 0}</b>
            <small>Critical</small>
          </div>
          <div className="sev-counter high">
            <b>{findings_count.high || 0}</b>
            <small>High</small>
          </div>
          <div className="sev-counter med">
            <b>{findings_count.medium || 0}</b>
            <small>Medium</small>
          </div>
          <div className="sev-counter low">
            <b>{findings_count.low || 0}</b>
            <small>Low</small>
          </div>
        </div>
      </div>

      {/* Language Breakdown */}
      {languages.length > 0 && (
        <div className="panel">
          <div className="panel-head">
            <h3>Phân bố ngôn ngữ lập trình</h3>
            <span className="muted small">{languages.length} ngôn ngữ được phát hiện</span>
          </div>
          <div className="lang-bar">
            {languages.map((l, i) => (
              <div
                key={l.name}
                className="lang-segment"
                style={{ width: `${Math.max(l.percentage, 2)}%`, backgroundColor: langColors[i % langColors.length] }}
                title={`${l.name}: ${l.percentage}% (${l.lines} dòng)`}
              />
            ))}
          </div>
          <div className="lang-legend">
            {languages.map((l, i) => (
              <div key={l.name} className="lang-item">
                <span className="lang-dot" style={{ backgroundColor: langColors[i % langColors.length] }} />
                <b>{l.name}</b>
                <span className="muted">{l.percentage}%</span>
                <small className="mono">({l.files} file, {l.lines} dòng)</small>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings Section */}
      <div className="panel">
        <div className="panel-head">
          <div>
            <h3>Chi tiết các vấn đề bảo mật ({findings.length})</h3>
            <span className="muted small">Lỗ hổng, mã độc, hàm nguy hiểm và thông tin nhạy cảm hardcoded</span>
          </div>
          <div className="filter-row">
            <div className="sev-tabs">
              <button className={sevFilter === 'ALL' ? 'active' : ''} onClick={() => setSevFilter('ALL')}>Tất cả ({findings.length})</button>
              <button className={sevFilter === 'CRITICAL' ? 'active crit' : 'crit'} onClick={() => setSevFilter('CRITICAL')}>Critical ({findings_count.critical || 0})</button>
              <button className={sevFilter === 'HIGH' ? 'active high' : 'high'} onClick={() => setSevFilter('HIGH')}>High ({findings_count.high || 0})</button>
              <button className={sevFilter === 'MEDIUM' ? 'active med' : 'med'} onClick={() => setSevFilter('MEDIUM')}>Medium ({findings_count.medium || 0})</button>
              <button className={sevFilter === 'LOW' ? 'active low' : 'low'} onClick={() => setSevFilter('LOW')}>Low ({findings_count.low || 0})</button>
            </div>
            <div className="search small-search">
              <Search size={14} />
              <input placeholder="Tìm theo file, quy tắc..." value={query} onChange={e => setQuery(e.target.value)} />
            </div>
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div className="empty-box">
            <CheckCircle2 size={32} className="green" />
            <p>Không tìm thấy vấn đề bảo mật nào phù hợp bộ lọc.</p>
          </div>
        ) : (
          <div className="findings-list">
            {filteredFindings.map((f, i) => {
              const isCrit = f.severity === 'CRITICAL';
              const isWarn = f.severity === 'HIGH' || f.severity === 'MEDIUM';
              return (
                <div key={i} className={`finding-card ${f.severity.toLowerCase()} ${isCrit ? 'is-critical-bold' : isWarn ? 'is-warning-bold' : ''}`}>
                  <div className="finding-top">
                    {isCrit && <ShieldAlert size={16} className="crit-icon" />}
                    {isWarn && <AlertTriangle size={15} className="warn-icon" />}
                    <span className={`pill sev-pill ${f.severity.toLowerCase()}`}>
                      <strong>{f.severity}</strong>
                    </span>
                    <span className="category-tag">{f.category}</span>
                    <strong className={`finding-title ${isCrit || isWarn ? 'bold-text' : ''}`}>{f.title}</strong>
                    <span className="finding-loc mono">{f.file}:{f.line}</span>
                  </div>
                  <p className="finding-desc">{f.description}</p>
                  {f.snippet && (
                    <div className={`finding-snippet ${isCrit ? 'snippet-critical' : isWarn ? 'snippet-warning' : ''}`}>
                      <span className="line-num">{f.line}</span>
                      <code className={isCrit || isWarn ? 'bold-code' : ''}>
                        {isCrit || isWarn ? <strong>{f.snippet}</strong> : f.snippet}
                      </code>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function ArchiveView({ archive }) {
  const [query, setQuery] = useState('');
  const [catFilter, setCatFilter] = useState('ALL');

  if (!archive) return null;

  const {
    archive_type = 'zip',
    total_files = 0,
    uncompressed_size = 0,
    warning = null,
    files = []
  } = archive;

  const filteredFiles = files.filter(f => {
    if (catFilter !== 'ALL' && f.category !== catFilter) return false;
    if (query) {
      return f.path.toLowerCase().includes(query.toLowerCase());
    }
    return true;
  });

  return (
    <div className="archive-wrap">
      <div className="archive-stats-bar">
        <div className="panel stat-item">
          <small>ĐỊNH DẠNG NÉN</small>
          <strong>{archive_type.toUpperCase()}</strong>
        </div>
        <div className="panel stat-item">
          <small>TỔNG SỐ TỆP TIN</small>
          <strong>{total_files.toLocaleString()} files</strong>
        </div>
        <div className="panel stat-item">
          <small>DUNG LƯỢNG GIẢI NÉN</small>
          <strong>{fmt(uncompressed_size)}</strong>
        </div>
      </div>

      {warning && (
        <div className="notice warning-notice bold-notice">
          <AlertTriangle size={18} />
          <strong className="bold-text">[WARNING] {warning}</strong>
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <div>
            <h3>Danh sách tệp tin bên trong tệp nén ({files.length})</h3>
            <span className="muted small">Tự động phân loại và quét nhị phân DIE cho các file thực thi</span>
          </div>
          <div className="filter-row">
            <div className="sev-tabs">
              {['ALL', 'source', 'binary', 'document', 'other'].map(c => (
                <button
                  key={c}
                  className={catFilter === c ? 'active' : ''}
                  onClick={() => setCatFilter(c)}
                >
                  {c === 'ALL' ? 'Tất cả' : c.toUpperCase()} ({c === 'ALL' ? files.length : files.filter(x => x.category === c).length})
                </button>
              ))}
            </div>
            <div className="search small-search">
              <Search size={14} />
              <input placeholder="Lọc theo tên file..." value={query} onChange={e => setQuery(e.target.value)} />
            </div>
          </div>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ĐƯỜNG DẪN TỆP</th>
                <th>LOẠI</th>
                <th>DUNG LƯỢNG</th>
                <th>DETECT IT EASY PHÁT HIỆN</th>
              </tr>
            </thead>
            <tbody>
              {filteredFiles.map((f, i) => (
                <tr key={i}>
                  <td className="mono file-path-cell">
                    <span className="file-icon-small">
                      {f.category === 'source' ? <FileCode size={14}/> : f.category === 'binary' ? <Terminal size={14}/> : <Files size={14}/>}
                    </span>
                    {f.path}
                  </td>
                  <td>
                    <span className={`pill cat-pill ${f.category}`}>{f.category}</span>
                  </td>
                  <td>{fmt(f.size)}</td>
                  <td>
                    {f.die_detects && f.die_detects.length > 0 ? (
                      <div className="die-mini-tags">
                        {f.die_detects.map((d, di) => (
                          <span key={di} className="pill die-tag">
                            {d.filetype || ''} {d.values?.[0]?.name ? `· ${d.values[0].name}` : ''}
                          </span>
                        ))}
                      </div>
                    ) : f.category === 'binary' ? (
                      <span className="muted small">Không khớp chữ ký</span>
                    ) : (
                      <span className="muted small">—</span>
                    )}
                  </td>
                </tr>
              ))}
              {!filteredFiles.length && (
                <tr>
                  <td colSpan="4" className="empty">Không tìm thấy tệp nào phù hợp.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function DieDetectionView({ dieData }) {
  const detects = dieData?.detects || (Array.isArray(dieData) ? dieData : []);

  if (!detects || detects.length === 0) {
    return (
      <div className="panel">
        <div className="empty-box">
          <FileSearch size={32} className="amber" />
          <p>Không phát hiện cấu trúc nhị phân đặc thù (PE, ELF, DEX, APK, v.v.).</p>
        </div>
      </div>
    );
  }

  return (
    <div className="die-view-grid">
      {detects.map((d, i) => (
        <div key={i} className="panel die-card">
          <div className="panel-head">
            <div>
              <span className="eyebrow">FILE TYPE</span>
              <h3>{d.filetype || 'Unknown'}</h3>
            </div>
            {d.size && <span className="pill">{fmt(parseInt(d.size))}</span>}
          </div>

          <div className="detect-values-list">
            {(d.values || []).map((val, vi) => (
              <div key={vi} className="detect-val-row">
                <span className={`pill val-type ${val.type || 'info'}`}>{val.type || 'detection'}</span>
                <div className="val-text">
                  <strong>{val.name || val.string}</strong>
                  {val.version && <span className="val-ver">v{val.version}</span>}
                  {val.info && <small className="val-info muted">{val.info}</small>}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [me, setMe] = useState(null), [scans, setScans] = useState([]), [selected, setSelected] = useState(null);
  const [files, setFiles] = useState([]), [query, setQuery] = useState(''), [tab, setTab] = useState('overview');
  const [users, setUsers] = useState([]), [busy, setBusy] = useState(false), [notice, setNotice] = useState('');
  const [detailSubtab, setDetailSubtab] = useState('die');
  const [settings, setSettings] = useState({ max_upload_mb: 250, upload_path: '/data/uploads' });
  const [uploadMbInput, setUploadMbInput] = useState(250);
  const [userFilter, setUserFilter] = useState(null);
  const [selectedScanIds, setSelectedScanIds] = useState(new Set());
  const [storageStats, setStorageStats] = useState(null);
  const [editingUserId, setEditingUserId] = useState(null);
  const [editingLimitVal, setEditingLimitVal] = useState('');
  const [savingLimit, setSavingLimit] = useState(false);
  const [resetPassUserId, setResetPassUserId] = useState(null);
  const [resetPassVal, setResetPassVal] = useState('');
  const [showResetPass, setShowResetPass] = useState(false);
  const [resettingPass, setResettingPass] = useState(false);
  const [confirmDeleteUserId, setConfirmDeleteUserId] = useState(null);
  const [deletingUser, setDeletingUser] = useState(false);
  const [logs, setLogs] = useState([]);
  const [loginSummary, setLoginSummary] = useState(null);
  const [logFilterUser, setLogFilterUser] = useState('');
  const [logFilterAction, setLogFilterAction] = useState('');
  const [logFilterStatus, setLogFilterStatus] = useState('');
  const [logFilterDays, setLogFilterDays] = useState('');
  const [logQuery, setLogQuery] = useState('');
  const [logsLoading, setLogsLoading] = useState(false);

  useEffect(() => {
    if (token) {
      api.defaults.headers.common.Authorization = `Bearer ${token}`;
      api.get('/auth/me').then(r => setMe(r.data)).catch(logout);
    }
  }, [token]);

  const hasActiveScans = useMemo(
    () => scans.some(x => ['queued', 'running'].includes(x.status)),
    [scans]
  );

  useEffect(() => {
    if (me) {
      refresh(false);
      api.get('/settings').then(r => {
        setSettings(r.data);
        setUploadMbInput(r.data.max_upload_mb);
      }).catch(() => {});
      if (me.role === 'admin') {
        api.get('/users').then(r => setUsers(r.data)).catch(() => {});
        fetchStorageStats();
      }
    }
  }, [me]);

  useEffect(() => {
    if (!me) return;
    const intervalMs = hasActiveScans ? 4000 : 30000;
    const t = setInterval(() => {
      if (!document.hidden) refresh(true);
    }, intervalMs);
    return () => clearInterval(t);
  }, [me, hasActiveScans, userFilter, query, selected?.id]);

  useEffect(() => {
    if (me) refresh(false);
  }, [userFilter, query]);

  useEffect(() => {
    if (selected?.result) {
      const res = selected.result;
      if (res.source_evaluation?.is_source_project) {
        setDetailSubtab('source');
      } else if (res.archive?.is_archive) {
        setDetailSubtab('archive');
      } else {
        setDetailSubtab('die');
      }
    }
  }, [selected?.id]);

  function logout() {
    if (localStorage.getItem('token')) {
      api.post('/auth/logout').catch(() => {});
    }
    localStorage.removeItem('token');
    setToken(null);
    setMe(null);
    setScans([]);
    setSelectedScanIds(new Set());
    delete api.defaults.headers.common.Authorization;
  }

  async function fetchLogs(categoryOverride = null) {
    if (!me || me.role !== 'admin') return;
    setLogsLoading(true);
    try {
      const params = { limit: 300 };
      const cat = categoryOverride !== null ? categoryOverride : (tab === 'logins' ? 'auth' : undefined);
      if (cat) params.category = cat;
      if (logFilterUser) params.user_id = parseInt(logFilterUser, 10);
      if (logFilterAction) params.action = logFilterAction;
      if (logFilterStatus) params.status = logFilterStatus;
      if (logFilterDays) params.days = parseInt(logFilterDays, 10);
      if (logQuery.trim()) params.q = logQuery.trim();
      const { data } = await api.get('/admin/logs', { params });
      setLogs(data);
    } catch {
      setNotice('Không thể tải dữ liệu nhật ký.');
    } finally {
      setLogsLoading(false);
    }
  }

  async function fetchLoginSummary() {
    if (!me || me.role !== 'admin') return;
    try {
      const { data } = await api.get('/admin/logs/summary');
      setLoginSummary(data);
    } catch {}
  }

  async function openLogins() {
    setTab('logins');
    setSelected(null);
    setLogFilterAction('');
    setLogFilterStatus('');
    setLogFilterUser('');
    setLogFilterDays('');
    setLogQuery('');
    await Promise.all([fetchLoginSummary(), fetchLogs('auth')]);
  }

  async function openLogs() {
    setTab('logs');
    setSelected(null);
    setLogFilterAction('');
    setLogFilterStatus('');
    setLogFilterUser('');
    setLogFilterDays('');
    setLogQuery('');
    await fetchLogs('');
  }

  async function exportLogs(format = 'csv', category = null) {
    try {
      setNotice(`Đang xuất tệp nhật ký (${format.toUpperCase()})...`);
      const params = { format };
      if (category) params.category = category;
      if (logFilterUser) params.user_id = parseInt(logFilterUser, 10);
      if (logFilterAction) params.action = logFilterAction;
      if (logFilterStatus) params.status = logFilterStatus;
      if (logFilterDays) params.days = parseInt(logFilterDays, 10);
      if (logQuery.trim()) params.q = logQuery.trim();
      const resp = await api.get('/admin/logs/export', { params, responseType: 'blob' });
      const blob = new Blob([resp.data], { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const prefix = category === 'auth' ? 'login-logs' : 'activity-logs';
      a.download = `${prefix}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setNotice(`Đã xuất nhật ký ${format.toUpperCase()} thành công!`);
    } catch (err) {
      setNotice('Xuất nhật ký thất bại: ' + (err.response?.data?.detail || err.message));
    }
  }

  async function clearOldLogs(days = 30, category = null) {
    const msg = days
      ? `Xóa toàn bộ nhật ký cũ hơn ${days} ngày?`
      : 'Xóa toàn bộ nhật ký đang hiển thị? Thao tác này không thể hoàn tác.';
    if (!window.confirm(msg)) return;
    try {
      const params = {};
      if (days) params.days = days;
      if (category) params.category = category;
      const { data } = await api.delete('/admin/logs', { params });
      setNotice(`Đã dọn dẹp ${data.deleted_count} bản ghi nhật ký.`);
      if (tab === 'logins') {
        fetchLoginSummary();
        fetchLogs('auth');
      } else {
        fetchLogs('');
      }
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Không thể xóa nhật ký.');
    }
  }

  useEffect(() => {
    if (me?.role === 'admin' && (tab === 'logins' || tab === 'logs')) {
      fetchLogs(tab === 'logins' ? 'auth' : '');
    }
  }, [logFilterUser, logFilterAction, logFilterStatus, logFilterDays, logQuery]);

  async function fetchStorageStats() {
    try {
      const { data } = await api.get('/admin/storage-stats');
      setStorageStats(data);
    } catch {}
  }

  async function refresh(isPoll = false) {
    try {
      const params = { limit: 300, q: query || undefined };
      if (userFilter != null) params.user_id = userFilter;
      if (isPoll) params.poll = 1;
      const { data } = await api.get('/scans', { params });
      setScans(data);
      if (selected) {
        const fresh = data.find(x => x.id === selected.id);
        if (fresh) setSelected(fresh);
      }
    } catch {}
  }

  async function deleteScan(id, e) {
    if (e) e.stopPropagation();
    if (!window.confirm('Bạn có chắc chắn muốn xóa tệp tin này và giải phóng dung lượng đĩa? Thao tác này không thể hoàn tác.')) return;
    try {
      await api.delete(`/scans/${id}`);
      setNotice('Đã xóa tệp tin thành công khỏi hệ thống.');
      if (selected?.id === id) setSelected(null);
      setSelectedScanIds(prev => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      refresh();
      fetchStorageStats();
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Xóa tệp tin thất bại.');
    }
  }

  async function deleteBatchScans(ids) {
    if (!ids || !ids.length) return;
    if (!window.confirm(`Bạn có chắc chắn muốn xóa ${ids.length} tệp tin đã chọn khỏi hệ thống? Dung lượng lưu trữ trên đĩa sẽ được giải phóng ngay lập tức.`)) return;
    try {
      const { data } = await api.post('/scans/delete-batch', { scan_ids: ids });
      setNotice(`Đã xóa thành công ${data.deleted_count} tệp tin (${fmt(data.freed_bytes)} dung lượng đĩa đã được giải phóng).`);
      setSelectedScanIds(new Set());
      if (selected && ids.includes(selected.id)) setSelected(null);
      refresh();
      fetchStorageStats();
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Xóa hàng loạt thất bại.');
    }
  }

  async function runCleanup(mode, days = null, userId = null) {
    let msg = 'Bạn có chắc chắn muốn thực hiện dọn dẹp hệ thống?';
    if (mode === 'failed') msg = 'Xóa toàn bộ các mẫu quét bị lỗi (Failed scans)?';
    if (mode === 'older_than') msg = `Xóa toàn bộ các tệp tin cũ hơn ${days} ngày?`;
    if (mode === 'user') msg = `Xóa toàn bộ các tệp tin của người dùng này?`;
    if (mode === 'orphans') msg = 'Dọn dẹp các tệp rác mồ côi (không có trong cơ sở dữ liệu) khỏi đĩa máy chủ?';
    if (mode === 'all') msg = 'CẢNH BÁO NGUY HIỂM: Thao tác này sẽ xóa SẠCH TOÀN BỘ các tệp tin và lịch sử quét trên hệ thống! Bạn có chắc chắn?';
    if (!window.confirm(msg)) return;

    try {
      const { data } = await api.post('/admin/cleanup', { mode, days, user_id: userId });
      setNotice(`Dọn dẹp hoàn tất: Đã xóa ${data.deleted_count} mẫu quét (${fmt(data.freed_bytes)} giải phóng)${data.orphans_deleted ? `, ${data.orphans_deleted} tệp rác mồ côi` : ''}.`);
      setSelected(null);
      setSelectedScanIds(new Set());
      refresh();
      fetchStorageStats();
      if (tab === 'users') openUsers();
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Dọn dẹp thất bại.');
    }
  }

  async function downloadPdf(scanId, scanName) {
    try {
      setNotice('Đang xuất bản báo cáo PDF...');
      const response = await api.get(`/scans/${scanId}/pdf`, { responseType: 'blob' });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const safeName = (scanName || 'scan').replace(/[^a-zA-Z0-9._-]/g, '_');
      a.download = `DIE-Report-${scanId}-${safeName}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setNotice('Đã xuất báo cáo PDF thành công!');
    } catch (err) {
      setNotice('Xuất báo cáo PDF thất bại: ' + (err.response?.data?.detail || err.message));
    }
  }

  async function upload(e) {
    e.preventDefault();
    if (!files.length) return;
    setBusy(true); setNotice('');
    try {
      const body = new FormData();
      files.forEach(f => body.append('files', f));
      await api.post('/scans', body, { headers: { 'Content-Type': 'multipart/form-data' } });
      setFiles([]);
      const input = document.getElementById('file-input');
      if (input) input.value = '';
      setNotice('Tệp đã được đưa vào hàng đợi phân tích.');
      setTab('history');
      refresh();
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Tải file thất bại');
    } finally {
      setBusy(false);
    }
  }

  async function openUsers() {
    setTab('users');
    setSelected(null);
    try {
      const { data } = await api.get('/users');
      setUsers(data);
    } catch {
      setNotice('Quản lý người dùng yêu cầu quyền Administrator.');
    }
  }

  function startEditLimit(user) {
    setEditingUserId(user.id);
    setEditingLimitVal(user.max_upload_mb != null ? String(user.max_upload_mb) : '');
  }

  async function saveUserLimit(userId) {
    const trimmed = String(editingLimitVal).trim();
    const newLimit = (trimmed === '' || trimmed === '0') ? null : parseInt(trimmed, 10);
    if (newLimit !== null && (isNaN(newLimit) || newLimit <= 0 || newLimit > 10240)) {
      setNotice('Giới hạn dung lượng không hợp lệ. Vui lòng nhập số nguyên từ 1 đến 10240 MB (hoặc để trống để dùng mặc định).');
      return;
    }
    setSavingLimit(true);
    try {
      await api.put(`/users/${userId}/limit`, { max_upload_mb: newLimit });
      setNotice(`Đã cập nhật giới hạn upload thành công (${newLimit ? newLimit + ' MB' : 'Mặc định hệ thống'}).`);
      setEditingUserId(null);
      openUsers();
      if (me && me.id === userId) {
        const { data: updatedMe } = await api.get('/auth/me');
        setMe(updatedMe);
      }
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Không thể cập nhật giới hạn tải lên.');
    } finally {
      setSavingLimit(false);
    }
  }

  async function toggleUserStatus(user) {
    const nextActive = user.is_active === false;
    try {
      const { data: updatedUser } = await api.put(`/users/${user.id}/status`, { is_active: nextActive });
      setUsers(prev => prev.map(x => (x.id === user.id ? updatedUser : x)));
      setNotice(
        nextActive
          ? `Đã kích hoạt lại tài khoản "${user.username}".`
          : `Đã tạm dừng hoạt động tài khoản "${user.username}". Người dùng sẽ không thể đăng nhập hoặc thao tác.`
      );
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Không thể thay đổi trạng thái tài khoản.');
    }
  }

  async function confirmDeleteUser(userId) {
    setDeletingUser(true);
    try {
      const { data } = await api.delete(`/users/${userId}`);
      setNotice(`Đã xóa vĩnh viễn tài khoản "${data.username}" (đã dọn ${data.deleted_scans} tệp quét, giải phóng ${fmt(data.freed_bytes)}).`);
      setConfirmDeleteUserId(null);
      openUsers();
      fetchStorageStats();
      refresh(false);
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Không thể xóa tài khoản.');
    } finally {
      setDeletingUser(false);
    }
  }

  function startResetPassword(user) {
    setResetPassUserId(user.id);
    setResetPassVal('');
    setShowResetPass(false);
  }

  function generateRandomPassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
    let pwd = '';
    const array = new Uint32Array(16);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < 16; i++) {
      pwd += chars[array[i] % chars.length];
    }
    setResetPassVal(pwd);
    setShowResetPass(true);
  }

  async function saveResetPassword(userId) {
    if (!resetPassVal || resetPassVal.length < 12) {
      setNotice('Mật khẩu mới phải có ít nhất 12 ký tự.');
      return;
    }
    setResettingPass(true);
    try {
      const { data } = await api.put(`/users/${userId}/password`, { new_password: resetPassVal });
      setNotice(data.message || 'Đã đặt lại mật khẩu thành công.');
      setResetPassUserId(null);
      setResetPassVal('');
    } catch (err) {
      setNotice(err.response?.data?.detail || 'Không thể đặt lại mật khẩu.');
    } finally {
      setResettingPass(false);
    }
  }

  async function openSettings() {
    setTab('settings');
    setSelected(null);
    try {
      const { data } = await api.get('/settings');
      setSettings(data);
      setUploadMbInput(data.max_upload_mb);
      fetchStorageStats();
    } catch {
      setNotice('Không thể tải cấu hình hệ thống.');
    }
  }

  const stats = useMemo(() => ({
    total: scans.length,
    done: scans.filter(x => x.status === 'completed').length,
    queued: scans.filter(x => ['queued', 'running'].includes(x.status)).length,
    failed: scans.filter(x => x.status === 'failed').length,
    highRisk: scans.filter(x => ['CRITICAL', 'HIGH'].includes(x.result?.source_evaluation?.risk_level)).length
  }), [scans]);

  if (!token || !me) {
    return (
      <Login onLogin={u => {
        api.defaults.headers.common.Authorization = `Bearer ${localStorage.getItem('token')}`;
        setMe(u);
        setToken(localStorage.getItem('token'));
      }} />
    );
  }

  const statusIcon = s => s === 'completed'
    ? <CheckCircle2 className="green" size={15} />
    : s === 'failed'
    ? <XCircle className="red" size={15} />
    : <Clock3 className="amber" size={15} />;

  const resultObj = selected?.result || {};
  const hasArchive = !!resultObj.archive;
  const hasSource = !!resultObj.source_evaluation;
  const dieData = resultObj.die || resultObj;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon"><ShieldCheck /></div>
          <div><b>DIE Analyzer</b><small>STATIC &amp; SOURCE</small></div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <button className={tab === 'overview' ? 'nav active' : 'nav'} onClick={() => { setTab('overview'); setSelected(null); }}>
          <Activity size={17} /> Tổng quan
        </button>
        <button className={tab === 'upload' ? 'nav active' : 'nav'} onClick={() => { setTab('upload'); setSelected(null); }}>
          <UploadCloud size={17} /> Tải lên mẫu
        </button>
        <button className={tab === 'history' ? 'nav active' : 'nav'} onClick={() => { setTab('history'); setSelected(null); }}>
          <Files size={17} /> Lịch sử quét
        </button>
        {me.role === 'admin' && (
          <>
            <div className="nav-label">QUẢN TRỊ</div>
            <button className={tab === 'users' ? 'nav active' : 'nav'} onClick={openUsers}>
              <Users size={17} /> Người dùng
            </button>
            <button className={tab === 'logins' ? 'nav active' : 'nav'} onClick={openLogins}>
              <Lock size={17} /> Quản lý Đăng nhập
            </button>
            <button className={tab === 'logs' ? 'nav active' : 'nav'} onClick={openLogs}>
              <ScrollText size={17} /> Nhật ký hoạt động
            </button>
            <button className={tab === 'settings' ? 'nav active' : 'nav'} onClick={openSettings}>
              <Settings size={17} /> Cài đặt hệ thống
            </button>
          </>
        )}
        <div className="sidebar-bottom">
          <div className="user-chip">
            <div className="avatar">{me.username?.[0]?.toUpperCase()}</div>
            <div><b>{me.username}</b><small>{me.role}</small></div>
            <button title="Đăng xuất" onClick={logout}><LogOut size={16} /></button>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <div className="eyebrow">STATIC ANALYSIS / {tab.toUpperCase()}</div>
            <h2>
              {selected
                ? selected.original_name
                : ({
                    overview: 'Tổng quan hệ thống',
                    upload: 'Tải lên mẫu phân tích',
                    history: 'Lịch sử phân tích',
                    users: 'Quản lý tài khoản',
                    logins: 'Quản lý Đăng nhập & Bảo mật',
                    logs: 'Nhật ký hoạt động người dùng',
                    settings: 'Cài đặt hệ thống & Giới hạn lưu trữ'
                  }[tab] || 'Analysis')}
            </h2>
          </div>
          <div className="top-actions">
            <span className="live"><i /> HỆ THỐNG TRỰC TUYẾN</span>
            <button className="icon-btn" onClick={() => refresh(false)} title="Làm mới"><RefreshCw size={17} /></button>
          </div>
        </header>

        {notice && (
          <div className="notice">
            <span>{notice}</span>
            <button onClick={() => setNotice('')}>×</button>
          </div>
        )}

        {selected ? (
          <section className="content">
            <div className="detail-top-actions">
              <button className="back" onClick={() => setSelected(null)}>← Quay lại lịch sử</button>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                {selected.status === 'completed' && (
                  <button
                    className="primary"
                    style={{ margin: 0, padding: '7px 14px', fontSize: '13px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                    onClick={() => downloadPdf(selected.id, selected.original_name)}
                    title="Tải về báo cáo phân tích bảo mật định dạng PDF"
                  >
                    <FileText size={15} /> Xuất Báo Cáo PDF
                  </button>
                )}
                {(me.role === 'admin' || selected.user_id === me.id) && (
                  <button
                    className="btn-danger-outline"
                    onClick={() => deleteScan(selected.id)}
                    title="Xóa tệp tin này và giải phóng dung lượng đĩa"
                  >
                    <Trash2 size={14} /> Xóa tệp này khỏi hệ thống
                  </button>
                )}
              </div>
            </div>

            {/* Quick Meta Card */}
            <div className="panel meta-bar">
              <div className="meta-bar-item">
                <small>TÊN FILE</small>
                <b>{selected.original_name}</b>
              </div>
              <div className="meta-bar-item">
                <small>NGƯỜI TẢI</small>
                <b>
                  <span className="user-badge"><User size={12} /> {selected.uploader || 'Admin'}</span>
                </b>
              </div>
              <div className="meta-bar-item">
                <small>KÍCH THƯỚC</small>
                <b>{fmt(selected.size)}</b>
              </div>
              <div className="meta-bar-item">
                <small>TRẠNG THÁI</small>
                <span className={`pill ${selected.status}`}>{statusIcon(selected.status)} {selected.status}</span>
              </div>
              {hasSource && (
                <div className="meta-bar-item">
                  <small>ĐÁNH GIÁ SOURCE</small>
                  <RiskPill level={resultObj.source_evaluation.risk_level} score={resultObj.source_evaluation.risk_score} />
                </div>
              )}
              {hasArchive && (
                <div className="meta-bar-item">
                  <small>TỆP NÉN</small>
                  <span className="pill cat-pill archive">📦 {resultObj.archive.archive_type.toUpperCase()} ({resultObj.archive.total_files} files)</span>
                </div>
              )}
            </div>

            {/* Sub navigation tabs */}
            <div className="detail-subtabs">
              {hasSource && (
                <button
                  className={detailSubtab === 'source' ? 'subtab active' : 'subtab'}
                  onClick={() => setDetailSubtab('source')}
                >
                  <Code size={16} /> Đánh giá Source Code {resultObj.source_evaluation.total_findings > 0 ? `(${resultObj.source_evaluation.total_findings})` : ''}
                </button>
              )}
              {hasArchive && (
                <button
                  className={detailSubtab === 'archive' ? 'subtab active' : 'subtab'}
                  onClick={() => setDetailSubtab('archive')}
                >
                  <Archive size={16} /> Tệp nén ({resultObj.archive.total_files} tệp)
                </button>
              )}
              <button
                className={detailSubtab === 'die' ? 'subtab active' : 'subtab'}
                onClick={() => setDetailSubtab('die')}
              >
                <ShieldCheck size={16} /> Detect It Easy
              </button>
              <button
                className={detailSubtab === 'hashes' ? 'subtab active' : 'subtab'}
                onClick={() => setDetailSubtab('hashes')}
              >
                <Hash size={16} /> Hashes &amp; Thông tin
              </button>
              <button
                className={detailSubtab === 'raw' ? 'subtab active' : 'subtab'}
                onClick={() => setDetailSubtab('raw')}
              >
                <Terminal size={16} /> Raw JSON
              </button>
            </div>

            {/* Subtab Contents */}
            {selected.status !== 'completed' ? (
              <div className="panel empty-box">
                <Clock3 size={32} className="amber" />
                <p>{selected.error || 'Đang chờ worker phân tích... Trang này sẽ tự động làm mới.'}</p>
              </div>
            ) : detailSubtab === 'source' ? (
              <SourceEvaluationView evaluation={resultObj.source_evaluation} />
            ) : detailSubtab === 'archive' ? (
              <ArchiveView archive={resultObj.archive} />
            ) : detailSubtab === 'die' ? (
              <DieDetectionView dieData={dieData} />
            ) : detailSubtab === 'hashes' ? (
              <div className="panel">
                <div className="panel-head"><h3>Thông tin tệp tin &amp; Mã băm mật mã</h3><Hash size={18} /></div>
                <Info label="Tên file gốc" value={selected.original_name} />
                <Info label="Người tải lên (Uploader)" value={`${selected.uploader || 'Admin'}${selected.user_id ? ` (User ID: ${selected.user_id})` : ''}`} />
                <Info label="Dung lượng" value={fmt(selected.size)} />
                <Info label="Mã định danh (Scan ID)" value={selected.id} />
                <Info label="Thời gian tạo" value={date(selected.created_at)} />
                <Info label="Thời gian hoàn tất" value={date(selected.completed_at)} />
                <Info label="Mã băm MD5" value={selected.md5} mono />
                <Info label="Mã băm SHA-1" value={selected.sha1} mono />
                <Info label="Mã băm SHA-256" value={selected.sha256} mono />
              </div>
            ) : detailSubtab === 'raw' ? (
              <div className="panel">
                <div className="panel-head">
                  <div>
                    <span className="eyebrow">RAW INSPECTION</span>
                    <h3>Kết quả chi tiết &amp; Raw CLI Output</h3>
                  </div>
                  <Terminal size={18} />
                </div>
                {selected.raw_output && (
                  <div style={{ marginBottom: '24px' }}>
                    <div className="eyebrow" style={{ marginBottom: '8px', color: '#93c5fd' }}>
                      CLI &amp; AUDIT LOGS (CÁC DÒNG [CRITICAL] VÀ [WARNING] ĐƯỢC ĐÁNH DẤU VÀ IN ĐẬM)
                    </div>
                    <FormattedOutput text={selected.raw_output} />
                  </div>
                )}
                <div className="eyebrow" style={{ marginBottom: '8px' }}>STRUCTURED JSON DATA</div>
                <pre className="json">{JSON.stringify(resultObj, null, 2)}</pre>
              </div>
            ) : null}
          </section>
        ) : tab === 'overview' ? (
          <section className="content">
            <div className="welcome">
              <div>
                <span className="eyebrow">STATIC TRIAGE &amp; CODE AUDIT</span>
                <h1>Phân tích nhị phân &amp; Đánh giá mã nguồn.</h1>
                <p>Hỗ trợ tệp nhị phân (PE, ELF, Mach-O), các loại file nén (ZIP, RAR, TAR, GZ, BZ2, XZ) và audit bảo mật source code tự động.</p>
                <button className="primary" onClick={() => setTab('upload')}>
                  <UploadCloud size={17} /> Tải file phân tích ngay
                </button>
              </div>
              <div className="welcome-art">
                <div className="orb"><ShieldCheck size={58} /></div>
                <span className="orbit o1" /><span className="orbit o2" />
              </div>
            </div>

            <div className="stats">
              <Stat icon={<Files />} label="Tổng số mẫu" value={stats.total} color="blue" />
              <Stat icon={<CheckCircle2 />} label="Hoàn tất" value={stats.done} color="green" />
              <Stat icon={<Clock3 />} label="Đang chờ / chạy" value={stats.queued} color="amber" />
              <Stat icon={<AlertTriangle />} label="Phát hiện rủi ro cao" value={stats.highRisk} color="red" />
            </div>

            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">HOẠT ĐỘNG GẦN ĐÂY</span>
                  <h3>Mẫu phân tích mới nhất</h3>
                </div>
                <button className="text-btn" onClick={() => setTab('history')}>Xem tất cả →</button>
              </div>
              <ScanTable scans={scans.slice(0, 8)} onSelect={setSelected} statusIcon={statusIcon} onDelete={deleteScan} onExportPdf={downloadPdf} me={me} />
            </div>
          </section>
        ) : tab === 'upload' ? (
          <section className="content">
            <div className="upload-layout">
              <div className="panel upload-panel">
                <span className="eyebrow">PHÂN TÍCH MỚI</span>
                <h3>Tải lên tệp phân tích</h3>
                <p className="muted">Hỗ trợ tệp thực thi (EXE, ELF, DLL), tệp nén (ZIP, RAR, TAR, GZ, TGZ, BZ2, XZ) hoặc trực tiếp mã nguồn (PY, JS, TS, PHP, GO, SH...).</p>
                <form onSubmit={upload}>
                  <label className="dropzone">
                    <input id="file-input" type="file" multiple onChange={e => setFiles([...e.target.files])} />
                    <UploadCloud size={34} />
                    <b>Nhấp để chọn tệp tin tải lên</b>
                    <span>Hỗ trợ tải nhiều file &bull; Tối đa 30 files mỗi lượt</span>
                    <small>
                      Tối đa <b>{me?.effective_limit_mb || settings.max_upload_mb || 250} MB</b> mỗi file{' '}
                      {me?.max_upload_mb ? (
                        <span style={{ color: '#38bdf8' }}>(Hạn mức tài khoản: {me.max_upload_mb} MB)</span>
                      ) : (
                        <span style={{ color: '#94a3b8' }}>(Hạn mức mặc định)</span>
                      )}
                      {' '}&bull; Tự động giải nén &amp; audit
                    </small>
                  </label>
                  {files.length > 0 && (
                    <div className="selected-files">
                      {files.map((f, i) => (
                        <div key={i}>
                          <Files size={15} />
                          <span>{f.name}</span>
                          <small>{fmt(f.size)}</small>
                        </div>
                      ))}
                    </div>
                  )}
                  <button className="primary full" disabled={!files.length || busy}>
                    {busy ? 'Đang tải lên…' : `Đưa ${files.length || ''} tệp tin vào hàng đợi phân tích`}
                  </button>
                </form>
              </div>

              <div className="panel">
                <h3>Quy trình phân tích tự động</h3>
                <div className="step">
                  <b>01</b>
                  <div>
                    <strong>Tải lên &amp; Tính toán Hash</strong>
                    <p>File được lưu với ID duy nhất, tính toán mã băm MD5, SHA-1, SHA-256 an toàn.</p>
                  </div>
                </div>
                <div className="step">
                  <b>02</b>
                  <div>
                    <strong>Đọc file nén (Archive Explorer)</strong>
                    <p>Nếu là ZIP, RAR, TAR, GZ..., tệp sẽ được giải nén an toàn với cơ chế chống Zip-Slip &amp; Zip-Bomb.</p>
                  </div>
                </div>
                <div className="step">
                  <b>03</b>
                  <div>
                    <strong>Đánh giá Source Code</strong>
                    <p>Quét các lỗ hổng Injection, hàm thực thi nguy hiểm, Backdoor, Reverse shell và lộ lọt Secrets.</p>
                  </div>
                </div>
                <div className="step">
                  <b>04</b>
                  <div>
                    <strong>Quét Detect It Easy (DIE)</strong>
                    <p>Phát hiện trình biên dịch (compiler), packer, protector và các định dạng nhị phân.</p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        ) : tab === 'history' ? (
          <section className="content">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">CƠ SỞ DỮ LIỆU</span>
                  <h3>Lịch sử quét</h3>
                </div>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                  {me.role === 'admin' && users.length > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <User size={15} style={{ color: '#7dd3fc' }} />
                      <select
                        className="user-filter-select"
                        value={userFilter ?? ''}
                        onChange={e => setUserFilter(e.target.value ? parseInt(e.target.value, 10) : null)}
                      >
                        <option value="">Tất cả người dùng ({users.length})</option>
                        {users.map(u => (
                          <option key={u.id} value={u.id}>
                            {u.username} ({u.upload_count || 0} tệp - {fmt(u.total_upload_size || 0)})
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                  <div className="search">
                    <Search size={16} />
                    <input placeholder="Tìm theo tên file hoặc SHA-256…" value={query} onChange={e => setQuery(e.target.value)} />
                  </div>
                </div>
              </div>

              {selectedScanIds.size > 0 && (
                <div className="batch-bar">
                  <div className="batch-bar-left">
                    <CheckCircle2 size={16} className="green" />
                    <span>
                      Đã chọn <b>{selectedScanIds.size}</b> tệp tin (tổng {fmt(scans.filter(x => selectedScanIds.has(x.id)).reduce((acc, cur) => acc + (cur.size || 0), 0))})
                    </span>
                  </div>
                  <div className="batch-bar-actions">
                    <button
                      className="btn-danger"
                      onClick={() => deleteBatchScans(Array.from(selectedScanIds))}
                    >
                      <Trash2 size={14} /> Xóa {selectedScanIds.size} tệp đã chọn
                    </button>
                    <button
                      className="text-btn"
                      onClick={() => setSelectedScanIds(new Set())}
                      style={{ color: '#94a3b8' }}
                    >
                      Bỏ chọn
                    </button>
                  </div>
                </div>
              )}

              <ScanTable
                scans={scans}
                onSelect={setSelected}
                statusIcon={statusIcon}
                onDelete={deleteScan}
                onExportPdf={downloadPdf}
                selectedIds={selectedScanIds}
                onToggleSelect={id => {
                  setSelectedScanIds(prev => {
                    const next = new Set(prev);
                    if (next.has(id)) next.delete(id);
                    else next.add(id);
                    return next;
                  });
                }}
                onSelectAll={checked => {
                  if (checked) {
                    setSelectedScanIds(new Set(scans.map(s => s.id)));
                  } else {
                    setSelectedScanIds(new Set());
                  }
                }}
                me={me}
              />
            </div>
          </section>
        ) : tab === 'users' ? (
          <section className="content">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">QUẢN LÝ TRUY CẬP</span>
                  <h3>Người dùng hệ thống</h3>
                </div>
              </div>
              <form className="user-create" onSubmit={async e => {
                e.preventDefault();
                const f = new FormData(e.currentTarget);
                const limitRaw = f.get('max_upload_mb')?.trim();
                try {
                  await api.post('/users', {
                    username: f.get('username'),
                    email: f.get('email'),
                    password: f.get('password'),
                    role: f.get('role'),
                    max_upload_mb: limitRaw ? parseInt(limitRaw, 10) : null
                  });
                  setNotice('Đã tạo người dùng thành công.');
                  e.currentTarget.reset();
                  openUsers();
                } catch (err) {
                  setNotice(err.response?.data?.detail || 'Không thể tạo người dùng.');
                }
              }}>
                <input name="username" placeholder="Tên đăng nhập" required minLength="3" />
                <input name="email" type="email" placeholder="Email" required />
                <input name="password" type="password" placeholder="Mật khẩu (12+ ký tự)" required minLength="12" />
                <input name="max_upload_mb" type="number" min="1" max="10240" placeholder="Giới hạn MB (trống = mặc định)" />
                <select name="role">
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
                <button className="primary">Tạo tài khoản</button>
              </form>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>TÊN ĐĂNG NHẬP</th>
                      <th>EMAIL</th>
                      <th>VAI TRÒ</th>
                      <th>TRẠNG THÁI</th>
                      <th>GIỚI HẠN UPLOAD</th>
                      <th>NGÀY TẠO</th>
                      <th>SỐ TỆP ĐÃ TẢI LÊN</th>
                      <th>DUNG LƯỢNG ĐÃ DÙNG</th>
                      <th style={{ textAlign: 'center' }}>THAO TÁC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(u => {
                      const isActive = u.is_active !== false;
                      const isSelf = me && me.id === u.id;
                      return (
                      <React.Fragment key={u.id}>
                      <tr style={!isActive ? { opacity: 0.72, background: '#17121b' } : undefined}>
                        <td>
                          <b>
                            <span className="user-badge" style={{ fontSize: '13.5px' }}>
                              <User size={13} /> {u.username}
                            </span>
                            {u.is_active === false && (
                              <span key="paused-tag" className="pill failed" style={{ marginLeft: '6px', padding: '2px 6px', fontSize: '11px' }}>Tạm dừng</span>
                            )}
                          </b>
                        </td>
                        <td>{u.email}</td>
                        <td><span className="pill">{u.role}</span></td>
                        <td>
                          {isActive ? (
                            <span key="status-active" className="pill completed">Hoạt động</span>
                          ) : (
                            <span key="status-paused" className="pill failed">Tạm dừng</span>
                          )}
                        </td>
                        <td>
                          {editingUserId === u.id ? (
                            <div className="inline-limit-box" onClick={e => e.stopPropagation()}>
                              <input
                                type="number"
                                min="1"
                                max="10240"
                                className="inline-limit-input"
                                placeholder="Mặc định"
                                value={editingLimitVal}
                                onChange={e => setEditingLimitVal(e.target.value)}
                                onKeyDown={e => {
                                  if (e.key === 'Enter') saveUserLimit(u.id);
                                  if (e.key === 'Escape') setEditingUserId(null);
                                }}
                                autoFocus
                              />
                              <span className="inline-limit-unit">MB</span>
                              <button
                                type="button"
                                className="btn-inline-save"
                                onClick={() => saveUserLimit(u.id)}
                                disabled={savingLimit}
                                title="Lưu lại (hoặc nhấn phím Enter)"
                              >
                                <Check size={12} /> {savingLimit ? '…' : 'Lưu'}
                              </button>
                              <button
                                type="button"
                                className="btn-inline-cancel"
                                onClick={() => setEditingUserId(null)}
                                disabled={savingLimit}
                                title="Hủy bỏ (hoặc nhấn phím Esc)"
                              >
                                <X size={12} />
                              </button>
                            </div>
                          ) : (
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              {u.max_upload_mb != null ? (
                                <span className="pill" style={{ background: '#0369a1', color: '#e0f2fe', fontWeight: 600 }} title="Giới hạn upload riêng được cấu hình cho tài khoản này">
                                  {u.max_upload_mb} MB (Riêng)
                                </span>
                              ) : (
                                <span className="pill" style={{ background: '#1e293b', color: '#94a3b8' }} title="Đang áp dụng giới hạn mặc định hệ thống">
                                  {u.effective_limit_mb || settings.max_upload_mb || 250} MB (Mặc định)
                                </span>
                              )}
                              <button
                                type="button"
                                className="text-btn icon-edit-btn"
                                style={{ color: '#a78bfa', padding: '2px 5px', fontSize: '13px', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                                onClick={() => startEditLimit(u)}
                                title="Sửa giới hạn trực tiếp trên bảng"
                              >
                                <Edit2 size={11} /> Sửa
                              </button>
                            </div>
                          )}
                        </td>
                        <td>{date(u.created_at)}</td>
                        <td>
                          <span className="pill" style={{ background: '#112942', color: '#7dd3fc' }}>
                            <Files size={12} /> {u.upload_count || 0} files
                          </span>
                        </td>
                        <td><b>{fmt(u.total_upload_size || 0)}</b></td>
                        <td style={{ textAlign: 'center' }}>
                          <div style={{ display: 'inline-flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
                            {editingUserId === u.id ? (
                              <button
                                type="button"
                                className="text-btn"
                                style={{ color: '#94a3b8', fontSize: '13px' }}
                                onClick={() => setEditingUserId(null)}
                              >
                                Đang sửa…
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="text-btn"
                                style={{ color: '#a78bfa', fontSize: '13px', fontWeight: 600 }}
                                onClick={() => startEditLimit(u)}
                                title="Chỉnh sửa hạn mức tải lên trực tiếp"
                              >
                                Sửa giới hạn
                              </button>
                            )}
                            <button
                              type="button"
                              className="text-btn"
                              style={{ color: '#fbbf24', fontSize: '13px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                              onClick={() => resetPassUserId === u.id ? setResetPassUserId(null) : startResetPassword(u)}
                              title="Đặt lại mật khẩu mới trực tiếp cho người dùng này"
                            >
                              <Key size={11} /> {resetPassUserId === u.id ? 'Đóng' : 'Reset pass'}
                            </button>
                            {!isSelf && (
                              <button
                                key={isActive ? 'suspend-btn' : 'activate-btn'}
                                type="button"
                                className="text-btn"
                                style={{
                                  color: isActive ? '#fb923c' : '#4ade80',
                                  fontSize: '13px',
                                  fontWeight: 600,
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '3px'
                                }}
                                onClick={() => toggleUserStatus(u)}
                                title={isActive ? 'Tạm dừng hoạt động tài khoản này' : 'Kích hoạt lại tài khoản này'}
                              >
                                {isActive ? <PauseCircle size={11} /> : <PlayCircle size={11} />}
                                <span>{isActive ? 'Tạm dừng' : 'Kích hoạt'}</span>
                              </button>
                            )}
                            <button
                              className="text-btn"
                              style={{ color: '#38bdf8', fontSize: '13px', fontWeight: 600 }}
                              onClick={() => {
                                setUserFilter(u.id);
                                setTab('history');
                              }}
                              title="Lọc và xem tất cả file do người dùng này tải lên"
                            >
                              Xem files →
                            </button>
                            {(u.upload_count > 0) && (
                              <button
                                className="text-btn"
                                style={{ color: '#f87171', fontSize: '13px', fontWeight: 600 }}
                                onClick={() => runCleanup('user', null, u.id)}
                                title="Xóa toàn bộ các tệp tin của người dùng này"
                              >
                                Dọn dẹp files
                              </button>
                            )}
                            {!isSelf && (
                              <button
                                type="button"
                                className="text-btn"
                                style={{ color: '#ef4444', fontSize: '13px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                                onClick={() => setConfirmDeleteUserId(confirmDeleteUserId === u.id ? null : u.id)}
                                title="Xóa vĩnh viễn tài khoản người dùng này"
                              >
                                <Trash2 size={11} /> Xóa
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                      {confirmDeleteUserId === u.id && (
                        <tr className="inline-delete-row">
                          <td colSpan="9">
                            <div className="inline-reset-panel">
                              <span className="inline-reset-label" style={{ color: '#fca5a5' }}>
                                <AlertTriangle size={14} className="red" />
                                Xác nhận xóa vĩnh viễn tài khoản <b>{u.username}</b> ({u.upload_count || 0} tệp tin sẽ bị xóa khỏi đĩa)?
                              </span>
                              <button
                                type="button"
                                className="btn-danger"
                                style={{ padding: '4px 10px', fontSize: '13px' }}
                                onClick={() => confirmDeleteUser(u.id)}
                                disabled={deletingUser}
                              >
                                <Trash2 size={12} /> {deletingUser ? 'Đang xóa…' : 'Xác nhận xóa'}
                              </button>
                              <button
                                type="button"
                                className="btn-inline-cancel"
                                onClick={() => setConfirmDeleteUserId(null)}
                                disabled={deletingUser}
                              >
                                <X size={12} /> Hủy
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                      {resetPassUserId === u.id && (
                        <tr className="inline-reset-row">
                          <td colSpan="9">
                            <div className="inline-reset-panel">
                              <span className="inline-reset-label">
                                <Key size={13} className="amber" /> Đặt lại mật khẩu cho <b>{u.username}</b>:
                              </span>
                              <div className="inline-pass-input-wrap">
                                <input
                                  type={showResetPass ? 'text' : 'password'}
                                  minLength="12"
                                  className="inline-pass-input"
                                  placeholder="Nhập mật khẩu mới (tối thiểu 12 ký tự)…"
                                  value={resetPassVal}
                                  onChange={e => setResetPassVal(e.target.value)}
                                  onKeyDown={e => {
                                    if (e.key === 'Enter') saveResetPassword(u.id);
                                    if (e.key === 'Escape') setResetPassUserId(null);
                                  }}
                                  autoFocus
                                />
                                <button
                                  type="button"
                                  className="inline-icon-toggle"
                                  onClick={() => setShowResetPass(v => !v)}
                                  title={showResetPass ? 'Ẩn mật khẩu' : 'Hiện mật khẩu'}
                                >
                                  {showResetPass ? <EyeOff size={13} /> : <Eye size={13} />}
                                </button>
                              </div>
                              <button
                                type="button"
                                className="btn-inline-gen"
                                onClick={generateRandomPassword}
                                title="Tạo mật khẩu mạnh ngẫu nhiên 16 ký tự"
                              >
                                <RefreshCw size={11} /> Tạo ngẫu nhiên
                              </button>
                              {resetPassVal && (
                                <button
                                  type="button"
                                  className="btn-inline-copy"
                                  onClick={() => {
                                    navigator.clipboard?.writeText(resetPassVal);
                                    setNotice('Đã sao chép mật khẩu mới vào clipboard.');
                                  }}
                                  title="Sao chép mật khẩu"
                                >
                                  <Copy size={11} /> Copy
                                </button>
                              )}
                              <button
                                type="button"
                                className="btn-inline-save"
                                onClick={() => saveResetPassword(u.id)}
                                disabled={resettingPass || resetPassVal.length < 12}
                                title="Lưu mật khẩu mới (Enter)"
                              >
                                <Check size={12} /> {resettingPass ? 'Đang lưu…' : 'Lưu mật khẩu'}
                              </button>
                              <button
                                type="button"
                                className="btn-inline-cancel"
                                onClick={() => setResetPassUserId(null)}
                                disabled={resettingPass}
                                title="Hủy bỏ (Esc)"
                              >
                                <X size={12} /> Hủy
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                      </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        ) : tab === 'settings' ? (
          <section className="content">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">QUẢN TRỊ HỆ THỐNG</span>
                  <h3>Cấu hình lưu trữ &amp; Giới hạn tải lên</h3>
                </div>
                <Settings size={22} className="amber" />
              </div>

              <div className="settings-section">
                <h4>1. Giới hạn dung lượng tải lên (Upload Size Limit)</h4>
                <p className="muted small">
                  Chỉ Quản trị viên (Admin) mới có quyền tùy chỉnh giới hạn này. Cấu hình sẽ được lưu vào cơ sở dữ liệu và có hiệu lực ngay lập tức cho toàn bộ người dùng khi tải file lên hệ thống.
                </p>

                <form onSubmit={async e => {
                  e.preventDefault();
                  try {
                    const val = parseInt(uploadMbInput, 10);
                    if (isNaN(val) || val < 1 || val > 2048) {
                      setNotice('Dung lượng phải từ 1 MB đến 2048 MB.');
                      return;
                    }
                    const { data } = await api.put('/settings', { max_upload_mb: val });
                    setSettings(data);
                    setNotice(`Đã cập nhật giới hạn upload thành công: ${data.max_upload_mb} MB.`);
                  } catch (err) {
                    setNotice(err.response?.data?.detail || 'Lưu cài đặt thất bại.');
                  }
                }} className="settings-form">
                  <div className="form-group">
                    <label>Dung lượng tối đa cho phép mỗi file (MB):</label>
                    <div className="input-with-action">
                      <input
                        type="number"
                        min="1"
                        max="2048"
                        value={uploadMbInput}
                        onChange={e => setUploadMbInput(e.target.value)}
                        required
                      />
                      <span className="unit">MB</span>
                      <button className="primary" style={{ margin: 0 }}>Lưu giới hạn</button>
                    </div>
                  </div>

                  <div className="presets-row">
                    <span className="muted small">Chọn nhanh:</span>
                    {[50, 100, 250, 500, 1000].map(p => (
                      <button
                        key={p}
                        type="button"
                        className={`pill preset-btn ${parseInt(uploadMbInput, 10) === p ? 'active' : ''}`}
                        onClick={() => setUploadMbInput(p)}
                      >
                        {p} MB
                      </button>
                    ))}
                  </div>
                </form>
              </div>

              <div className="settings-section" style={{ marginTop: '28px', borderTop: '1px solid #1f334d', paddingTop: '20px' }}>
                <h4>2. Vị trí &amp; Đường dẫn lưu trữ tệp tin (Storage Path)</h4>
                <p className="muted small">
                  Tệp tin tải lên được lưu trữ trực tiếp vào thư mục trên máy host (được bind mount đồng bộ vào container API và Worker để quét an toàn):
                </p>
                <div className="storage-info-grid">
                  <div className="storage-box">
                    <small>THƯ MỤC TRÊN MÁY HOST</small>
                    <b className="mono">./data/uploads</b>
                    <span className="muted small">(Cấu hình qua biến UPLOAD_PATH trong .env)</span>
                  </div>
                  <div className="storage-box">
                    <small>ĐƯỜNG DẪN CONTAINER MOUNT</small>
                    <b className="mono">{settings.upload_path}</b>
                    <span className="pill green-pill">Đã mount &amp; Sẵn sàng</span>
                  </div>
                </div>
              </div>

              <div className="settings-section" style={{ marginTop: '28px', borderTop: '1px solid #1f334d', paddingTop: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <h4>3. Quản lý dung lượng &amp; Dọn dẹp tệp tin tải lên (Storage &amp; File Cleanup)</h4>
                    <p className="muted small">
                      Quản trị viên có toàn quyền xóa dọn dẹp các tệp tin đã tải lên hệ thống để giải phóng dung lượng đĩa lưu trữ theo ý muốn.
                    </p>
                  </div>
                  <button className="text-btn" onClick={fetchStorageStats} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <RefreshCw size={14} /> Làm mới thống kê
                  </button>
                </div>

                {storageStats && (
                  <div className="storage-info-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', marginTop: '14px' }}>
                    <div className="storage-box">
                      <small>TỔNG SỐ MẪU QUÉT</small>
                      <b style={{ fontSize: '20px', color: '#38bdf8' }}>{storageStats.total_scans}</b>
                      <span className="muted small">Trong cơ sở dữ liệu</span>
                    </div>
                    <div className="storage-box">
                      <small>DUNG LƯỢNG TRONG DB</small>
                      <b style={{ fontSize: '20px', color: '#4ade80' }}>{fmt(storageStats.total_db_size)}</b>
                      <span className="muted small">Tổng kích thước mẫu</span>
                    </div>
                    <div className="storage-box">
                      <small>TỆP TRÊN ĐĨA MÁY CHỦ</small>
                      <b style={{ fontSize: '20px', color: '#facc15' }}>{storageStats.disk_files_count} files</b>
                      <span className="muted small">Thực tế: {fmt(storageStats.disk_used_bytes)}</span>
                    </div>
                    <div className="storage-box">
                      <small>TỆP RÁC MỒ CÔI (ORPHANS)</small>
                      <b style={{ fontSize: '20px', color: storageStats.orphan_files_count > 0 ? '#f87171' : '#94a3b8' }}>
                        {storageStats.orphan_files_count} files
                      </b>
                      <span className="muted small">Không thuộc mẫu nào</span>
                    </div>
                  </div>
                )}

                <div className="cleanup-grid">
                  <div className="cleanup-card">
                    <div>
                      <h5><XCircle size={16} className="red" /> Dọn dẹp mẫu lỗi (Failed)</h5>
                      <p>Xóa tất cả các mẫu phân tích bị lỗi kỹ thuật hoặc hết thời gian chờ để làm sạch danh sách và bộ nhớ.</p>
                    </div>
                    <button className="cleanup-btn amber" onClick={() => runCleanup('failed')}>
                      <Trash2 size={14} /> Xóa các mẫu lỗi
                    </button>
                  </div>

                  <div className="cleanup-card">
                    <div>
                      <h5><Clock3 size={16} className="amber" /> Dọn dẹp tệp cũ hơn 7 ngày</h5>
                      <p>Tự động tìm và xóa tất cả các tệp tin đã tải lên từ hơn 7 ngày trước để giải phóng dung lượng định kỳ.</p>
                    </div>
                    <button className="cleanup-btn amber" onClick={() => runCleanup('older_than', 7)}>
                      <Trash2 size={14} /> Xóa tệp &gt; 7 ngày
                    </button>
                  </div>

                  <div className="cleanup-card">
                    <div>
                      <h5><Clock3 size={16} className="amber" /> Dọn dẹp tệp cũ hơn 30 ngày</h5>
                      <p>Xóa toàn bộ các tệp tin lưu trữ và kết quả phân tích cũ hơn 30 ngày khỏi máy chủ.</p>
                    </div>
                    <button className="cleanup-btn amber" onClick={() => runCleanup('older_than', 30)}>
                      <Trash2 size={14} /> Xóa tệp &gt; 30 ngày
                    </button>
                  </div>

                  <div className="cleanup-card">
                    <div>
                      <h5><FolderX size={16} className="blue" /> Quét dọn tệp rác mồ côi</h5>
                      <p>Quét thư mục upload máy chủ và dọn dẹp các tệp không còn bản ghi trong cơ sở dữ liệu.</p>
                    </div>
                    <button className="cleanup-btn blue" onClick={() => runCleanup('orphans')}>
                      <FolderX size={14} /> Dọn tệp mồ côi
                    </button>
                  </div>

                  <div className="cleanup-card" style={{ gridColumn: '1 / -1', borderColor: '#5e1b24', background: '#160b10' }}>
                    <div>
                      <h5 style={{ color: '#f87171' }}><AlertTriangle size={16} className="red" /> Xóa toàn bộ tệp tin (Storage Reset)</h5>
                      <p style={{ color: '#fca5a5' }}>
                        CẢNH BÁO NGUY HIỂM: Thao tác này sẽ xóa sạch toàn bộ các tệp đã tải lên và toàn bộ lịch sử quét trong cơ sở dữ liệu.
                      </p>
                    </div>
                    <button className="cleanup-btn red" onClick={() => runCleanup('all')}>
                      <Trash2 size={14} /> Xóa sạch toàn bộ tệp tin &amp; Dữ liệu
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </section>
        ) : tab === 'logins' ? (
          <section className="content">
            <div className="stats">
              <Stat icon={<CheckCircle2 />} label="Đăng nhập thành công (24h)" value={loginSummary?.login_success_24h ?? 0} color="green" />
              <Stat icon={<ShieldAlert />} label="Đăng nhập thất bại (24h)" value={loginSummary?.login_failed_24h ?? 0} color="red" />
              <Stat icon={<Users />} label="Tài khoản hoạt động (24h)" value={loginSummary?.active_users_24h ?? 0} color="blue" />
              <Stat icon={<Lock />} label="Tổng lượt đăng nhập" value={loginSummary?.total_logins ?? 0} color="amber" />
            </div>

            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">PHIÊN TRUY CẬP TÀI KHOẢN</span>
                  <h3>Tình trạng đăng nhập theo người dùng</h3>
                </div>
                <button className="icon-btn" onClick={() => { fetchLoginSummary(); fetchLogs('auth'); }} title="Làm mới dữ liệu">
                  <RefreshCw size={16} />
                </button>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>TÀI KHOẢN</th>
                      <th>VAI TRÒ</th>
                      <th>ĐĂNG NHẬP GẦN NHẤT</th>
                      <th>ĐỊA CHỈ IP GẦN NHẤT</th>
                      <th>THIẾT BỊ / TRÌNH DUYỆT</th>
                      <th>THÀNH CÔNG</th>
                      <th>THẤT BẠI</th>
                      <th style={{ textAlign: 'center' }}>THAO TÁC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(loginSummary?.user_sessions || []).map(u => (
                      <tr key={u.id}>
                        <td>
                          <b>
                            <span className="user-badge" style={{ fontSize: '13.5px' }}>
                              <User size={13} /> {u.username}
                            </span>
                            {u.is_active === false && (
                              <span className="pill failed" style={{ marginLeft: '6px', padding: '2px 6px', fontSize: '11px' }}>Tạm dừng</span>
                            )}
                          </b>
                        </td>
                        <td><span className="pill">{u.role}</span></td>
                        <td>{u.last_login_at ? date(u.last_login_at) : <span className="muted">Chưa đăng nhập</span>}</td>
                        <td className="mono">{u.last_login_ip || '—'}</td>
                        <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={u.last_login_ua || ''}>
                          <span className="muted small">{u.last_login_ua || '—'}</span>
                        </td>
                        <td>
                          <span className="pill completed">{u.login_count} lần</span>
                        </td>
                        <td>
                          {u.failed_count > 0 ? (
                            <span className="pill failed"><b>{u.failed_count} lần</b></span>
                          ) : (
                            <span className="muted">0</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <div style={{ display: 'inline-flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
                            <button
                              className="text-btn"
                              style={{ color: '#38bdf8', fontSize: '13px', fontWeight: 600 }}
                              onClick={() => setLogFilterUser(String(u.id))}
                            >
                              Lọc log login
                            </button>
                            <button
                              className="text-btn"
                              style={{ color: '#fbbf24', fontSize: '13px', fontWeight: 600 }}
                              onClick={() => { openUsers(); startResetPassword(u); }}
                            >
                              Reset pass
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">LỊCH SỬ XÁC THỰC (AUTH AUDIT)</span>
                  <h3>Chi tiết đăng nhập &amp; đăng xuất ({logs.length})</h3>
                </div>
                <div className="audit-actions">
                  <button className="btn-export csv" onClick={() => exportLogs('csv', 'auth')}>
                    <Download size={14} /> Xuất CSV
                  </button>
                  <button className="btn-export json" onClick={() => exportLogs('json', 'auth')}>
                    <Download size={14} /> Xuất JSON
                  </button>
                  <button className="btn-danger-outline" onClick={() => clearOldLogs(30, 'auth')}>
                    <Trash2 size={13} /> Xóa log &gt; 30 ngày
                  </button>
                </div>
              </div>

              <div className="audit-filter-bar">
                <select className="user-filter-select" value={logFilterUser} onChange={e => setLogFilterUser(e.target.value)}>
                  <option value="">Tất cả tài khoản</option>
                  {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
                <select className="user-filter-select" value={logFilterAction} onChange={e => setLogFilterAction(e.target.value)}>
                  <option value="">Tất cả sự kiện Login</option>
                  <option value="LOGIN_SUCCESS">Đăng nhập thành công</option>
                  <option value="LOGIN_FAILED">Đăng nhập thất bại</option>
                  <option value="LOGOUT">Đăng xuất</option>
                </select>
                <select className="user-filter-select" value={logFilterStatus} onChange={e => setLogFilterStatus(e.target.value)}>
                  <option value="">Mọi trạng thái</option>
                  <option value="success">Thành công</option>
                  <option value="failed">Thất bại</option>
                </select>
                <div className="search small-search">
                  <Search size={14} />
                  <input placeholder="Tìm theo username, IP, thiết bị…" value={logQuery} onChange={e => setLogQuery(e.target.value)} />
                </div>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>THỜI GIAN</th>
                      <th>TÀI KHOẢN</th>
                      <th>SỰ KIỆN</th>
                      <th>TRẠNG THÁI</th>
                      <th>ĐỊA CHỈ IP</th>
                      <th>TRÌNH DUYỆT / USER-AGENT</th>
                      <th>CHI TIẾT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map(l => (
                      <tr key={l.id} className={l.status === 'failed' ? 'row-warning' : ''}>
                        <td className="mono">{date(l.created_at)}</td>
                        <td>
                          <span className="user-badge"><User size={12} /> {l.username}</span>
                        </td>
                        <td><b>{ACTION_LABELS[l.action] || l.action}</b></td>
                        <td>
                          <span className={`pill ${l.status === 'success' ? 'completed' : 'failed'}`}>
                            {l.status === 'success' ? 'Thành công' : 'Thất bại'}
                          </span>
                        </td>
                        <td className="mono"><Globe size={12} style={{ verticalAlign: 'middle', marginRight: '4px', color: '#7dd3fc' }} />{l.ip_address || '—'}</td>
                        <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={l.user_agent || ''}>
                          <span className="muted small">{l.user_agent || '—'}</span>
                        </td>
                        <td>{l.details || '—'}</td>
                      </tr>
                    ))}
                    {!logs.length && (
                      <tr>
                        <td colSpan="7" className="empty">
                          {logsLoading ? 'Đang tải dữ liệu...' : 'Chưa có dữ liệu đăng nhập nào phù hợp bộ lọc.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        ) : tab === 'logs' ? (
          <section className="content">
            <div className="panel">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">GIÁM SÁT HỆ THỐNG (ACTIVITY AUDIT)</span>
                  <h3>Nhật ký hoạt động người dùng ({logs.length})</h3>
                </div>
                <div className="audit-actions">
                  <button className="btn-export csv" onClick={() => exportLogs('csv', null)}>
                    <Download size={14} /> Xuất CSV (Excel)
                  </button>
                  <button className="btn-export json" onClick={() => exportLogs('json', null)}>
                    <Download size={14} /> Xuất JSON
                  </button>
                  <button className="btn-danger-outline" onClick={() => clearOldLogs(30, null)}>
                    <Trash2 size={13} /> Xóa log &gt; 30 ngày
                  </button>
                  <button className="icon-btn" onClick={() => fetchLogs('')} title="Làm mới">
                    <RefreshCw size={16} />
                  </button>
                </div>
              </div>

              <div className="audit-filter-bar">
                <select className="user-filter-select" value={logFilterUser} onChange={e => setLogFilterUser(e.target.value)}>
                  <option value="">Tất cả người dùng</option>
                  {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
                <select className="user-filter-select" value={logFilterAction} onChange={e => setLogFilterAction(e.target.value)}>
                  <option value="">Tất cả hành động</option>
                  {Object.entries(ACTION_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>{v}</option>
                  ))}
                </select>
                <select className="user-filter-select" value={logFilterStatus} onChange={e => setLogFilterStatus(e.target.value)}>
                  <option value="">Mọi trạng thái</option>
                  <option value="success">Thành công</option>
                  <option value="failed">Thất bại</option>
                </select>
                <select className="user-filter-select" value={logFilterDays} onChange={e => setLogFilterDays(e.target.value)}>
                  <option value="">Tất cả thời gian</option>
                  <option value="1">24 giờ qua</option>
                  <option value="7">7 ngày qua</option>
                  <option value="30">30 ngày qua</option>
                </select>
                <div className="search small-search">
                  <Search size={14} />
                  <input placeholder="Tìm user, IP, tên file, chi tiết…" value={logQuery} onChange={e => setLogQuery(e.target.value)} />
                </div>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>THỜI GIAN</th>
                      <th>NGƯỜI DÙNG</th>
                      <th>HÀNH ĐỘNG</th>
                      <th>TRẠNG THÁI</th>
                      <th>ĐỊA CHỈ IP</th>
                      <th>ĐỐI TƯỢNG</th>
                      <th>CHI TIẾT HOẠT ĐỘNG</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map(l => (
                      <tr key={l.id} className={l.status === 'failed' ? 'row-warning' : ''}>
                        <td className="mono">{date(l.created_at)}</td>
                        <td>
                          <span className="user-badge"><User size={12} /> {l.username}</span>
                        </td>
                        <td>
                          <span className={`pill action-pill ${l.category}`}>
                            {ACTION_LABELS[l.action] || l.action}
                          </span>
                        </td>
                        <td>
                          <span className={`pill ${l.status === 'success' ? 'completed' : 'failed'}`}>
                            {l.status === 'success' ? 'Thành công' : 'Thất bại'}
                          </span>
                        </td>
                        <td className="mono">{l.ip_address || '—'}</td>
                        <td className="mono" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={l.target || ''}>
                          {l.target || '—'}
                        </td>
                        <td style={{ whiteSpace: 'normal', minWidth: '220px' }}>{l.details || '—'}</td>
                      </tr>
                    ))}
                    {!logs.length && (
                      <tr>
                        <td colSpan="7" className="empty">
                          {logsLoading ? 'Đang tải dữ liệu...' : 'Không có bản ghi hoạt động nào phù hợp bộ lọc.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        ) : null}
      </main>
    </div>
  );
}

function Info({ label, value, mono }) {
  return (
    <div className="info">
      <span>{label}</span>
      <b className={mono ? 'mono' : ''}>{value || '—'}</b>
    </div>
  );
}

function Stat({ icon, label, value, color }) {
  return (
    <div className="stat">
      <div className={`stat-icon ${color}`}>{icon}</div>
      <div>
        <small>{label}</small>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function ScanTable({ scans, onSelect, statusIcon, onDelete, onExportPdf, selectedIds = new Set(), onToggleSelect, onSelectAll, me }) {
  const allSelected = scans.length > 0 && scans.every(s => selectedIds.has(s.id));
  const someSelected = scans.some(s => selectedIds.has(s.id));

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: '38px', textAlign: 'center' }}>
              <input
                type="checkbox"
                className="row-checkbox"
                checked={allSelected}
                ref={el => { if (el) el.indeterminate = someSelected && !allSelected; }}
                onChange={e => onSelectAll && onSelectAll(e.target.checked)}
              />
            </th>
            <th>TỆP TIN</th>
            <th>DUNG LƯỢNG</th>
            <th>NGƯỜI TẢI</th>
            <th>ĐẶC ĐIỂM / ĐÁNH GIÁ</th>
            <th>SHA-256</th>
            <th>TRẠNG THÁI</th>
            <th>NGÀY QUÉT</th>
            <th style={{ textAlign: 'center' }}>THAO TÁC</th>
          </tr>
        </thead>
        <tbody>
          {scans.map(s => {
            const res = s.result || {};
            const isArc = !!res.archive;
            const srcEval = res.source_evaluation;
            const isCrit = srcEval?.risk_level === 'CRITICAL';
            const isHigh = srcEval?.risk_level === 'HIGH';
            const isSelected = selectedIds.has(s.id);
            const canDelete = me?.role === 'admin' || s.user_id === me?.id;
            return (
              <tr key={s.id} onClick={() => onSelect(s)} className={`click-row ${isCrit ? 'row-critical' : isHigh ? 'row-warning' : ''} ${isSelected ? 'row-selected' : ''}`}>
                <td style={{ textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    className="row-checkbox"
                    checked={isSelected}
                    onChange={() => onToggleSelect && onToggleSelect(s.id)}
                  />
                </td>
                <td>
                  <div className="file-cell">
                    <div className="file-icon">
                      {isArc ? <Archive size={16} /> : srcEval ? <Code size={16} /> : <Files size={16} />}
                    </div>
                    <b className={isCrit ? 'bold-critical-name' : isHigh ? 'bold-warning-name' : ''}>
                      {isCrit && <span className="crit-mark" title="CRITICAL DETECTED">🚨 </span>}
                      {s.original_name}
                    </b>
                  </div>
                </td>
                <td>{fmt(s.size)}</td>
                <td>
                  <span className="user-badge" title={`User ID: ${s.user_id || '—'}`}>
                    <User size={12} /> {s.uploader || 'Admin'}
                  </span>
                </td>
                <td>
                  <div className="tags-cell">
                    {isArc && <span className="pill cat-pill archive">📦 {res.archive.archive_type.toUpperCase()}</span>}
                    {srcEval && <RiskPill level={srcEval.risk_level} />}
                    {!isArc && !srcEval && (res.detects?.[0]?.filetype ? <span className="pill die-tag">{res.detects[0].filetype}</span> : <span className="muted">—</span>)}
                  </div>
                </td>
                <td className="mono hash-cell">{s.sha256.slice(0, 16)}…</td>
                <td>
                  <span className={`pill ${s.status}`}>
                    {statusIcon(s.status)} {s.status}
                  </span>
                </td>
                <td>{new Date(s.created_at).toLocaleString()}</td>
                <td style={{ textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                  <div style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
                    {s.status === 'completed' && (
                      <button
                        className="btn-action-row"
                        title="Xuất báo cáo PDF"
                        onClick={() => onExportPdf && onExportPdf(s.id, s.original_name)}
                      >
                        <FileText size={15} />
                      </button>
                    )}
                    {canDelete && (
                      <button
                        className="btn-delete-row"
                        title="Xóa tệp tin này và giải phóng bộ nhớ"
                        onClick={(e) => onDelete && onDelete(s.id, e)}
                      >
                        <Trash2 size={15} />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
          {!scans.length && (
            <tr>
              <td colSpan="9" className="empty">Không có mẫu quét nào. Hãy tải tệp tin lên để bắt đầu.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default App;
