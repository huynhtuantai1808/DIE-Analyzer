import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './style.css';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24, background: '#0b1220', color: '#e6edf7' }}>
          <div style={{ maxWidth: 520, background: '#111e31', border: '1px solid #7f1d1d', borderRadius: 12, padding: 24 }}>
            <h3 style={{ margin: '0 0 10px', color: '#fca5a5' }}>Đã xảy ra lỗi hiển thị giao diện</h3>
            <p style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.5 }}>
              {this.state.error?.message || 'Lỗi không xác định khi cập nhật giao diện.'}
            </p>
            <button
              className="primary"
              onClick={() => window.location.reload()}
              style={{ marginTop: 12 }}
            >
              Tải lại trang
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
