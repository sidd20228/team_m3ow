import React, { useEffect, useMemo, useRef, useState } from 'react'
import WAFDashboardAPI from '../dashboard-api'
import { Chart, LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler, Legend, Tooltip } from 'chart.js'

Chart.register(LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler, Legend, Tooltip)

export default function Dashboard() {
  const api = useMemo(() => new WAFDashboardAPI('http://localhost:8001'), [])

  const [benignCount, setBenign] = useState(0)
  const [maliciousCount, setMalicious] = useState(0)
  const totalCount = benignCount + maliciousCount
  const [connected, setConnected] = useState(false)
  const [lastUpdated, setLastUpdated] = useState('--:--:--')
  const [events, setEvents] = useState([])
  const [mode, setModeState] = useState('fast')
  const [logCollapsed, setLogCollapsed] = useState(false)

  const chartRef = useRef(null)
  const chartInstanceRef = useRef(null)

  useEffect(() => {
    const ctx = chartRef.current?.getContext('2d')
    if (!ctx) return

    chartInstanceRef.current = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Benign',
            data: [],
            borderColor: 'rgba(59, 130, 246, 1)',
            backgroundColor: 'rgba(59, 130, 246, 0.15)',
            tension: 0.35,
            fill: true,
          },
          {
            label: 'Malicious',
            data: [],
            borderColor: 'rgba(239, 68, 68, 1)',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
        plugins: { legend: { display: true }, tooltip: { intersect: false, mode: 'index' } },
      },
    })

    return () => {
      chartInstanceRef.current?.destroy()
      chartInstanceRef.current = null
    }
  }, [])

  useEffect(() => {
    api.connectWebSocket(
      (data) => {
        const isMal = data.action_taken === 'BLOCK' || data.is_malicious
        setMalicious((m) => m + (isMal ? 1 : 0))
        setBenign((b) => b + (!isMal ? 1 : 0))
        setLastUpdated(new Date().toLocaleTimeString())

        const nowLabel = new Date().toLocaleTimeString()
        const chart = chartInstanceRef.current
        if (chart) {
          chart.data.labels.push(nowLabel)
          chart.data.datasets[0].data.push(!isMal ? 1 : 0)
          chart.data.datasets[1].data.push(isMal ? 1 : 0)
          if (chart.data.labels.length > 100) {
            chart.data.labels.shift()
            chart.data.datasets.forEach((ds) => ds.data.shift())
          }
          chart.update('none')
        }

        setEvents((prev) => [{ id: data.mongo_id || Date.now(), path: data.path || '/', action: data.action_taken || (isMal ? 'BLOCK' : 'ALLOW'), ip: (data.request_body && (data.request_body.ip || data.request_body.client_ip)) || '0.0.0.0', ts: new Date().toLocaleTimeString() }, ...prev].slice(0, 20))
      },
      (conn) => setConnected(conn)
    )

    // Initial health check
    api.checkHealth().then(() => setLastUpdated(new Date().toLocaleTimeString())).catch(() => {})

    return () => api.disconnectWebSocket()
  }, [api])

  const setMode = async (mode) => {
    try {
      await api.setWAFMode(mode)
      setModeState(mode)
    } catch (e) {
      console.error('Failed to set mode', e)
    }
  }

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="header-left">
          <h1 className="dashboard-title">
            <i className="fas fa-shield-alt pulse" />
            WireFall
          </h1>
          <div className="system-status">
            <div className="status-indicator" id="mlStatus">
              <div className={`status-dot ml${connected ? '' : ' offline'}`} id="mlStatusDot" />
              <span>ML Model</span>
            </div>
          </div>
        </div>
        <div className="header-right">
          <div className="last-updated">
            <i className="fas fa-clock" />
            <span id="lastUpdated">Last Updated: {lastUpdated}</span>
          </div>
          <button className="refresh-btn" id="refreshBtn" onClick={() => setLastUpdated(new Date().toLocaleTimeString())}>
            <i className="fas fa-sync-alt" />
          </button>
        </div>
      </header>

      <div className="dashboard-body">
        <aside className="control-panel">
          <div className="panel-section">
            <h3>WAF Mode</h3>
            <div className="toggle-group" id="wafModeToggle">
              <div className={`toggle-option${mode === 'fast' ? ' active' : ''}`} data-mode="fast" onClick={() => setMode('fast')}>
                <i className="fas fa-bolt" />
                <span>Fast</span>
                <div className="toggle-ring" />
              </div>
              <div className={`toggle-option${mode === 'full' ? ' active' : ''}`} data-mode="full" onClick={() => setMode('full')}>
                <i className="fas fa-shield" />
                <span>Full</span>
                <div className="toggle-ring" />
              </div>
              <div className={`toggle-option${mode === 'off' ? ' active' : ''}`} data-mode="off" onClick={() => setMode('off')}>
                <i className="fas fa-power-off" />
                <span>Off</span>
                <div className="toggle-ring" />
              </div>
            </div>
          </div>

          <div className="panel-section">
            <h3>Live Metrics</h3>
            <div className="metric-card">
              <div className="metric-icon benign"><i className="fas fa-check" /></div>
              <div className="metric-content">
                <div className="metric-value" id="benignCount">{benignCount}</div>
                <div className="metric-label">Benign</div>
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-icon malicious"><i className="fas fa-ban" /></div>
              <div className="metric-content">
                <div className="metric-value" id="maliciousCount">{maliciousCount}</div>
                <div className="metric-label">Blocked</div>
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-icon total"><i className="fas fa-chart-line" /></div>
              <div className="metric-content">
                <div className="metric-value" id="totalCount">{totalCount}</div>
                <div className="metric-label">Total</div>
              </div>
            </div>
          </div>
        </aside>

        <main className="main-content">
          <section className="graph-section">
            <div className="graph-header">
              <h2>Live Request Traffic</h2>
            </div>
            <div className="ecg-chart-container">
              <canvas id="ecgChart" ref={chartRef} />
            </div>
          </section>

          <section className="table-section">
            <div className="table-header">
              <h3>Recent Events</h3>
            </div>
            <div className="table-container">
              <table className="events-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>IP</th>
                    <th>Path</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} className={e.action === 'BLOCK' ? 'malicious' : ''}>
                      <td>{e.ts}</td>
                      <td>{e.ip}</td>
                      <td>{e.path}</td>
                      <td>{e.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>

      <div className={`log-viewer${logCollapsed ? ' collapsed' : ''}`} id="logViewer">
        <div className="log-header" onClick={() => setLogCollapsed((c) => !c)}>
          <h4>System Logs</h4>
          <button
            className="log-toggle"
            id="logToggle"
            aria-expanded={!logCollapsed}
            onClick={(e) => {
              e.stopPropagation()
              setLogCollapsed((c) => !c)
            }}
          >
            <i className="fas fa-chevron-up" />
          </button>
        </div>
        <div className="log-content" id="logContent">
          <div className="log-entry">
            <span className="log-time">[{lastUpdated}]</span>
            <span className="log-level info">INFO</span>
            <span className="log-message">Dashboard running</span>
          </div>
        </div>
      </div>

      <div className="background-effects">
        <div className="particle" style={{ ['--delay']: '0s', ['--duration']: '10s' }} />
        <div className="particle" style={{ ['--delay']: '2s', ['--duration']: '12s' }} />
        <div className="particle" style={{ ['--delay']: '4s', ['--duration']: '8s' }} />
      </div>
    </div>
  )
}
