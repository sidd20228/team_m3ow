// Ported from original dashboard-api.js for use inside Vite/ESM
export default class WAFDashboardAPI {
  constructor(baseUrl = 'http://localhost:8001') {
    this.baseUrl = baseUrl;
    this.wsUrl = baseUrl.replace('http', 'ws') + '/ws/logs';
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 3000;
    this.onMessageCallback = null;
    this.onConnectionChange = null;
  }

  connectWebSocket(onMessage, onConnectionChange) {
    this.onMessageCallback = onMessage;
    this.onConnectionChange = onConnectionChange;
    try {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.onConnectionChange?.(true);
      };
      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.onMessageCallback?.(data);
        } catch (err) {
          console.error('WebSocket message parse error', err);
        }
      };
      this.ws.onclose = () => {
        this.onConnectionChange?.(false);
        this.attemptReconnect();
      };
      this.ws.onerror = () => {
        this.onConnectionChange?.(false);
      };
    } catch (error) {
      console.error('WebSocket connection error:', error);
      this.attemptReconnect();
    }
  }

  attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => {
        if (this.onMessageCallback && this.onConnectionChange) {
          this.connectWebSocket(this.onMessageCallback, this.onConnectionChange);
        }
      }, this.reconnectDelay);
    }
  }

  disconnectWebSocket() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  async checkHealth() {
    try {
      const res = await fetch(`${this.baseUrl}/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      return {
        status: 'error',
        redis_connected: false,
        mongodb_connected: false,
        anomaly_model_loaded: false,
        error: e.message,
      };
    }
  }

  async getHistoricalLogs(limit = 20) {
    try {
      const res = await fetch(`${this.baseUrl}/logs?limit=${limit}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      return { logs: [], count: 0, error: e.message };
    }
  }

  async setWAFMode(mode) {
    const valid = ['off', 'fast', 'full'];
    if (!valid.includes(mode)) throw new Error(`Invalid mode: ${mode}`);
    const res = await fetch(`${this.baseUrl}/set-mode/${mode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }

  async whitelistRequest(mongoId) {
    const res = await fetch(`${this.baseUrl}/pass-request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mongo_id: mongoId }) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }

  async sendTestRequest(method, path, requestBody) {
    const res = await fetch(`${this.baseUrl}/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ method, path, protocol: 'HTTP/1.1', request_body: requestBody }) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }
}
