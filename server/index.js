// LeoNet Sentinel — Core Monitoring Engine
// Runs standalone (node server/index.js) or required by Electron

const express  = require('express');
const http     = require('http');
const { Server } = require('socket.io');
const { exec } = require('child_process');
const { promisify } = require('util');
const os   = require('os');
const path = require('path');
const fs   = require('fs');

const execAsync = promisify(exec);
const app        = express();
const httpServer = http.createServer(app);
const io         = new Server(httpServer, { cors: { origin: '*' } });

app.use(express.json());

// Serve built React UI
const distPath = path.join(__dirname, '..', 'dist');
if (fs.existsSync(distPath)) app.use(express.static(distPath));

// ── Config ────────────────────────────────────────────────────────────────────
const cfg = {
  leoNetUrl:  process.env.LEONET_URL  || '',
  agentId:    process.env.AGENT_ID    || `sentinel-${os.hostname().toLowerCase().replace(/[^a-z0-9]/g,'-').slice(0,20)}`,
  agentName:  process.env.AGENT_NAME  || os.hostname(),
  apiKey:     process.env.LEONET_KEY  || '',
};

// ── Live State ────────────────────────────────────────────────────────────────
let state = {
  system: null, processes: [], connections: [],
  threats: [], mitigations: [], lastScan: null,
  leoNetConnected: false, scanCount: 0,
};

// ── Threat Intelligence ────────────────────────────────────────────────────────
const BAD_PROCS = [
  'mimikatz','procdump','wce','fgdump','pwdump','gsecdump',
  'xmrig','minerd','cpuminer','cgminer','bfgminer','t-rex','nbminer',
  'netcat','ncat','nc.exe','ncat.exe',
  'powersploit','empire','cobalt','meterpreter','beacon.x64',
  'masscan','zmap','aircrack-ng','hashcat','john','hydra','medusa',
  'lazagne','credential','dumpntlm','secretsdump',
];

const BAD_PORTS = new Set([
  4444, 4445, 4446, 31337, 1337, 12345, 54321,
  6667, 6668, 6669, 6697,    // IRC C2
  9050, 9150, 9100,          // Tor
  1080, 3128,                // SOCKS / proxy
  5555, 5554,                // ADB / Android exploit
  8888, 9999, 7777,          // Common backdoor ports
]);

const BAD_IP_RANGES = [
  '185.220.', '45.142.', '91.108.', '194.165.',
  '5.188.', '195.123.', '176.119.', '198.251.',
  '193.32.', '80.82.', '89.248.',
];

// ── System Info ───────────────────────────────────────────────────────────────
async function getSystemInfo() {
  const cpus  = os.cpus();
  const total = os.totalmem();
  const free  = os.freemem();
  const load  = os.loadavg();
  return {
    hostname:   os.hostname(),
    platform:   os.platform(),
    arch:       os.arch(),
    release:    os.release(),
    uptime:     Math.round(os.uptime()),
    cpuCount:   cpus.length,
    cpuModel:   (cpus[0]?.model || 'Unknown').trim().slice(0, 40),
    cpuPct:     Math.min(99, Math.round((load[0] / cpus.length) * 100)),
    memTotalGB: +((total) / 1073741824).toFixed(1),
    memFreeGB:  +((free)  / 1073741824).toFixed(1),
    memPct:     Math.round((total - free) / total * 100),
    loadAvg:    load.map(l => +l.toFixed(2)),
    interfaces: Object.entries(os.networkInterfaces())
      .flatMap(([iface, addrs]) =>
        (addrs || []).filter(a => a.family === 'IPv4' && !a.internal)
                    .map(a => ({ iface, address: a.address }))
      ),
  };
}

// ── Process Monitor ───────────────────────────────────────────────────────────
async function getProcessList() {
  try {
    const isWin = process.platform === 'win32';
    const cmd   = isWin
      ? 'wmic process get Name,ProcessId,WorkingSetSize /format:csv 2>nul'
      : 'ps aux | head -60';
    const { stdout } = await execAsync(cmd, { timeout: 8000 });
    return parseProcessList(stdout, isWin);
  } catch { return []; }
}

function parseProcessList(stdout, isWin) {
  const lines = stdout.split('\n').map(l => l.trim()).filter(Boolean);
  const out   = [];
  if (isWin) {
    for (const line of lines.slice(2)) {
      const p   = line.split(',');
      const name = (p[2] || '').replace(/"/g, '').trim();
      const pid  = parseInt(p[3]);
      const mem  = Math.round(parseInt(p[1] || '0') / 1048576);
      if (!name || isNaN(pid)) continue;
      const sus = BAD_PROCS.some(b => name.toLowerCase().includes(b));
      out.push({ pid, name, cpu: 0, mem, suspicious: sus, threat: sus ? 'critical' : 'safe' });
    }
  } else {
    for (const line of lines.slice(1)) {
      const p    = line.split(/\s+/);
      if (p.length < 11) continue;
      const pid  = parseInt(p[1]);
      const cpu  = parseFloat(p[2]);
      const mem  = parseFloat(p[3]);
      const name = p.slice(10).join(' ').split('/').pop().split(' ')[0].slice(0, 40);
      if (isNaN(pid) || !name) continue;
      const sus    = BAD_PROCS.some(b => name.toLowerCase().includes(b));
      const hiCpu  = cpu > 70;
      const threat = sus ? 'critical' : hiCpu ? 'medium' : cpu > 30 ? 'low' : 'safe';
      out.push({ pid, name, cpu, mem, suspicious: sus || hiCpu, threat });
    }
  }
  return out.slice(0, 50);
}

// ── Network Monitor ───────────────────────────────────────────────────────────
async function getNetworkConnections() {
  try {
    const { stdout } = await execAsync('netstat -an', { timeout: 8000 });
    return parseConnections(stdout);
  } catch { return []; }
}

function parseConnections(stdout) {
  return stdout.split('\n')
    .filter(l => l.includes('ESTABLISHED') || l.includes('LISTEN') || l.includes('SYN_SENT'))
    .map(line => {
      const p      = line.trim().split(/\s+/);
      const proto  = p[0] || 'tcp';
      const local  = p[3] || p[1] || '';
      const remote = p[4] || p[2] || '';
      const state  = (p[5] || p[3] || 'UNKNOWN').trim();
      const rPort  = parseInt((remote.split(':').pop() || remote.split('.').pop() || '0'));
      const rIp    = remote.includes('.')
        ? remote.split(':').slice(0, -1).join(':')
        : remote.split('.').slice(0, -1).join('.');
      const susPrt = BAD_PORTS.has(rPort);
      const susIp  = BAD_IP_RANGES.some(r => rIp.startsWith(r));
      const ext    = !remote.startsWith('127.') && !remote.startsWith('0.')
                  && !remote.startsWith('::1') && remote !== '*.*';
      return {
        proto, local, remote, state,
        suspicious: susPrt || susIp,
        external: ext,
        threat: susIp ? 'critical' : susPrt ? 'high' : 'safe',
        remotePort: rPort, remoteIp: rIp,
      };
    }).filter(c => c.local && c.local !== '*').slice(0, 40);
}

// ── Threat Detection Engine ───────────────────────────────────────────────────
function detectThreats(system, processes, connections) {
  const threats = [];
  const now     = new Date().toISOString();

  for (const p of processes) {
    if (p.threat === 'critical' || p.threat === 'high') {
      threats.push({
        id: `PROC-${p.pid}`,
        type: 'Suspicious Process',
        severity: p.threat,
        name: p.name,
        details: `PID ${p.pid} | CPU ${p.cpu}% | Mem ${p.mem}MB`,
        source: 'Process Monitor',
        timestamp: now,
        mitigated: false,
        action: { action: 'kill_process', pid: p.pid, label: `Kill PID ${p.pid}` },
      });
    }
  }

  for (const c of connections) {
    if (c.threat === 'critical' || c.threat === 'high') {
      threats.push({
        id: `NET-${c.remoteIp.replace(/[.:]/g, '-')}`,
        type: c.threat === 'critical' ? 'Malicious C2 Connection' : 'Suspicious Connection',
        severity: c.threat,
        name: c.remote,
        details: `${c.local} → ${c.remote} [${c.state}] port ${c.remotePort}`,
        source: 'Network Monitor',
        timestamp: now,
        mitigated: false,
        action: { action: 'block_ip', ip: c.remoteIp, label: `Block ${c.remoteIp}` },
      });
    }
  }

  if (system?.cpuPct > 85) {
    threats.push({
      id: 'SYS-CPU',
      type: 'High CPU Anomaly',
      severity: 'medium',
      name: `CPU at ${system.cpuPct}%`,
      details: `Load: ${system.loadAvg?.join(', ')}. Possible cryptominer or C2 beacon.`,
      source: 'System Monitor',
      timestamp: now,
      mitigated: false,
      action: null,
    });
  }

  if (system?.memPct > 92) {
    threats.push({
      id: 'SYS-MEM',
      type: 'Memory Exhaustion',
      severity: 'medium',
      name: `Memory at ${system.memPct}%`,
      details: 'Possible DoS condition, ransomware encryption, or memory scraper active.',
      source: 'System Monitor',
      timestamp: now,
      mitigated: false,
      action: null,
    });
  }

  return threats;
}

// ── Main Scan ─────────────────────────────────────────────────────────────────
async function runScan() {
  try {
    const [system, processes, connections] = await Promise.all([
      getSystemInfo(), getProcessList(), getNetworkConnections(),
    ]);
    const threats = detectThreats(system, processes, connections);
    state = { ...state, system, processes, connections, threats, lastScan: new Date().toISOString(), scanCount: state.scanCount + 1 };
    io.emit('update', state);
    if (cfg.leoNetUrl) pushToLeoNet().catch(() => {});
  } catch (e) { console.error('[Sentinel] Scan error:', e.message); }
}

// ── LeoNet Defense Bridge ─────────────────────────────────────────────────────
async function pushToLeoNet() {
  const axios = require('axios');
  try {
    await axios.post(`${cfg.leoNetUrl}/api/sentinel/report`, {
      agentId:       cfg.agentId,
      agentName:     cfg.agentName,
      platform:      state.system?.platform,
      hostname:      state.system?.hostname,
      timestamp:     state.lastScan,
      system:        state.system,
      threats:       state.threats,
      threatCount:   state.threats.length,
      criticalCount: state.threats.filter(t => t.severity === 'critical').length,
      highCount:     state.threats.filter(t => t.severity === 'high').length,
    }, { timeout: 10000, headers: cfg.apiKey ? { 'x-api-key': cfg.apiKey } : {} });
    if (!state.leoNetConnected) {
      state.leoNetConnected = true;
      io.emit('leonet-status', { connected: true, url: cfg.leoNetUrl });
    }
  } catch (e) {
    if (state.leoNetConnected) {
      state.leoNetConnected = false;
      io.emit('leonet-status', { connected: false, error: e.message });
    }
  }
}

async function pollCommands() {
  if (!cfg.leoNetUrl) return;
  try {
    const axios = require('axios');
    const { data } = await axios.get(
      `${cfg.leoNetUrl}/api/sentinel/command?agentId=${cfg.agentId}`,
      { timeout: 8000, headers: cfg.apiKey ? { 'x-api-key': cfg.apiKey } : {} }
    );
    for (const cmd of (data.commands || [])) await executeCommand(cmd);
  } catch {}
}

// ── Mitigation Engine ─────────────────────────────────────────────────────────
async function executeCommand(cmd) {
  const result = { ...cmd, executedAt: new Date().toISOString(), success: false, output: '' };
  try {
    if (cmd.action === 'kill_process' && cmd.pid) {
      const k = process.platform === 'win32'
        ? `taskkill /PID ${cmd.pid} /F`
        : `kill -9 ${cmd.pid}`;
      await execAsync(k, { timeout: 5000 });
      result.success = true;
      result.output  = `Process PID ${cmd.pid} terminated.`;

    } else if (cmd.action === 'block_ip' && cmd.ip) {
      let blk;
      if      (process.platform === 'darwin') blk = `sudo pfctl -t leonet_blocklist -T add ${cmd.ip} 2>/dev/null; echo "blocked"`;
      else if (process.platform === 'win32')  blk = `netsh advfirewall firewall add rule name="LeoNet-Block-${cmd.ip}" dir=in action=block remoteip=${cmd.ip} && netsh advfirewall firewall add rule name="LeoNet-Block-${cmd.ip}-out" dir=out action=block remoteip=${cmd.ip}`;
      else                                    blk = `iptables -A INPUT -s ${cmd.ip} -j DROP && iptables -A OUTPUT -d ${cmd.ip} -j DROP`;
      await execAsync(blk, { timeout: 8000 });
      result.success = true;
      result.output  = `IP ${cmd.ip} blocked via firewall rule.`;

    } else if (cmd.action === 'isolate_network') {
      const iso = process.platform === 'win32'
        ? 'netsh interface set interface "Ethernet" admin=disable && netsh interface set interface "Wi-Fi" admin=disable'
        : 'ifconfig | grep -E "^[a-z]" | awk -F: \'{print $1}\' | grep -v lo | xargs -I{} ifconfig {} down';
      await execAsync(iso, { timeout: 10000 });
      result.success = true;
      result.output  = 'Network interfaces disabled. Device isolated.';

    } else if (cmd.action === 'scan_now') {
      await runScan();
      result.success = true;
      result.output  = 'Immediate scan complete.';
    }
  } catch (e) { result.output = e.message || 'Command failed'; }

  state.mitigations = [result, ...state.mitigations].slice(0, 50);
  io.emit('mitigation', result);

  if (cfg.leoNetUrl) {
    const axios = require('axios');
    axios.post(`${cfg.leoNetUrl}/api/sentinel/mitigation`, { agentId: cfg.agentId, ...result }).catch(() => {});
  }
  return result;
}

// ── API Routes ────────────────────────────────────────────────────────────────
app.get('/api/status', (_, res) => res.json({
  status: 'online', agentId: cfg.agentId, agentName: cfg.agentName,
  platform: os.platform(), lastScan: state.lastScan, threats: state.threats.length,
}));
app.get('/api/data',    (_, res) => res.json(state));
app.post('/api/scan',   async (_, res) => { await runScan(); res.json({ ok: true, threats: state.threats.length }); });
app.post('/api/command',async (req, res) => { const r = await executeCommand(req.body); res.json(r); });
app.post('/api/config', (req, res) => {
  if (req.body.leoNetUrl  !== undefined) cfg.leoNetUrl  = req.body.leoNetUrl;
  if (req.body.agentName  !== undefined) cfg.agentName  = req.body.agentName;
  if (req.body.apiKey     !== undefined) cfg.apiKey     = req.body.apiKey;
  res.json({ ok: true, config: { leoNetUrl: cfg.leoNetUrl, agentId: cfg.agentId, agentName: cfg.agentName } });
});
app.get('*', (_, res) => {
  const f = path.join(__dirname, '..', 'dist', 'index.html');
  fs.existsSync(f) ? res.sendFile(f) : res.send('<h1>Run <code>npm run build</code> first, then reload.</h1>');
});

// ── Socket.io ─────────────────────────────────────────────────────────────────
io.on('connection', socket => {
  socket.emit('update', state);
  socket.emit('config', { leoNetUrl: cfg.leoNetUrl, agentId: cfg.agentId, agentName: cfg.agentName });
  socket.on('scan',       ()  => runScan());
  socket.on('command',    async cmd => { const r = await executeCommand(cmd); socket.emit('mitigation', r); });
  socket.on('set-config', nc  => { Object.assign(cfg, nc); socket.emit('config', { ...cfg }); });
});

// ── Export (for Electron) + Auto-start (for headless) ────────────────────────
function startMonitoring() {
  runScan();
  setInterval(runScan,       10000);   // scan every 10 s
  setInterval(pollCommands,  15000);   // poll LeoNet Defense every 15 s
}

module.exports = { app, httpServer, io, runScan, startMonitoring, cfg, PORT: process.env.PORT || 3001 };

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  httpServer.listen(PORT, () => {
    console.log(`\n🦁  LeoNet Sentinel  ·  http://localhost:${PORT}`);
    console.log(`    Agent ID : ${cfg.agentId}`);
    console.log(`    Platform : ${os.platform()} ${os.arch()}`);
    console.log(`    LeoNet   : ${cfg.leoNetUrl || '(not configured — set LEONET_URL env var)'}`);
    console.log('\n    Dashboard opening in browser...\n');
  });
  startMonitoring();
}
