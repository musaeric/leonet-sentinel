import React, { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';

// ── Design (matches LeoNet Defense) ──────────────────────────────────────────
const D = {
  bg:'#050A14', surface:'#0D1B2A', panel:'#112233', panel2:'#0A1828',
  border:'#1E3A5F', border2:'#0F2844',
  cyan:'#00D4FF', blue:'#1A7AFF', green:'#00FF88',
  red:'#FF2D55', orange:'#FF6B35', purple:'#BF5FFF',
  gold:'#FFD700', muted:'#4A7FA5', text:'#C8E0F4', white:'#FFFFFF',
};
const sev = s => ({ critical:D.red, high:D.orange, medium:D.gold, low:D.cyan, safe:D.green }[s]||D.muted);
const sevBg = s => ({ critical:'rgba(255,45,85,0.12)', high:'rgba(255,107,53,0.12)', medium:'rgba(255,215,0,0.1)', low:'rgba(0,212,255,0.1)', safe:'rgba(0,255,136,0.1)' }[s]||'transparent');

// ── Reusable components ────────────────────────────────────────────────────────
const GlowCard = ({ children, color=D.cyan, style={}, onClick }) => (
  <div onClick={onClick} style={{ background:D.panel, border:`1px solid ${color}33`, borderRadius:14,
    boxShadow:`0 0 0 1px ${color}22, inset 0 0 30px ${color}06`, position:'relative', overflow:'hidden', ...style }}>
    <div style={{ position:'absolute', top:0, left:0, right:0, height:1, background:`linear-gradient(90deg,transparent,${color}88,transparent)` }} />
    {children}
  </div>
);

const StatCard = ({ label, value, unit='', icon, color=D.cyan, sub }) => (
  <GlowCard color={color} style={{ padding:'16px 20px' }}>
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
      <div>
        <div style={{ fontSize:10, fontWeight:700, color:D.muted, textTransform:'uppercase', letterSpacing:1.5, marginBottom:8 }}>{label}</div>
        <div style={{ fontSize:28, fontWeight:900, color, lineHeight:1, fontFamily:'monospace' }}>{value}<span style={{ fontSize:13, marginLeft:4, opacity:0.7 }}>{unit}</span></div>
        {sub && <div style={{ fontSize:10, color:D.muted, marginTop:5 }}>{sub}</div>}
      </div>
      <div style={{ fontSize:26, opacity:0.7 }}>{icon}</div>
    </div>
    <div style={{ position:'absolute', bottom:0, left:0, right:0, height:2, background:`linear-gradient(90deg,transparent,${color},transparent)` }} />
  </GlowCard>
);

const Badge = ({ label, color }) => (
  <span style={{ fontSize:9, fontWeight:800, color, background:`${color}18`, border:`1px solid ${color}33`,
    borderRadius:10, padding:'2px 8px', textTransform:'uppercase', letterSpacing:1, whiteSpace:'nowrap' }}>{label}</span>
);

// ── DevTools Guard ─────────────────────────────────────────────────────────────
// Returns 'null' string for any sensitive field when browser inspect panel is open.
function useDevToolsGuard() {
  const [devOpen, setDevOpen] = useState(false);
  const ref = useRef(false);

  useEffect(() => {
    const noop = () => {};
    const orig = {
      log:   console.log.bind(console),
      table: console.table.bind(console),
      dir:   console.dir.bind(console),
      debug: console.debug.bind(console),
      group: console.group.bind(console),
    };
    console.log = console.table = console.dir = console.debug = console.group = noop;

    const detect = () => {
      const h = window.outerHeight - window.innerHeight > 150;
      const w = window.outerWidth  - window.innerWidth  > 150;
      const detected = h || w;
      if (detected !== ref.current) {
        ref.current = detected;
        setDevOpen(detected);
        if (detected) {
          console.clear();
          orig.log(
            '%c⛔  LeoNet Sentinel — Unauthorized inspection detected. All sensitive data has been nullified.',
            'color:#FF2D55;font-size:14px;font-weight:900;padding:12px 16px;background:#050A14;border-left:4px solid #FF2D55'
          );
        }
      }
    };

    const noCtx = (e) => e.preventDefault();
    document.addEventListener('contextmenu', noCtx);

    const id = setInterval(detect, 350);
    detect();
    return () => {
      clearInterval(id);
      document.removeEventListener('contextmenu', noCtx);
      Object.assign(console, orig);
    };
  }, []);

  const mask = useCallback((val) => devOpen ? 'null' : val, [devOpen]);
  return { devOpen, mask };
}

// ── NAV ───────────────────────────────────────────────────────────────────────
const TABS = [
  { id:'overview',    label:'Overview',    icon:'⚡' },
  { id:'processes',   label:'Processes',   icon:'⚙️' },
  { id:'network',     label:'Network',     icon:'🌐' },
  { id:'threats',     label:'Threats',     icon:'🎯' },
  { id:'mitigations', label:'Mitigations', icon:'🛡️' },
  { id:'settings',    label:'Settings',    icon:'🔧' },
];

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]         = useState('overview');
  const [data, setData]       = useState(null);
  const [connected, setConn]  = useState(false);
  const [leonet, setLeonet]   = useState({ connected: false, url: '' });
  const [cfg, setCfg]         = useState({ leoNetUrl:'', agentId:'', agentName:'' });
  const [toast, setToast]     = useState(null);
  const [scanning, setScanning] = useState(false);
  const [leoNetInput, setLeoNetInput] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const { devOpen, mask } = useDevToolsGuard();
  const socketRef = useRef(null);

  const showToast = (msg, color=D.green) => {
    setToast({ msg, color });
    setTimeout(() => setToast(null), 3500);
  };

  // Socket.io connection
  useEffect(() => {
    const socket = io(window.location.origin, { transports:['websocket','polling'] });
    socketRef.current = socket;

    socket.on('connect',        () => setConn(true));
    socket.on('disconnect',     () => setConn(false));
    socket.on('update',         d  => setData(d));
    socket.on('config',         c  => { setCfg(c); setLeoNetInput(c.leoNetUrl||''); });
    socket.on('leonet-status',  s  => setLeonet(s));
    socket.on('mitigation',     r  => showToast(r.success ? `✅ ${r.output}` : `⚠️ ${r.output}`, r.success ? D.green : D.orange));

    return () => socket.disconnect();
  }, []);

  const scan = () => {
    setScanning(true);
    socketRef.current?.emit('scan');
    setTimeout(() => setScanning(false), 3000);
    showToast('🔬 Scan triggered…', D.cyan);
  };

  const sendCommand = (cmd) => {
    socketRef.current?.emit('command', cmd);
    showToast(`⚡ Executing: ${cmd.action}…`, D.orange);
  };

  const saveLeoNet = () => {
    socketRef.current?.emit('set-config', { leoNetUrl: leoNetInput, ...(apiKeyInput ? { apiKey: apiKeyInput } : {}) });
    showToast('🔗 LeoNet Defense URL saved. Connecting…', D.blue);
  };

  // ── Overview ───────────────────────────────────────────────────────────────
  const renderOverview = () => {
    const sys = data?.system;
    const threats = data?.threats || [];
    const crit = threats.filter(t => t.severity === 'critical').length;
    const high = threats.filter(t => t.severity === 'high').length;
    return (
      <div style={{ animation:'fade-in 0.3s ease' }}>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(160px,1fr))', gap:14, marginBottom:20 }}>
          <StatCard label="Threats Detected" value={threats.length} icon="🎯" color={threats.length>0?D.red:D.green} sub={`${crit} critical · ${high} high`} />
          <StatCard label="CPU Usage"     value={sys?.cpuPct||0}   unit="%" icon="⚡" color={sys?.cpuPct>80?D.red:sys?.cpuPct>50?D.orange:D.cyan} sub={sys?.cpuModel?.slice(0,22)||'—'} />
          <StatCard label="Memory Usage"  value={sys?.memPct||0}   unit="%" icon="🧠" color={sys?.memPct>85?D.red:sys?.memPct>70?D.orange:D.cyan} sub={`${sys?.memFreeGB||0} GB free`} />
          <StatCard label="Uptime"        value={sys ? Math.floor(sys.uptime/3600) : 0} unit="h" icon="⏱️" color={D.purple} sub={`${sys?.cpuCount||0} CPUs`} />
          <StatCard label="Scans Run"     value={data?.scanCount||0}  icon="🔬" color={D.gold} sub="every 10 seconds" />
          <StatCard label="Mitigations"   value={data?.mitigations?.length||0} icon="🛡️" color={D.green} sub="executed" />
        </div>

        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
          {/* System Info */}
          <GlowCard color={D.blue} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>💻 System Information</div>
            {[
              ['Hostname',    mask(sys?.hostname  || '—')],
              ['Platform',    `${sys?.platform||'—'} ${sys?.arch||''}`.trim()],
              ['OS Release',  sys?.release   || '—'],
              ['CPU',         sys?.cpuModel  || '—'],
              ['Load Avg',    sys?.loadAvg?.join(' · ') || '—'],
              ['Interfaces',  mask(sys?.interfaces?.map(i=>`${i.iface}: ${i.address}`).join(', ') || '—')],
              ['Agent ID',    mask(cfg.agentId    || '—')],
              ['Last Scan',   data?.lastScan ? new Date(data.lastScan).toLocaleTimeString() : 'Never'],
            ].map(([k,v]) => (
              <div key={k} style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:9, padding:'6px 10px', background:'#081420', borderRadius:6 }}>
                <span style={{ fontSize:10, color:D.muted, fontWeight:700, textTransform:'uppercase', letterSpacing:0.8 }}>{k}</span>
                <span style={{ fontSize:11, color:D.text, fontFamily:'monospace', maxWidth:'60%', textAlign:'right', wordBreak:'break-all' }}>{v}</span>
              </div>
            ))}
          </GlowCard>

          {/* Active Threats */}
          <GlowCard color={D.red} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🎯 Active Threats</div>
            {threats.length === 0
              ? <div style={{ textAlign:'center', padding:'30px 0', color:D.green, fontSize:13 }}>✅ No active threats detected</div>
              : threats.slice(0,6).map(t => (
                <div key={t.id} style={{ padding:'10px 12px', background:sevBg(t.severity), border:`1px solid ${sev(t.severity)}33`, borderRadius:8, marginBottom:8 }}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                    <span style={{ fontSize:11, fontWeight:700, color:sev(t.severity) }}>{t.type}</span>
                    <Badge label={t.severity} color={sev(t.severity)} />
                  </div>
                  <div style={{ fontSize:10, color:D.text, marginBottom:4 }}>{t.name}</div>
                  <div style={{ fontSize:9, color:D.muted }}>{t.details}</div>
                  {t.action && (
                    <button onClick={() => sendCommand(t.action)} style={{ marginTop:8, padding:'5px 12px', borderRadius:6, border:'none', background:sev(t.severity), color:'#fff', fontWeight:800, fontSize:10, cursor:'pointer' }}>
                      ⚡ {t.action.label}
                    </button>
                  )}
                </div>
              ))
            }
            {threats.length > 6 && <div style={{ fontSize:10, color:D.muted, textAlign:'center', marginTop:8 }}>+{threats.length-6} more — see Threats tab</div>}
          </GlowCard>
        </div>

        {/* LeoNet Defense connection status */}
        <GlowCard color={leonet.connected ? D.green : D.orange} style={{ padding:20 }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
            <div>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:4 }}>
                {leonet.connected ? '🟢 Connected to LeoNet Defense' : '🟡 LeoNet Defense — Not Connected'}
              </div>
              <div style={{ fontSize:10, color:D.muted }}>
                {leonet.connected
                  ? `Streaming threat data to ${mask(cfg.leoNetUrl)} · Commands received in real-time`
                  : 'Configure the LeoNet Defense URL in Settings to enable two-way threat sharing and remote command execution'}
              </div>
            </div>
            {!leonet.connected && (
              <button onClick={() => setTab('settings')} style={{ padding:'9px 18px', borderRadius:8, border:`1px solid ${D.orange}`, background:'transparent', color:D.orange, fontWeight:700, fontSize:12, cursor:'pointer' }}>
                Configure →
              </button>
            )}
          </div>
        </GlowCard>
      </div>
    );
  };

  // ── Processes ──────────────────────────────────────────────────────────────
  const renderProcesses = () => {
    const procs = data?.processes || [];
    return (
      <div style={{ animation:'fade-in 0.3s ease' }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
          <div>
            <h3 style={{ fontSize:14, fontWeight:800, color:D.white }}>⚙️ Running Processes ({procs.length})</h3>
            <p style={{ fontSize:11, color:D.muted, marginTop:3 }}>Real-time process table · Suspicious processes highlighted · Click Kill to terminate</p>
          </div>
          <button onClick={scan} style={{ padding:'9px 18px', borderRadius:8, border:`1px solid ${D.cyan}`, background:'rgba(0,212,255,0.08)', color:D.cyan, fontWeight:700, fontSize:12, cursor:'pointer' }}>
            🔄 Refresh
          </button>
        </div>
        <GlowCard color={D.cyan} style={{ padding:0, overflow:'hidden' }}>
          <div style={{ overflowX:'auto' }}>
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
              <thead>
                <tr style={{ background:'#061428' }}>
                  {['PID','Name','CPU %','Mem MB','Threat','Action'].map(h => (
                    <th key={h} style={{ padding:'10px 14px', textAlign:'left', color:D.muted, fontSize:9, fontWeight:800, textTransform:'uppercase', letterSpacing:1.5, borderBottom:`1px solid ${D.border}` }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {procs.sort((a,b) => (b.suspicious?1:0)-(a.suspicious?1:0)||(b.cpu-a.cpu)).map((p,i) => (
                  <tr key={p.pid} style={{ background: p.suspicious ? sevBg(p.threat) : i%2===0?'#0A1828':'#081420', borderBottom:`1px solid ${D.border2}`, boxShadow: p.suspicious ? `inset 3px 0 0 ${sev(p.threat)}` : 'none' }}>
                    <td style={{ padding:'8px 14px', fontFamily:'monospace', color:D.muted, fontSize:10 }}>{p.pid}</td>
                    <td style={{ padding:'8px 14px', color:p.suspicious?sev(p.threat):D.text, fontWeight:p.suspicious?700:400 }}>{p.name}</td>
                    <td style={{ padding:'8px 14px', fontFamily:'monospace', color: p.cpu>70?D.red:p.cpu>30?D.orange:D.muted }}>{p.cpu}%</td>
                    <td style={{ padding:'8px 14px', fontFamily:'monospace', color:D.muted }}>{p.mem}</td>
                    <td style={{ padding:'8px 14px' }}><Badge label={p.threat} color={sev(p.threat)} /></td>
                    <td style={{ padding:'8px 14px' }}>
                      {p.suspicious && (
                        <button onClick={() => sendCommand({ action:'kill_process', pid:p.pid, label:`Kill ${p.name}` })}
                          style={{ background:D.red, color:'#fff', border:'none', borderRadius:5, padding:'4px 10px', fontSize:9, fontWeight:800, cursor:'pointer' }}>
                          ✕ Kill
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlowCard>
      </div>
    );
  };

  // ── Network ────────────────────────────────────────────────────────────────
  const renderNetwork = () => {
    const conns = data?.connections || [];
    return (
      <div style={{ animation:'fade-in 0.3s ease' }}>
        <div style={{ marginBottom:16 }}>
          <h3 style={{ fontSize:14, fontWeight:800, color:D.white }}>🌐 Network Connections ({conns.length})</h3>
          <p style={{ fontSize:11, color:D.muted, marginTop:3 }}>Real-time netstat output · Bad IPs and suspicious ports flagged · Click Block to add firewall rule</p>
        </div>
        <GlowCard color={D.blue} style={{ padding:0, overflow:'hidden' }}>
          <div style={{ overflowX:'auto' }}>
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
              <thead>
                <tr style={{ background:'#061428' }}>
                  {['Proto','Local','Remote','Port','State','Threat','Action'].map(h => (
                    <th key={h} style={{ padding:'10px 14px', textAlign:'left', color:D.muted, fontSize:9, fontWeight:800, textTransform:'uppercase', letterSpacing:1.5, borderBottom:`1px solid ${D.border}` }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {conns.sort((a,b) => (b.suspicious?1:0)-(a.suspicious?1:0)).map((c,i) => (
                  <tr key={`${c.local}-${c.remote}-${i}`} style={{ background: c.suspicious ? sevBg(c.threat) : i%2===0?'#0A1828':'#081420', borderBottom:`1px solid ${D.border2}`, boxShadow: c.suspicious ? `inset 3px 0 0 ${sev(c.threat)}` : 'none' }}>
                    <td style={{ padding:'8px 14px', color:D.muted, fontFamily:'monospace', fontSize:10 }}>{c.proto?.toUpperCase()}</td>
                    <td style={{ padding:'8px 14px', color:D.text, fontFamily:'monospace', fontSize:10 }}>{c.local}</td>
                    <td style={{ padding:'8px 14px', color:c.suspicious?sev(c.threat):c.external?D.cyan:D.muted, fontFamily:'monospace', fontSize:10, fontWeight:c.suspicious?700:400 }}>{mask(c.remote||'*')}</td>
                    <td style={{ padding:'8px 14px', fontFamily:'monospace', color:D.muted, fontSize:10 }}>{mask(String(c.remotePort||'—'))}</td>
                    <td style={{ padding:'8px 14px', fontSize:10, color:D.muted }}>{c.state}</td>
                    <td style={{ padding:'8px 14px' }}><Badge label={c.threat} color={sev(c.threat)} /></td>
                    <td style={{ padding:'8px 14px' }}>
                      {c.suspicious && c.remoteIp && (
                        <button onClick={() => sendCommand({ action:'block_ip', ip:c.remoteIp, label:`Block ${c.remoteIp}` })}
                          style={{ background:D.orange, color:'#fff', border:'none', borderRadius:5, padding:'4px 10px', fontSize:9, fontWeight:800, cursor:'pointer' }}>
                          🚫 Block IP
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlowCard>
      </div>
    );
  };

  // ── Threats ────────────────────────────────────────────────────────────────
  const renderThreats = () => {
    const threats = data?.threats || [];
    return (
      <div style={{ animation:'fade-in 0.3s ease' }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
          <div>
            <h3 style={{ fontSize:14, fontWeight:800, color:D.white }}>🎯 Threat Console ({threats.length} active)</h3>
            <p style={{ fontSize:11, color:D.muted, marginTop:3 }}>Detected by process + network + system analysis · Execute mitigations in one click</p>
          </div>
          <button onClick={scan} style={{ padding:'9px 18px', borderRadius:8, border:`1px solid ${D.red}`, background:'rgba(255,45,85,0.08)', color:D.red, fontWeight:700, fontSize:12, cursor:'pointer' }}>
            🔬 Re-Scan
          </button>
        </div>
        {threats.length === 0
          ? (
            <GlowCard color={D.green} style={{ padding:48, textAlign:'center' }}>
              <div style={{ fontSize:40, marginBottom:12 }}>✅</div>
              <div style={{ fontSize:16, fontWeight:700, color:D.green }}>No Active Threats</div>
              <div style={{ fontSize:12, color:D.muted, marginTop:6 }}>System is clean. Sentinel is monitoring continuously.</div>
            </GlowCard>
          )
          : threats.map(t => (
            <GlowCard key={t.id} color={sev(t.severity)} style={{ padding:20, marginBottom:12 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:16 }}>
                <div style={{ flex:1 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
                    <Badge label={t.severity} color={sev(t.severity)} />
                    <span style={{ fontSize:12, fontWeight:700, color:D.white }}>{t.type}</span>
                    <span style={{ fontSize:10, color:D.muted }}>· {t.source}</span>
                  </div>
                  <div style={{ fontSize:13, fontWeight:700, color:sev(t.severity), marginBottom:4 }}>{t.name}</div>
                  <div style={{ fontSize:10, color:D.muted, fontFamily:'monospace' }}>{t.details}</div>
                  <div style={{ fontSize:9, color:D.muted, marginTop:6 }}>{new Date(t.timestamp).toLocaleString()}</div>
                </div>
                <div style={{ display:'flex', flexDirection:'column', gap:8, flexShrink:0 }}>
                  {t.action && (
                    <button onClick={() => sendCommand(t.action)}
                      style={{ padding:'8px 16px', borderRadius:8, border:'none', background:`linear-gradient(135deg,${sev(t.severity)},${D.orange})`, color:'#fff', fontWeight:800, fontSize:11, cursor:'pointer', whiteSpace:'nowrap' }}>
                      ⚡ {t.action.label}
                    </button>
                  )}
                  <button onClick={() => sendCommand({ action:'scan_now', label:'Re-scan' })}
                    style={{ padding:'8px 16px', borderRadius:8, border:`1px solid ${D.cyan}44`, background:'transparent', color:D.cyan, fontWeight:700, fontSize:11, cursor:'pointer' }}>
                    🔬 Re-scan
                  </button>
                </div>
              </div>
            </GlowCard>
          ))
        }
      </div>
    );
  };

  // ── Mitigations ────────────────────────────────────────────────────────────
  const renderMitigations = () => {
    const mits = data?.mitigations || [];
    return (
      <div style={{ animation:'fade-in 0.3s ease' }}>
        <h3 style={{ fontSize:14, fontWeight:800, color:D.white, marginBottom:4 }}>🛡️ Mitigation Log ({mits.length})</h3>
        <p style={{ fontSize:11, color:D.muted, marginBottom:16 }}>All defense actions executed on this device · Sent to LeoNet Defense when connected</p>

        {/* Manual command panel */}
        <GlowCard color={D.purple} style={{ padding:22, marginBottom:18 }}>
          <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>⚡ Manual Command Console</div>
          <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
            {[
              { label:'Scan Now',           cmd:{ action:'scan_now' },         color:D.cyan   },
              { label:'Isolate Network',    cmd:{ action:'isolate_network' },  color:D.red    },
            ].map(({ label, cmd, color }) => (
              <button key={label} onClick={() => { if (cmd.action==='isolate_network' && !window.confirm('This will disable ALL network interfaces on the monitored device. Are you sure?')) return; sendCommand(cmd); }}
                style={{ padding:'10px 18px', borderRadius:8, border:`1px solid ${color}44`, background:`${color}12`, color, fontWeight:700, fontSize:12, cursor:'pointer' }}>
                {label}
              </button>
            ))}
          </div>
        </GlowCard>

        {mits.length === 0
          ? <GlowCard color={D.muted} style={{ padding:40, textAlign:'center' }}><div style={{ color:D.muted }}>No mitigations executed yet</div></GlowCard>
          : mits.map((m, i) => (
            <div key={i} style={{ display:'flex', gap:14, padding:'14px 18px', background: m.success ? 'rgba(0,255,136,0.05)' : 'rgba(255,107,53,0.05)', border:`1px solid ${m.success?D.green:D.orange}33`, borderRadius:10, marginBottom:8 }}>
              <div style={{ fontSize:20 }}>{m.success ? '✅' : '⚠️'}</div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:11, fontWeight:700, color:m.success?D.green:D.orange }}>{m.action?.toUpperCase()?.replace(/_/g,' ')} — {m.success?'SUCCESS':'FAILED'}</div>
                <div style={{ fontSize:10, color:D.text, marginTop:3 }}>{m.output}</div>
                <div style={{ fontSize:9, color:D.muted, marginTop:4 }}>{m.executedAt ? new Date(m.executedAt).toLocaleString() : ''}</div>
              </div>
            </div>
          ))
        }
      </div>
    );
  };

  // ── Settings ───────────────────────────────────────────────────────────────
  const renderSettings = () => (
    <div style={{ animation:'fade-in 0.3s ease' }}>
      <h3 style={{ fontSize:14, fontWeight:800, color:D.white, marginBottom:4 }}>🔧 Sentinel Settings</h3>
      <p style={{ fontSize:11, color:D.muted, marginBottom:20 }}>Configure the connection to LeoNet Defense · Two-way threat sharing and remote command execution</p>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18 }}>
        <GlowCard color={D.blue} style={{ padding:26 }}>
          <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:20 }}>🔗 LeoNet Defense Connection</div>

          <div style={{ marginBottom:16 }}>
            <div style={{ fontSize:10, color:D.muted, fontWeight:700, marginBottom:6, textTransform:'uppercase', letterSpacing:1 }}>LeoNet Defense URL</div>
            <input value={leoNetInput} onChange={e=>setLeoNetInput(e.target.value)}
              placeholder="https://leonet-defense.vercel.app"
              style={{ width:'100%', padding:'10px 14px', background:'#081420', border:`1px solid ${D.border}`, borderRadius:8, color:D.white, fontSize:12, outline:'none', boxSizing:'border-box' }} />
            <div style={{ fontSize:9, color:D.muted, marginTop:5 }}>Your deployed LeoNet Defense URL</div>
          </div>

          <div style={{ marginBottom:16 }}>
            <div style={{ fontSize:10, color:D.muted, fontWeight:700, marginBottom:6, textTransform:'uppercase', letterSpacing:1 }}>Sentinel Shared Key</div>
            <input type="password" value={apiKeyInput} onChange={e=>setApiKeyInput(e.target.value)}
              placeholder="Same key set as SENTINEL_SHARED_KEY on LeoNet Defense"
              style={{ width:'100%', padding:'10px 14px', background:'#081420', border:`1px solid ${D.border}`, borderRadius:8, color:D.white, fontSize:12, outline:'none', boxSizing:'border-box' }} />
            <div style={{ fontSize:9, color:D.muted, marginTop:5 }}>Required — without it, LeoNet Defense rejects this agent's reports and commands. Never echoed back once saved.</div>
          </div>

          <button onClick={saveLeoNet}
            style={{ width:'100%', padding:'12px', borderRadius:10, border:'none', background:`linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', fontWeight:800, fontSize:13, cursor:'pointer' }}>
            💾 Save &amp; Connect
          </button>

          <div style={{ marginTop:20, padding:'14px 16px', background:'rgba(0,212,255,0.06)', border:`1px solid ${D.cyan}22`, borderRadius:10 }}>
            <div style={{ fontSize:11, fontWeight:700, color:D.cyan, marginBottom:8 }}>Connection Status</div>
            <div style={{ display:'flex', gap:8, alignItems:'center' }}>
              <div style={{ width:8, height:8, borderRadius:'50%', background: leonet.connected?D.green:D.orange, animation: leonet.connected?'pulse-glow 2s infinite':'none' }} />
              <span style={{ fontSize:11, color: leonet.connected?D.green:D.orange, fontWeight:700 }}>
                {leonet.connected ? 'Connected — Live data streaming' : 'Not Connected'}
              </span>
            </div>
            {cfg.leoNetUrl && <div style={{ fontSize:9, color:D.muted, marginTop:6 }}>{mask(cfg.leoNetUrl)}</div>}
          </div>
        </GlowCard>

        <GlowCard color={D.purple} style={{ padding:26 }}>
          <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:20 }}>🦁 Agent Identity</div>
          {[
            ['Agent ID',    mask(cfg.agentId   || '—')],
            ['Agent Name',  mask(cfg.agentName || '—')],
            ['Platform',    data?.system?.platform || '—'],
            ['Hostname',    mask(data?.system?.hostname || '—')],
            ['Last Scan',   data?.lastScan ? new Date(data.lastScan).toLocaleString() : 'Never'],
            ['Scans Total', String(data?.scanCount || 0)],
          ].map(([k,v]) => (
            <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:10, padding:'8px 12px', background:'#081420', borderRadius:6 }}>
              <span style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1, fontWeight:700 }}>{k}</span>
              <span style={{ fontSize:10, color:D.text, fontFamily:'monospace' }}>{v}</span>
            </div>
          ))}

          <div style={{ marginTop:16, padding:'12px 14px', background:'rgba(0,255,136,0.06)', border:`1px solid ${D.green}22`, borderRadius:10, fontSize:10, color:D.green, lineHeight:1.7 }}>
            ✅ Sentinel is active and scanning every 10 seconds.<br/>
            Threats are detected using: process names · known bad ports · suspicious IPs · CPU/memory anomalies.
          </div>
        </GlowCard>
      </div>

      <GlowCard color={D.gold} style={{ padding:24, marginTop:18 }}>
        <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:14 }}>📋 How to Use LeoNet Sentinel</div>
        {[
          ['Desktop App',   'Double-click LeoNet Sentinel to launch. Runs in system tray. Dashboard opens at localhost:3001'],
          ['Headless Mode', 'Run: node server/index.js — then open http://localhost:3001 in any browser on the device'],
          ['Connect',       'Set LEONET_URL and LEONET_KEY (or enter them in the fields above) — both are required to authenticate with LeoNet Defense'],
          ['Mitigations',   'LeoNet Defense sends Kill/Block/Isolate commands to this Sentinel in real-time'],
          ['Scans',         'Every 10 seconds: process table, netstat, CPU/memory — threats auto-push to LeoNet Defense'],
        ].map(([step, desc]) => (
          <div key={step} style={{ display:'flex', gap:12, marginBottom:10 }}>
            <span style={{ fontSize:11, fontWeight:800, color:D.gold, minWidth:100 }}>{step}</span>
            <span style={{ fontSize:11, color:D.text }}>{desc}</span>
          </div>
        ))}
      </GlowCard>
    </div>
  );

  const renderTab = () => {
    switch(tab) {
      case 'overview':    return renderOverview();
      case 'processes':   return renderProcesses();
      case 'network':     return renderNetwork();
      case 'threats':     return renderThreats();
      case 'mitigations': return renderMitigations();
      case 'settings':    return renderSettings();
      default:            return renderOverview();
    }
  };

  const threats = data?.threats || [];

  return (
    <div style={{ display:'flex', flexDirection:'column', minHeight:'100vh', background:D.bg }}>
      {/* Watermark logo — fixed, centered, behind all content */}
      <div style={{ position:'fixed', top:'50%', left:'50%', transform:'translate(-50%,-50%)', pointerEvents:'none', zIndex:0, userSelect:'none' }}>
        <img src="/logo.jpg" alt="" style={{ width:420, height:420, objectFit:'contain', opacity:0.07, borderRadius:32, filter:'drop-shadow(0 0 40px #FF6B3544)' }} />
      </div>
      {/* DevTools tamper alert */}
      {devOpen && (
        <div style={{ position:'fixed', top:0, left:0, right:0, zIndex:99999, background:'#FF2D55', color:'#fff', padding:'10px 20px', display:'flex', alignItems:'center', gap:12, fontSize:12, fontWeight:800, letterSpacing:0.5 }}>
          <span style={{ fontSize:16 }}>⛔</span>
          SECURITY ALERT — Inspection panel detected. All sensitive device data has been nullified.
          <span style={{ marginLeft:'auto', fontSize:11, opacity:0.8 }}>Close DevTools to restore view.</span>
        </div>
      )}
      {/* Toast */}
      {toast && (
        <div style={{ position:'fixed', top:16, right:16, zIndex:9999, padding:'12px 20px', background:D.surface, border:`1px solid ${toast.color}66`, borderRadius:10, color:toast.color, fontWeight:700, fontSize:12, boxShadow:`0 4px 24px rgba(0,0,0,0.4)`, animation:'fade-in 0.2s ease', maxWidth:340 }}>
          {toast.msg}
        </div>
      )}

      {/* Top bar */}
      <div style={{ background:D.surface, borderBottom:`1px solid ${D.border}`, padding:'0 20px', display:'flex', alignItems:'center', justifyContent:'space-between', height:56, flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'center', gap:14 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <img src="/logo.jpg" alt="LeoNet Sentinel" style={{ width:34, height:34, borderRadius:8, objectFit:'cover', boxShadow:`0 0 14px ${D.orange}88` }} />
            <span style={{ fontSize:18, fontWeight:900, color:D.cyan, letterSpacing:-0.5 }}>LeoNet <span style={{ color:D.orange }}>Sentinel</span></span>
          </div>
          <span style={{ fontSize:10, color:D.muted, background:'#1A3A5F', padding:'2px 8px', borderRadius:10 }}>DEVICE AGENT</span>
        </div>

        <div style={{ display:'flex', alignItems:'center', gap:16 }}>
          {/* Connection dots */}
          <div style={{ display:'flex', alignItems:'center', gap:6 }}>
            <div style={{ width:7, height:7, borderRadius:'50%', background: connected?D.green:D.red, animation: connected?'pulse-glow 2s infinite':'none' }} />
            <span style={{ fontSize:10, color: connected?D.green:D.red, fontWeight:700 }}>{connected?'LIVE':'OFFLINE'}</span>
          </div>
          <div style={{ width:1, height:20, background:D.border }} />
          <div style={{ display:'flex', alignItems:'center', gap:6 }}>
            <div style={{ width:7, height:7, borderRadius:'50%', background: leonet.connected?D.cyan:D.muted }} />
            <span style={{ fontSize:10, color: leonet.connected?D.cyan:D.muted, fontWeight:700 }}>LEONET {leonet.connected?'SYNC':'UNLINKED'}</span>
          </div>
          <div style={{ width:1, height:20, background:D.border }} />
          <div style={{ fontSize:10, color: threats.length>0?D.red:D.green, fontWeight:800 }}>
            {threats.length > 0 ? `⚠️ ${threats.length} THREAT${threats.length>1?'S':''}` : '✅ CLEAN'}
          </div>
          <button onClick={scan} disabled={scanning}
            style={{ padding:'7px 16px', borderRadius:8, border:'none', background: scanning ? D.muted : `linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', fontWeight:800, fontSize:11, cursor: scanning?'not-allowed':'pointer', opacity: scanning?0.7:1 }}>
            {scanning ? '⏳ Scanning…' : '🔬 Scan'}
          </button>
        </div>
      </div>

      {/* Nav tabs */}
      <div style={{ background:D.surface, borderBottom:`1px solid ${D.border}`, padding:'0 20px', display:'flex', gap:2, overflowX:'auto' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding:'10px 16px', background:'none', border:'none', borderBottom: tab===t.id?`2px solid ${D.cyan}`:'2px solid transparent', color: tab===t.id?D.white:D.muted, cursor:'pointer', fontSize:12, fontWeight: tab===t.id?700:400, whiteSpace:'nowrap', transition:'color 0.15s', flexShrink:0 }}>
            {t.icon} {t.label}
            {t.id==='threats' && threats.length>0 && (
              <span style={{ marginLeft:6, background:D.red, color:'#fff', borderRadius:10, fontSize:9, fontWeight:900, padding:'1px 6px' }}>{threats.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex:1, padding:'24px 20px 40px', maxWidth:1400, margin:'0 auto', width:'100%' }}>
        {!connected
          ? (
            <div style={{ textAlign:'center', padding:80, color:D.muted }}>
              <div style={{ fontSize:40, marginBottom:12, animation:'spin 1s linear infinite', display:'inline-block' }}>⚙️</div>
              <div style={{ fontSize:16, fontWeight:700 }}>Connecting to Sentinel engine…</div>
              <div style={{ fontSize:12, marginTop:6 }}>Make sure the server is running: <code style={{ color:D.cyan }}>npm start</code></div>
            </div>
          )
          : renderTab()
        }
      </div>
    </div>
  );
}
