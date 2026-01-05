import React, { useState, useEffect } from 'react';
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    PieChart, Pie, Cell, Legend
} from 'recharts';
import { Activity, ShieldAlert, Globe, AlertTriangle, List, CheckCircle, Plus, Trash2, FileText, Lock, X, Microscope } from 'lucide-react';

const Dashboard = () => {
    // State for Real Data
    const [data, setData] = useState([]);
    const [metrics, setMetrics] = useState({
        total_events: 0,
        active_threats: 0,
        temp_isolate: 0,
        quarantined: 0,
        rollbacks: 0,
        phi_attempts: 0,
        recent_alerts: []
    });

    // Device Management State
    const [showAddDevice, setShowAddDevice] = useState(false);
    const [newDeviceIp, setNewDeviceIp] = useState('');
    const [isAdding, setIsAdding] = useState(false);
    const [reportStatus, setReportStatus] = useState('IDLE'); // IDLE, GENERATING, DONE

    // Details Modal State
    const [selectedMetric, setSelectedMetric] = useState(null); // 'TEMP_ISOLATE', 'QUARANTINED', 'ROLLBACKS', 'PHI'
    const [modalData, setModalData] = useState([]);
    const [modalLoading, setModalLoading] = useState(false);

    // Charts Data
    const [trafficData, setTrafficData] = useState([]);

    // IoMT State
    const [iomtPrio, setIomtPrio] = useState('MONITORING');
    const [threatLevel, setThreatLevel] = useState('LOW'); // Added threatLevel state

    useEffect(() => {
        const fetchData = async () => {
            try {
                // 1. Fetch Traffic Stream
                const trafficRes = await fetch('http://localhost:5000/api/traffic');
                const trafficJson = await trafficRes.json();

                setTrafficData(prev => {
                    const newData = [...prev, {
                        time: trafficJson.time,
                        cpu: trafficJson.cpu_load,
                        packets: trafficJson.packets
                    }];
                    return newData.slice(-20); // Keep last 20
                });

                // Update IoMT (Automated)
                if (trafficJson.iomt) {
                    setIomtPrio(trafficJson.iomt.priority);
                    setThreatLevel(trafficJson.iomt.threat_level || 'LOW'); // Assuming iomt has threat_level
                }

                // 2. Fetch Aggregated Stats & Alerts
                const statsRes = await fetch('http://localhost:5000/api/stats');
                const statsJson = await statsRes.json();
                setMetrics(statsJson);

            } catch (err) {
                console.error("Dash API Error:", err);
            }
        };

        const interval = setInterval(fetchData, 1000);
        return () => clearInterval(interval);
    }, []);

    const handleAddDevice = async () => {
        if (!newDeviceIp) return;
        setIsAdding(true);
        try {
            await fetch('http://localhost:5000/api/devices/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({ ip: newDeviceIp, type: "Manual Entry" })
            });
            setShowAddDevice(false);
            setNewDeviceIp('');
            // Optional: Trigger a refresh or toast here
        } catch (err) {
            console.error(err);
        } finally {
            setIsAdding(false);
        }
    };

    const handleGenerateReport = async () => {
        setReportStatus('GENERATING');
        try {
            const response = await fetch('http://localhost:5000/api/report');
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = "ARS_Security_Report.pdf";
                document.body.appendChild(a);
                a.click();
                a.remove();
                setReportStatus('DONE');
            } else {
                console.error("Report generation failed");
                setReportStatus('IDLE');
            }
        } catch (err) {
            console.error(err);
            setReportStatus('IDLE');
        }
        setTimeout(() => setReportStatus('IDLE'), 5000);
    };

    // --- HANDLE CARD CLICKS ---
    const handleCardClick = async (metricType) => {
        setSelectedMetric(metricType);
        setModalLoading(true);
        setModalData([]);

        try {
            let endpoint = '';
            let filterFn = null;

            if (metricType === 'TEMP_ISOLATE') {
                endpoint = 'http://localhost:5000/api/devices';
                filterFn = (data) => data.filter(d => d.status === 'ISOLATING').map(d => ({
                    col1: d.ip, col2: d.lastSeen, col3: 'High Risk (Isolating)'
                }));
            } else if (metricType === 'QUARANTINED') {
                endpoint = 'http://localhost:5000/api/devices';
                filterFn = (data) => data.filter(d => d.status === 'QUARANTINED').map(d => ({
                    col1: d.ip, col2: d.lastSeen, col3: 'Confirmed Threat'
                }));
            } else if (metricType === 'ROLLBACKS') {
                endpoint = 'http://localhost:5000/api/history';
                filterFn = (data) => data.filter(d => d.decision === 'ROLLBACK').slice(-20).map(d => ({
                    col1: d.src_ip, col2: d.timestamp, col3: 'False Positive Cleared'
                }));
            } else if (metricType === 'PHI') {
                endpoint = 'http://localhost:5000/api/privacy';
                filterFn = (data) => data.slice(-20).map(d => ({
                    col1: d.src_ip, col2: d.timestamp, col3: 'PHI Redacted'
                }));
            }

            const res = await fetch(endpoint);
            const json = await res.json();
            if (filterFn) {
                setModalData(filterFn(json));
            } else {
                setModalData(json);
            }
        } catch (err) {
            console.error("Failed to fetch detail data", err);
        } finally {
            setModalLoading(false);
        }
    };

    // Static Data for Visuals (Donut)
    const agentStatus = [
        { name: 'Active', value: 45, color: '#3b82f6' }, // Blue-500
        { name: 'Offline', value: 2, color: '#64748b' } // Slate-500
    ];

    return (
        <div className="space-y-6 text-slate-100">

            {/* --- ADMIN TOOLBAR --- */}
            <div className="flex justify-between items-center bg-slate-800/50 p-4 rounded-lg border border-slate-700 backdrop-blur-sm">
                <div className="flex items-center gap-4">
                    <button
                        onClick={() => setShowAddDevice(!showAddDevice)}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-bold transition-all shadow-lg hover:shadow-blue-500/25">
                        <Plus className="w-4 h-4" /> Add Device
                    </button>
                    {showAddDevice && (
                        <div className="flex gap-2 animate-fade-in-right">
                            <input
                                type="text"
                                placeholder="192.168.1.x"
                                className="bg-slate-900 border border-slate-600 rounded px-3 text-sm focus:outline-none focus:border-blue-500"
                                value={newDeviceIp}
                                onChange={(e) => setNewDeviceIp(e.target.value)}
                            />
                            <button
                                onClick={handleAddDevice}
                                disabled={isAdding}
                                className="text-emerald-400 hover:text-emerald-300 font-bold text-sm disabled:opacity-50 disabled:cursor-not-allowed">
                                {isAdding ? 'SAVING...' : 'SAVE'}
                            </button>
                        </div>
                    )}
                </div>

                <div className="flex gap-2">
                    {/* IoMT AI STATUS CARD - AUTOMATED */}
                    <div className={`flex items-center gap-3 px-4 py-2 rounded-lg border shadow-lg transition-all 
                        ${iomtPrio === 'CRITICAL' ? 'bg-red-950/50 border-red-500 text-red-500 animate-pulse' :
                            iomtPrio === 'HIGH' ? 'bg-orange-950/50 border-orange-500 text-orange-500' :
                                'bg-slate-900 border-slate-700 text-slate-400'}`}>
                        <Microscope className="w-5 h-5" />
                        <div className="flex flex-col leading-tight">
                            <span className="text-[10px] uppercase font-bold tracking-widest opacity-70">AI THREAT LEVEL</span>
                            <span className="text-sm font-black tracking-wide">{iomtPrio}</span>
                        </div>
                    </div>

                    <button
                        onClick={handleGenerateReport}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-lg
                        ${reportStatus === 'GENERATING' ? 'bg-amber-600 animate-pulse' :
                                reportStatus === 'DONE' ? 'bg-emerald-600' : 'bg-slate-700 hover:bg-slate-600 text-white'}`}>
                        <FileText className="w-4 h-4" />
                        {reportStatus === 'GENERATING' ? 'Generating PDF...' :
                            reportStatus === 'DONE' ? 'Report Downloaded!' : 'Generate Report'}
                    </button>
                </div>
            </div>

            {/* --- ROW 1: RESPONSE FLOW METRICS --- */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <KPICard
                    title="Temp. Isolate"
                    value={metrics.metrics?.temp_isolate || 0}
                    icon={AlertTriangle}
                    color="text-amber-400"
                    border="border-l-4 border-amber-500"
                    onClick={() => handleCardClick('TEMP_ISOLATE')}
                />
                <KPICard
                    title="Quarantined"
                    value={metrics.metrics?.quarantined || 0}
                    icon={ShieldAlert}
                    color="text-red-500"
                    border="border-l-4 border-red-500"
                    onClick={() => handleCardClick('QUARANTINED')}
                />
                <KPICard
                    title="Rollbacks"
                    value={metrics.metrics?.rollbacks || 0}
                    icon={CheckCircle}
                    color="text-emerald-400"
                    border="border-l-4 border-emerald-500"
                    onClick={() => handleCardClick('ROLLBACKS')}
                />
                <KPICard
                    title="PHI Blocked"
                    value={metrics.metrics?.phi_attempts || 0}
                    icon={Lock}
                    color="text-violet-400"
                    border="border-l-4 border-violet-500"
                    onClick={() => handleCardClick('PHI')}
                />
            </div>

            {/* --- ROW 2: CHARTS GRID --- */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* 1. AGENT STATUS (Donut) */}
                <div className="bg-slate-800/80 p-4 rounded shadow-lg border border-slate-700">
                    <h3 className="text-sm font-bold text-slate-300 mb-4 flex gap-2"><Globe className="w-4 h-4" /> Agent Status</h3>
                    <div className="h-48">
                        <ResponsiveContainer>
                            <PieChart>
                                <Pie data={agentStatus} innerRadius={50} outerRadius={70} paddingAngle={5} dataKey="value">
                                    {agentStatus.map((e, i) => <Cell key={i} fill={e.color} />)}
                                </Pie>
                                <Legend />
                                <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* 2. LIVE TRAFFIC (Area) */}
                <div className="lg:col-span-2 bg-slate-800/80 p-4 rounded shadow-lg border border-slate-700">
                    <h3 className="text-sm font-bold text-slate-300 mb-4 flex gap-2"><Activity className="w-4 h-4" /> Live Network & Vitals</h3>
                    <div className="h-48">
                        <ResponsiveContainer>
                            <AreaChart data={data}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 10 }} interval={5} />

                                {/* Left Axis: System Load (0-100%) */}
                                <YAxis yAxisId="left" stroke="#3b82f6" domain={[0, 100]} tick={{ fill: '#3b82f6' }} label={{ value: 'Load %', angle: -90, position: 'insideLeft', fill: '#3b82f6' }} />

                                {/* Right Axis: Network Traffic (Auto) */}
                                <YAxis yAxisId="right" orientation="right" stroke="#f59e0b" tick={{ fill: '#f59e0b' }} label={{ value: 'Pkts/s', angle: 90, position: 'insideRight', fill: '#f59e0b' }} />

                                <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }} />

                                <Area yAxisId="left" type="monotone" dataKey="cpu" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} name="System Load %" />
                                <Area yAxisId="right" type="monotone" dataKey="packets" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.2} name="Packets/s" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

            </div>

            {/* --- ROW 3: ALL ALERTS TABLE --- */}
            <div className="bg-slate-800/80 p-4 rounded shadow-lg border border-slate-700">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-sm font-bold text-slate-300 flex gap-2"><AlertTriangle className="w-4 h-4 text-amber-500" /> Security Events Log</h3>
                    <div className="text-xs text-slate-500 font-mono">LIVE FEED</div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm text-slate-400">
                        <thead className="bg-slate-900 uppercase font-mono text-xs">
                            <tr>
                                <th className="p-3">Timestamp</th>
                                <th className="p-3">Severity</th>
                                <th className="p-3">Event Type</th>
                                <th className="p-3">Source Data</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-700">
                            {metrics.recent_alerts.length === 0 ? (
                                <tr><td colSpan="4" className="p-4 text-center italic opacity-50">No alerts recorded yet...</td></tr>
                            ) : (
                                metrics.recent_alerts.slice().reverse().map((alert, idx) => (
                                    <tr key={idx} className="hover:bg-slate-700/50 transition-colors">
                                        <td className="p-3 font-mono text-slate-300">{alert.timestamp || new Date().toLocaleTimeString()}</td>
                                        <td className="p-3">
                                            <span className={`px-2 py-0.5 rounded text-xs font-bold ${alert.event_type === 'DANGER' ? 'bg-red-900/50 text-red-400 border border-red-800' : 'bg-emerald-900/50 text-emerald-400 border border-emerald-800'
                                                }`}>
                                                {alert.event_type === 'DANGER' ? 'CRITICAL' : 'INFO'}
                                            </span>
                                        </td>
                                        <td className="p-3 text-white font-medium">{alert.event_type} DETECTED</td>
                                        <td className="p-3 font-mono text-xs overflow-hidden max-w-xs truncate">
                                            {JSON.stringify(alert).slice(0, 80)}...
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* --- DETAILS MODAL --- */}
            {selectedMetric && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in duration-200">
                    <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 w-full max-w-2xl shadow-2xl max-h-[80vh] flex flex-col">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                                <List className="text-blue-500" />
                                {selectedMetric === 'TEMP_ISOLATE' && "Devices in Temporary Isolation"}
                                {selectedMetric === 'QUARANTINED' && "Terminally Quarantined Devices"}
                                {selectedMetric === 'ROLLBACKS' && "Recent False Positive Rollbacks"}
                                {selectedMetric === 'PHI' && "PHI Privacy Blocks"}
                            </h3>
                            <button onClick={() => setSelectedMetric(null)} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
                        </div>

                        <div className="flex-1 overflow-auto bg-slate-950 rounded-lg border border-slate-800">
                            <table className="w-full text-left font-mono text-sm">
                                <thead className="bg-slate-900 text-slate-400 text-xs uppercase sticky top-0">
                                    <tr>
                                        <th className="p-3">Primary ID (IP)</th>
                                        <th className="p-3">Timestamp / Last Seen</th>
                                        <th className="p-3">Status Detail</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800 text-slate-300">
                                    {modalLoading ? (
                                        <tr><td colSpan="3" className="p-8 text-center text-blue-400">Loading data...</td></tr>
                                    ) : modalData.length === 0 ? (
                                        <tr><td colSpan="3" className="p-8 text-center text-slate-500 italic">No records found for this category.</td></tr>
                                    ) : (
                                        modalData.map((row, i) => (
                                            <tr key={i} className="hover:bg-slate-800/30">
                                                <td className="p-3 font-bold text-blue-400">{row.col1}</td>
                                                <td className="p-3 text-slate-400">{row.col2}</td>
                                                <td className="p-3">
                                                    <span className="px-2 py-1 bg-slate-800 rounded text-xs border border-slate-700">
                                                        {row.col3}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                        <div className="mt-4 text-right">
                            <button onClick={() => setSelectedMetric(null)} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded text-sm font-bold border border-slate-600">
                                Close Details
                            </button>
                        </div>
                    </div>
                </div>
            )}

        </div>
    );
};

// Reusable KPI Component
const KPICard = ({ title, value, icon: Icon, color, border, onClick }) => (
    <div
        onClick={onClick}
        className={`bg-slate-800/90 p-4 rounded shadow-lg flex items-center justify-between ${border} cursor-pointer hover:bg-slate-700/80 transition-all hover:scale-[1.02] group`}
    >
        <div>
            <p className="text-slate-400 text-xs uppercase font-bold tracking-wider group-hover:text-white transition-colors">{title}</p>
            <p className="text-2xl font-bold text-white mt-1">{value}</p>
        </div>
        <Icon className={`w-8 h-8 ${color} opacity-80 group-hover:opacity-100 group-hover:drop-shadow-lg transition-all`} />
    </div>
);

export default Dashboard;
