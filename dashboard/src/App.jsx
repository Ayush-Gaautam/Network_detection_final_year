import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertOctagon, BarChart3, Bell, ChevronRight, Cpu, Database,
  FileWarning, Gauge, LayoutDashboard, Menu, Network, Search, Settings,
  ShieldCheck, SlidersHorizontal, Table2, X, Zap,
} from 'lucide-react'

import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line,
  LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

import {
  getAnalytics,
  getAnomalies,
  getDashboardStats,
  getPackets,
  getTraffic,
} from './services/api'

import NetworkTopology from './components/NetworkTopology'


// ============================================================
// NAVIGATION
// ============================================================

const navItems = [
  { label: 'Dashboard', icon: LayoutDashboard, route: 'dashboard' },
  { label: 'Live Monitoring', icon: Activity, route: 'monitoring' },
  { label: 'Anomalies', icon: AlertOctagon, route: 'anomalies' },
  { label: 'Analytics', icon: BarChart3, route: 'analytics' },
  { label: 'Network Traffic', icon: Network, route: 'traffic' },
]


// ============================================================
// HELPERS
// ============================================================

const formatNumber = (value) =>
  new Intl.NumberFormat('en-US').format(Number(value) || 0)

const percentage = (part, total) => {
  if (!total) return '0.00'
  return ((part / total) * 100).toFixed(2)
}

const severityClass = (severity = 'Low') =>
  `severity severity-${String(severity).toLowerCase()}`


// ============================================================
// MAIN APP
// ============================================================

function App() {
  const [route, setRoute] = useState(
    window.location.hash.replace('#/', '') || 'dashboard'
  )

  const [stats, setStats] = useState(null)
  const [traffic, setTraffic] = useState([])
  const [anomalies, setAnomalies] = useState([])
  const [packets, setPackets] = useState([])
  const [analytics, setAnalytics] = useState(null)

  const [mobileNav, setMobileNav] = useState(false)
  const [selectedAnomaly, setSelectedAnomaly] = useState(null)

  // ----------------------------------------------------------
  // LOAD DATA FROM FASTAPI
  // ----------------------------------------------------------

  const loadData = async () => {
    try {
      const [
        dashboardStats,
        liveTraffic,
        liveAnomalies,
        livePackets,
        analyticsData,
      ] = await Promise.all([
        getDashboardStats(),
        getTraffic(),
        getAnomalies(),
        getPackets(),
        getAnalytics(),
      ])

      setStats(dashboardStats)
      setTraffic(liveTraffic)
      setAnomalies(liveAnomalies)
      setPackets(livePackets)
      setAnalytics(analyticsData)
    } catch (error) {
      console.error('Failed to load backend data:', error)
    }
  }

  useEffect(() => {
    loadData()

    const refreshTimer = setInterval(() => {
      loadData()
    }, 10000)

    const onHashChange = () => {
      setRoute(window.location.hash.replace('#/', '') || 'dashboard')
      setMobileNav(false)
    }

    window.addEventListener('hashchange', onHashChange)

    return () => {
      clearInterval(refreshTimer)
      window.removeEventListener('hashchange', onHashChange)
    }
  }, [])

  if (!stats || !analytics) {
    return (
      <div className="loading-screen">
        <ShieldCheck size={30} />
        <span>Initializing secure telemetry...</span>
      </div>
    )
  }

  const pageTitle =
    navItems.find((item) => item.route === route)?.label || 'Dashboard'

  return (
    <div className="app-shell">

      <Sidebar
        route={route}
        mobileNav={mobileNav}
        onClose={() => setMobileNav(false)}
      />

      <main className="main-content">

        <Header
          title={pageTitle}
          onMenu={() => setMobileNav(true)}
        />

        <div className="page-content">

          {route === 'dashboard' && (
            <Dashboard
              stats={stats}
              traffic={traffic}
              anomalies={anomalies}
              packets={packets}
            />
          )}

          {route === 'monitoring' && (
            <Monitoring
              traffic={traffic}
              packets={packets}
              stats={stats}
            />
          )}

          {route === 'anomalies' && (
            <Anomalies
              anomalies={anomalies}
              onSelect={setSelectedAnomaly}
            />
          )}

          {route === 'analytics' && (
            <Analytics
              analytics={analytics}
              stats={stats}
              packets={packets}
              anomalies={anomalies}
            />
          )}

          {route === 'traffic' && (
            <TrafficTable packets={packets} />
          )}

          {route === 'settings' && <SettingsPage />}

        </div>
      </main>

      {selectedAnomaly && (
        <AnomalyModal
          anomaly={selectedAnomaly}
          onClose={() => setSelectedAnomaly(null)}
        />
      )}

    </div>
  )
}


// ============================================================
// SIDEBAR
// ============================================================

function Sidebar({ route, mobileNav, onClose }) {
  return (
    <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>

      <div className="brand">
        <div className="brand-mark">
          <ShieldCheck size={20} />
        </div>

        <div>
          <strong>
            NetGuard<span> AI</span>
          </strong>
          <small>NETWORK DEFENSE</small>
        </div>

        <button
          className="icon-button sidebar-close"
          onClick={onClose}
        >
          <X size={17} />
        </button>
      </div>

      <div className="nav-section-label">
        COMMAND RAIL
      </div>

      <nav>
        {navItems.map(({ label, icon: Icon, route: target }) => (
          <a
            href={`#/${target}`}
            className={`nav-item ${route === target ? 'active' : ''}`}
            key={target}
          >
            <Icon size={16} />
            <span>{label}</span>

            {route === target && (
              <ChevronRight
                className="nav-chevron"
                size={13}
              />
            )}
          </a>
        ))}
      </nav>

      <div className="nav-section-label nav-section-lower">
        SYSTEM
      </div>

      <a
        href="#/settings"
        className={`nav-item ${route === 'settings' ? 'active' : ''}`}
      >
        <Settings size={16} />
        <span>Settings</span>
      </a>

      <div className="sidebar-footer">

        <div className="status-block">
          <span className="live-dot" />
          <span>System operational</span>
          <strong>CONNECTED</strong>
        </div>

        <div className="sensor-row">
          <Database size={13} />
          <span>Sensor cluster</span>
          <span className="status-online">ONLINE</span>
        </div>

        <div className="sensor-row">
          <Cpu size={13} />
          <span>Inference engine</span>
          <span className="status-online">READY</span>
        </div>

      </div>

    </aside>
  )
}


// ============================================================
// HEADER
// ============================================================

function Header({ title, onMenu }) {
  return (
    <header className="top-header">

      <button
        className="icon-button menu-button"
        onClick={onMenu}
      >
        <Menu size={20} />
      </button>

      <div>
        <p className="eyebrow">
          NETGUARD AI // SOC CONSOLE
        </p>

        <h1>
          {title === 'Dashboard'
            ? 'Network Intelligence'
            : title}
        </h1>
      </div>

      <div className="header-actions">

        <div className="system-live">
          <span className="live-dot" />
          PERIMETER LIVE
        </div>

        <button className="icon-button notification">
          <Bell size={17} />
          <i />
        </button>

        <div className="profile">
          <div className="avatar">JD</div>

          <div>
            <strong>J. Doe</strong>
            <span>Analyst</span>
          </div>
        </div>

      </div>

    </header>
  )
}


// ============================================================
// STAT CARD
// ============================================================

function StatCard({
  label,
  value,
  detail,
  icon: Icon,
  accent,
}) {
  return (
    <div className={`stat-card ${accent}`}>

      <div className="stat-card-top">
        <span>{label}</span>

        <div className="stat-icon">
          <Icon size={16} />
        </div>
      </div>

      <strong>{value}</strong>

      <div className="stat-detail">
        {detail}
      </div>

    </div>
  )
}


// ============================================================
// SECTION HEADER
// ============================================================

function SectionHeader({
  eyebrow,
  title,
  action,
}) {
  return (
    <div className="section-header">

      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h2>{title}</h2>
      </div>

      {action}

    </div>
  )
}


// ============================================================
// CHART TOOLTIP
// ============================================================

function ChartTooltip({
  active,
  payload,
  label,
}) {
  if (!active || !payload?.length) {
    return null
  }

  return (
    <div className="chart-tooltip">

      <strong>{label}</strong>

      {payload.map((item) => (
        <span key={item.name}>
          <i style={{ background: item.color }} />
          {item.name}: <b>{item.value}</b>
        </span>
      ))}

    </div>
  )
}


// ============================================================
// TRAFFIC CHART
// ============================================================

function TrafficChart({
  data,
  compact = false,
}) {
  return (
    <ResponsiveContainer
      width="100%"
      height={compact ? 220 : 290}
    >

      <AreaChart
        data={data}
        margin={{
          top: 10,
          right: 0,
          left: -20,
          bottom: 0,
        }}
      >

        <defs>

          <linearGradient
            id="normalFill"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop
              offset="0%"
              stopColor="#818cf8"
              stopOpacity=".28"
            />

            <stop
              offset="100%"
              stopColor="#818cf8"
              stopOpacity="0"
            />
          </linearGradient>

          <linearGradient
            id="anomalyFill"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop
              offset="0%"
              stopColor="#ef4444"
              stopOpacity=".28"
            />

            <stop
              offset="100%"
              stopColor="#ef4444"
              stopOpacity="0"
            />
          </linearGradient>

        </defs>

        <CartesianGrid
          stroke="#1e1b4b"
          strokeDasharray="3 3"
          vertical={false}
        />

        <XAxis
          dataKey="time"
          stroke="#64748b"
          tickLine={false}
          axisLine={false}
          fontSize={10}
        />

        <YAxis
          stroke="#64748b"
          tickLine={false}
          axisLine={false}
          fontSize={10}
        />

        <Tooltip content={<ChartTooltip />} />

        <Legend
          iconType="circle"
          wrapperStyle={{
            fontSize: 10,
            color: '#94a3b8',
            paddingTop: 10,
          }}
        />

        <Area
          type="monotone"
          dataKey="normal"
          name="Normal traffic"
          stroke="#818cf8"
          strokeWidth={2}
          fill="url(#normalFill)"
        />

        <Area
          type="monotone"
          dataKey="anomaly"
          name="Anomalous traffic"
          stroke="#ef4444"
          strokeWidth={2}
          fill="url(#anomalyFill)"
        />

      </AreaChart>

    </ResponsiveContainer>
  )
}


// ============================================================
// DASHBOARD
// ============================================================

function Dashboard({
  stats,
  traffic,
  anomalies,
  packets,
}) {

  const totalFlows = Number(stats.totalFlows ?? stats.totalPackets ?? 0)
  const normalFlows = Number(stats.normalFlows ?? stats.normalTraffic ?? 0)
  const attackFlows = Number(stats.attackFlows ?? 0)
  const anomalyCount = Number(stats.anomalies ?? 0)

  const normalPercentage = Number(
    stats.normalPercentage ?? percentage(normalFlows, totalFlows)
  ).toFixed(2)

  const anomalyPercentage = Number(
    stats.anomalyPercentage ?? percentage(anomalyCount, totalFlows)
  ).toFixed(2)

  return (
    <>

      <div className="hero-editorial">

        <div className="hero-editorial-left">

          <p className="eyebrow-hero">
            <span className="live-dot" />
            REAL-TIME NETWORK INTELLIGENCE
          </p>

          <h1 className="hero-headline">
            Real-Time Autonomous
            <br />
            Network Defense
          </h1>

          <p className="hero-subtext">
            Perimeter network intelligence powered by
            Scapy telemetry & deep inference engines.
          </p>

        </div>

        <div className="hero-editorial-right">

          <div className="hero-status-pill">
            <span className="hero-status-title">
              SYSTEM STATUS
            </span>

            <span className="hero-status-val">
              PERIMETER PROTECTED
            </span>
          </div>

        </div>

      </div>


      {/* REAL BACKEND STATISTICS */}

      <div className="stats-grid">

        <StatCard
          label="Total Flows"
          value={formatNumber(totalFlows)}
          detail="Flows processed from PCAP"
          icon={Database}
          accent="indigo"
        />

        <StatCard
          label="Flows Loaded"
          value={formatNumber(totalFlows)}
          detail="Network flow records"
          icon={Gauge}
          accent="violet"
        />

        <StatCard
          label="Normal Flows"
          value={formatNumber(normalFlows)}
          detail={`${normalPercentage}% of flows`}
          icon={ShieldCheck}
          accent="blue"
        />

        <StatCard
          label="Anomalies Detected"
          value={formatNumber(anomalyCount)}
          detail={`${anomalyPercentage}% of flows`}
          icon={AlertOctagon}
          accent="amber"
        />

        <StatCard
          label="Attack Flows"
          value={formatNumber(attackFlows)}
          detail="Random Forest classified flows"
          icon={Zap}
          accent="red"
        />

        <StatCard
          label="Detection Engine"
          value="ACTIVE"
          detail="Random Forest + Isolation Forest"
          icon={Network}
          accent="purple"
        />

      </div>


      {/* NETWORK TOPOLOGY */}

      <section className="panel topology-panel">

        <SectionHeader
          eyebrow="NETWORK MONITORING"
          title="Network Telemetry Hero Scene"
          action={
            <span className="chart-live">
              <span className="live-dot" />
              {packets.length} flows loaded
            </span>
          }
        />

        <NetworkTopology />

      </section>


      <div className="dashboard-grid">

        <section className="panel traffic-panel">

          <SectionHeader
            eyebrow="BACKEND TELEMETRY"
            title="Traffic activity"
            action={
              <span className="chart-live">
                <span className="live-dot" />
                API data
              </span>
            }
          />

          <TrafficChart data={traffic} />

        </section>


        <ThreatDistribution
          anomalies={anomalies}
          total={totalFlows}
        />


        <ProtocolDistribution
          packets={packets}
        />

      </div>


      <div className="overview-lower">

        <RecentAnomalies
          anomalies={anomalies}
        />

        <SecurityEvents
          anomalies={anomalies}
        />

        <TopSources
          packets={packets}
        />

      </div>

    </>
  )
}


// ============================================================
// THREAT DISTRIBUTION
// ============================================================

function ThreatDistribution({
  anomalies,
  total,
}) {

  const critical = anomalies.filter(
    (a) => a.severity === 'Critical'
  ).length

  const high = anomalies.filter(
    (a) => a.severity === 'High'
  ).length

  const medium = anomalies.filter(
    (a) => a.severity === 'Medium'
  ).length

  const low = anomalies.filter(
    (a) => a.severity === 'Low'
  ).length

  const normal = Math.max(
    total - anomalies.length,
    0
  )

  const data = [
    { name: 'Normal', value: normal },
    { name: 'Low', value: low },
    { name: 'Medium', value: medium },
    { name: 'High', value: high },
    { name: 'Critical', value: critical },
  ]

  return (
    <section className="panel threat-panel">

      <SectionHeader
        eyebrow="RISK PROFILE"
        title="Anomaly distribution"
      />

      <ResponsiveContainer
        width="100%"
        height={205}
      >

        <BarChart
          data={data}
          margin={{
            top: 5,
            right: 0,
            left: -25,
            bottom: 0,
          }}
        >

          <CartesianGrid
            stroke="#1e1b4b"
            strokeDasharray="3 3"
            vertical={false}
          />

          <XAxis
            dataKey="name"
            stroke="#64748b"
            tickLine={false}
            axisLine={false}
            fontSize={10}
          />

          <YAxis
            stroke="#64748b"
            tickLine={false}
            axisLine={false}
            fontSize={10}
          />

          <Tooltip content={<ChartTooltip />} />

          <Bar
            dataKey="value"
            radius={[3, 3, 0, 0]}
          >

            {data.map((item) => (
              <Cell
                key={item.name}
                fill={{
                  Normal: '#818cf8',
                  Low: '#a855f7',
                  Medium: '#f59e0b',
                  High: '#ea580c',
                  Critical: '#ef4444',
                }[item.name]}
              />
            ))}

          </Bar>

        </BarChart>

      </ResponsiveContainer>

    </section>
  )
}


// ============================================================
// PROTOCOL DISTRIBUTION
// ============================================================

function ProtocolDistribution({
  packets = [],
}) {

  const tcp = packets.filter(
    (p) => String(p.protocol).toUpperCase() === 'TCP'
  ).length

  const udp = packets.filter(
    (p) => String(p.protocol).toUpperCase() === 'UDP'
  ).length

  const other = Math.max(
    packets.length - tcp - udp,
    0
  )

  const total = packets.length || 1

  const tcpPercent = Math.round((tcp / total) * 100)
  const udpPercent = Math.round((udp / total) * 100)
  const otherPercent = Math.max(
    100 - tcpPercent - udpPercent,
    0
  )

  const data = [
    { name: 'TCP', value: tcp },
    { name: 'UDP', value: udp },
    { name: 'Other', value: other },
  ]

  return (
    <section className="panel protocol-panel">

      <SectionHeader
        eyebrow="TRAFFIC COMPOSITION"
        title="Protocols"
      />

      <div className="donut-wrap">

        <ResponsiveContainer
          width="50%"
          height={160}
        >

          <PieChart>

            <Pie
              data={data}
              innerRadius={47}
              outerRadius={69}
              paddingAngle={4}
              dataKey="value"
              stroke="none"
            >

              {[
                '#818cf8',
                '#c084fc',
                '#334155',
              ].map((color) => (
                <Cell
                  key={color}
                  fill={color}
                />
              ))}

            </Pie>

            <text
              x="25%"
              y="50%"
              textAnchor="middle"
              dominantBaseline="middle"
              fill="#f8fafc"
              fontSize="20"
              fontWeight="700"
            >
              {tcpPercent}%
            </text>

          </PieChart>

        </ResponsiveContainer>


        <div className="legend-list">

          <div>
            <i className="legend-dot violet" />
            TCP
            <b>{tcpPercent}%</b>
          </div>

          <div>
            <i className="legend-dot purple" />
            UDP
            <b>{udpPercent}%</b>
          </div>

          <div>
            <i className="legend-dot slate" />
            Other
            <b>{otherPercent}%</b>
          </div>

        </div>

      </div>

    </section>
  )
}


// ============================================================
// RECENT ANOMALIES
// ============================================================

function RecentAnomalies({
  anomalies,
}) {

  return (
    <section className="panel anomalies-panel">

      <SectionHeader
        eyebrow="DETECTION FEED"
        title="Recent anomalies"
        action={
          <a
            className="text-link"
            href="#/anomalies"
          >
            View all
            <ChevronRight size={13} />
          </a>
        }
      />

      <AnomalyTable
        anomalies={anomalies.slice(0, 4)}
        compact
      />

    </section>
  )
}


// ============================================================
// ANOMALY TABLE
// ============================================================

function AnomalyTable({
  anomalies,
  compact = false,
  onSelect,
}) {

  return (
    <div className="table-scroll">

      <table>

        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Anomaly type</th>
            <th>Score</th>
            <th>Severity</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>

          {anomalies.map((item, index) => (

            <tr
              key={item.id ?? index}
              onClick={() => onSelect?.(item)}
              className={
                onSelect
                  ? 'clickable-row'
                  : ''
              }
            >

              <td className="muted">
                {item.time}
              </td>

              <td className="mono">
                {item.source}
              </td>

              <td className="mono">
                {item.destination}
              </td>

              <td>
                <span className="protocol-tag">
                  {item.protocol}
                </span>
              </td>

              <td>
                {item.type}
              </td>

              <td>
                <span
                  className={`score ${
                    Number(item.score) > 80
                      ? 'score-high'
                      : ''
                  }`}
                >
                  {item.score}%
                </span>
              </td>

              <td>
                <span
                  className={severityClass(
                    item.severity
                  )}
                >
                  {item.severity}
                </span>
              </td>

              <td>
                <span className="status-text">
                  {item.status}
                </span>
              </td>

            </tr>

          ))}

        </tbody>

      </table>

      {!anomalies.length && (
        <div className="empty-state">
          No anomalies found.
        </div>
      )}

    </div>
  )
}


// ============================================================
// SECURITY EVENTS
// ============================================================

function SecurityEvents({
  anomalies,
}) {

  const first = anomalies[0]
  const second = anomalies[1]

  return (
    <section className="panel security-events">

      <SectionHeader
        eyebrow="SECURITY EVENTS"
        title="Recent activity"
      />

      <div className="event-row">

        <span className="event-mark red">
          <AlertOctagon size={13} />
        </span>

        <div>
          <strong>
            Model flagged anomaly
          </strong>

          <small>
            {first?.source || 'Network traffic'}
          </small>
        </div>

        <time>
          Recent
        </time>

      </div>


      <div className="event-row">

        <span className="event-mark amber">
          <FileWarning size={13} />
        </span>

        <div>
          <strong>
            Investigation required
          </strong>

          <small>
            {second?.type || 'Suspicious network flow'}
          </small>
        </div>

        <time>
          Recent
        </time>

      </div>


      <div className="event-row">

        <span className="event-mark green">
          <ShieldCheck size={13} />
        </span>

        <div>
          <strong>
            Backend health check passed
          </strong>

          <small>
            FastAPI detection service responding
          </small>
        </div>

        <time>
          Active
        </time>

      </div>

    </section>
  )
}


// ============================================================
// TOP SOURCES
// ============================================================

function TopSources({
  packets = [],
}) {

  const sourceMap = {}

  const destinationMap = {}

  packets.forEach((packet) => {

    if (packet.src_ip) {
      sourceMap[packet.src_ip] =
        (sourceMap[packet.src_ip] || 0) + 1
    }

    if (packet.dst_ip) {
      destinationMap[packet.dst_ip] =
        (destinationMap[packet.dst_ip] || 0) + 1
    }

  })


  const sources = Object.entries(sourceMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)

  const destinations = Object.entries(destinationMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)


  return (
    <section className="panel top-sources">

      <SectionHeader
        eyebrow="TRAFFIC CONTEXT"
        title="Top endpoints"
      />

      <p className="list-label">
        SOURCE IPs
      </p>

      <div className="ip-list">

        {sources.map(
          ([ip, count], index) => (

            <div key={ip}>

              <span className="rank">
                {index + 1}
              </span>

              <span className="mono">
                {ip}
              </span>

              <b>
                {formatNumber(count)}
              </b>

            </div>

          )
        )}

      </div>


      <p className="list-label destination-label">
        DESTINATION IPs
      </p>

      <div className="ip-list">

        {destinations.map(
          ([ip, count]) => (

            <div key={ip}>

              <span className="rank">
                -
              </span>

              <span className="mono">
                {ip}
              </span>

              <b>
                {formatNumber(count)}
              </b>

            </div>

          )
        )}

      </div>

    </section>
  )
}


// ============================================================
// MONITORING
// ============================================================

function Monitoring({
  traffic,
  packets,
  stats,
}) {

  const totalFlows = Number(stats.totalFlows ?? stats.totalPackets ?? 0)
  const normalFlows = Number(stats.normalFlows ?? stats.normalTraffic ?? 0)
  const anomalyCount = Number(stats.anomalies ?? 0)

  const normalPercent = Number(
    stats.normalPercentage ?? percentage(normalFlows, totalFlows)
  ).toFixed(2)

  return (
    <>

      <div className="page-heading">

        <div>

          <p className="eyebrow">
            REAL-TIME SENSOR VIEW
          </p>

          <h2>
            Live monitoring
          </h2>

          <p>
            Streaming network telemetry from the detection backend.
          </p>

        </div>

        <div className="monitoring-active">
          <span className="live-dot" />
          Monitoring active
        </div>

      </div>


      <div className="metric-strip">

        <div>
          <span>Flows loaded</span>

          <strong>
            {formatNumber(totalFlows)}
          </strong>

          <small>
            Backend PCAP telemetry
          </small>
        </div>


        <div>
          <span>Attack flows</span>

          <strong>
            {formatNumber(stats.attackFlows)}
          </strong>

          <small>
            From PCAP
          </small>
        </div>


        <div>
          <span>Loaded records</span>

          <strong>
            {formatNumber(packets.length)}
          </strong>

          <small>
            API response
          </small>
        </div>


        <div>
          <span>Normal / anomaly</span>

          <strong>
            {formatNumber(normalFlows)}
            {' / '}
            {formatNumber(anomalyCount)}
          </strong>

          <small className="good">
            {normalPercent}% normal
          </small>
        </div>

      </div>


      <section className="panel topology-panel monitoring-topology">

        <SectionHeader
          eyebrow="NETWORK HERO SCENE // SENSORS"
          title="Live network map"
          action={
            <span className="chart-live">
              <span className="live-dot" />
              API connected
            </span>
          }
        />

        <NetworkTopology />

      </section>


      <div className="dashboard-grid monitoring-grid">

        <section className="panel traffic-panel">

          <SectionHeader
            eyebrow="TRAFFIC"
            title="Network traffic stream"
          />

          <TrafficChart data={traffic} />

        </section>


        <LiveConnectionHealth />

      </div>


      <section className="panel flow-panel">

        <SectionHeader
          eyebrow="BACKEND DATA"
          title="Network flow data"
          action={
            <span className="stream-status">
              <span className="live-dot" />
              Receiving data
            </span>
          }
        />

        <PacketTable packets={packets} />

      </section>

    </>
  )
}


// ============================================================
// CONNECTION HEALTH
// ============================================================

function LiveConnectionHealth() {

  return (
    <section className="panel health-panel">

      <SectionHeader
        eyebrow="BACKEND HEALTH"
        title="Connection health"
      />

      <div className="health-ring">

        <div>
          <strong>OK</strong>
          <span>API HEALTH</span>
        </div>

      </div>

      <div className="health-list">

        <div>
          <span className="live-dot" />
          Packet ingestion
          <b>Connected</b>
        </div>

        <div>
          <span className="live-dot" />
          Model inference
          <b>Ready</b>
        </div>

        <div>
          <span className="live-dot" />
          API gateway
          <b>Connected</b>
        </div>

      </div>

    </section>
  )
}


// ============================================================
// ANOMALIES PAGE
// ============================================================

function Anomalies({
  anomalies,
  onSelect,
}) {

  const [query, setQuery] = useState('')
  const [severity, setSeverity] =
    useState('All severities')

  const [protocol, setProtocol] =
    useState('All protocols')

  const [type, setType] =
    useState('All types')


  const filtered = useMemo(
    () =>
      anomalies.filter((item) => {

        const searchText =
          `${item.source || ''} ${item.destination || ''} ${item.type || ''}`
            .toLowerCase()

        const queryMatch =
          searchText.includes(
            query.toLowerCase()
          )

        const severityMatch =
          severity === 'All severities' ||
          item.severity === severity

        const protocolMatch =
          protocol === 'All protocols' ||
          item.protocol === protocol

        const typeMatch =
          type === 'All types' ||
          item.type === type

        return (
          queryMatch &&
          severityMatch &&
          protocolMatch &&
          typeMatch
        )
      }),
    [
      anomalies,
      query,
      severity,
      protocol,
      type,
    ]
  )


  const criticalCount =
    anomalies.filter(
      (a) => a.severity === 'Critical'
    ).length

  const highCount =
    anomalies.filter(
      (a) => a.severity === 'High'
    ).length

  const mediumCount =
    anomalies.filter(
      (a) => a.severity === 'Medium'
    ).length

  const lowCount =
    anomalies.filter(
      (a) => a.severity === 'Low'
    ).length


  return (
    <>

      <div className="page-heading">

        <div>

          <p className="eyebrow">
            THREAT INTELLIGENCE
          </p>

          <h2>
            Anomaly detection
          </h2>

          <p>
            Investigate model-flagged deviations
            from learned network behavior.
          </p>

        </div>

        <div className="heading-count">

          <strong>
            {formatNumber(anomalies.length)}
          </strong>

          <span>
            Loaded detections
          </span>

        </div>

      </div>


      <div className="severity-summary">

        <div>
          <span>Total detections</span>
          <b>{formatNumber(anomalies.length)}</b>
        </div>

        <div className="critical">
          <span>Critical</span>
          <b>{criticalCount}</b>
        </div>

        <div className="high">
          <span>High</span>
          <b>{highCount}</b>
        </div>

        <div className="medium">
          <span>Medium</span>
          <b>{mediumCount}</b>
        </div>

        <div className="low">
          <span>Low</span>
          <b>{lowCount}</b>
        </div>

      </div>


      <section className="panel full-panel">

        <div className="filter-bar">

          <div className="search-box">

            <Search size={16} />

            <input
              value={query}
              onChange={(e) =>
                setQuery(e.target.value)
              }
              placeholder="Search IP or anomaly type"
            />

          </div>


          <select
            value={severity}
            onChange={(e) =>
              setSeverity(e.target.value)
            }
          >
            <option>All severities</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>


          <select
            value={protocol}
            onChange={(e) =>
              setProtocol(e.target.value)
            }
          >
            <option>All protocols</option>
            <option>TCP</option>
            <option>UDP</option>
          </select>


          <select
            value={type}
            onChange={(e) =>
              setType(e.target.value)
            }
          >

            <option>
              All types
            </option>

            {[
              ...new Set(
                anomalies.map(
                  (item) => item.type
                )
              ),
            ].map((item) => (

              <option key={item}>
                {item}
              </option>

            ))}

          </select>


          <SlidersHorizontal
            size={18}
            className="filter-icon"
          />

        </div>


        <AnomalyTable
          anomalies={filtered}
          onSelect={onSelect}
        />

      </section>

    </>
  )
}


// ============================================================
// ANALYTICS
// ============================================================

function Analytics({
  analytics,
  stats,
  packets,
  anomalies,
}) {

  const totalFlows = Number(stats.totalFlows ?? stats.totalPackets ?? 0)
  const anomalyCount = Number(stats.anomalies ?? 0)

  const anomalyPercent = Number(
    stats.anomalyPercentage ?? percentage(anomalyCount, totalFlows)
  ).toFixed(2)


  const scores = anomalies
    .map((a) => Number(a.score))
    .filter((score) => !Number.isNaN(score))

  const meanScore =
    scores.length
      ? (
          scores.reduce(
            (sum, score) => sum + score,
            0
          ) / scores.length
        ).toFixed(1)
      : '0.0'


  const pcapFlowCount = Number(
    analytics.traffic?.[0]?.packets ?? totalFlows
  )


  return (
    <>

      <div className="page-heading">

        <div>

          <p className="eyebrow">
            SECURITY INTELLIGENCE
          </p>

          <h2>
            Analytics overview
          </h2>

          <p>
            Traffic and detection information
            from the backend.
          </p>

        </div>

        <div className="date-chip">
          PCAP analysis
          <ChevronRight size={14} />
        </div>

      </div>


      <div className="analytics-kpis">

        <div>
          <span>Total flows</span>

          <strong>
            {formatNumber(totalFlows)}
          </strong>
        </div>


        <div>
          <span>Anomaly percentage</span>

          <strong>
            {anomalyPercent}%
          </strong>
        </div>


        <div>
          <span>Mean detection score</span>

          <strong>
            {meanScore}%
          </strong>
        </div>


        <div>
          <span>PCAP flow count</span>

          <strong>
            {formatNumber(pcapFlowCount)}
            <small> flows</small>
          </strong>
        </div>

      </div>


      <div className="analytics-grid">

        <section className="panel large-chart">

          <SectionHeader
            eyebrow="TRAFFIC VOLUME"
            title="Traffic over time"
          />

          <TrafficChart
            data={analytics.traffic}
          />

        </section>


        <ProtocolDistribution
          packets={packets}
        />


        <section className="panel large-chart">

          <SectionHeader
            eyebrow="DETECTION COUNTS"
            title="Anomalies over time"
          />

          <ResponsiveContainer
            width="100%"
            height={245}
          >

            <LineChart
              data={analytics.traffic}
              margin={{
                top: 10,
                right: 0,
                left: -20,
                bottom: 0,
              }}
            >

              <CartesianGrid
                stroke="#1e1b4b"
                strokeDasharray="3 3"
                vertical={false}
              />

              <XAxis
                dataKey="time"
                stroke="#64748b"
                tickLine={false}
                axisLine={false}
                fontSize={10}
              />

              <YAxis
                stroke="#64748b"
                tickLine={false}
                axisLine={false}
                fontSize={10}
              />

              <Tooltip
                content={<ChartTooltip />}
              />

              <Line
                type="monotone"
                dataKey="anomaly"
                name="Anomalies"
                stroke="#ef4444"
                strokeWidth={2}
                dot={false}
              />

            </LineChart>

          </ResponsiveContainer>

        </section>


        <ThreatDistribution
          anomalies={anomalies}
          total={totalFlows}
        />


        <AnalyticsDistribution
          packets={packets}
        />

      </div>

    </>
  )
}


// ============================================================
// ANALYTICS DISTRIBUTION
// ============================================================

function AnalyticsDistribution({
  packets = [],
}) {

  const sizes = [
    {
      name: '0-256',
      value: packets.filter(
        (p) => Number(p.packet_size) <= 256
      ).length,
    },
    {
      name: '257-512',
      value: packets.filter(
        (p) =>
          Number(p.packet_size) > 256 &&
          Number(p.packet_size) <= 512
      ).length,
    },
    {
      name: '513-1024',
      value: packets.filter(
        (p) =>
          Number(p.packet_size) > 512 &&
          Number(p.packet_size) <= 1024
      ).length,
    },
    {
      name: '1025+',
      value: packets.filter(
        (p) =>
          Number(p.packet_size) > 1024
      ).length,
    },
  ]


  const sourceMap = {}

  packets.forEach((packet) => {

    if (packet.src_ip) {
      sourceMap[packet.src_ip] =
        (sourceMap[packet.src_ip] || 0) + 1
    }

  })


  const sources = Object.entries(sourceMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([name, value]) => ({
      name,
      value,
    }))


  return (
    <>

      <section className="panel analytics-mini">

        <SectionHeader
          eyebrow="PACKET PROFILE"
          title="Flow-size distribution"
        />

        <ResponsiveContainer
          width="100%"
          height={185}
        >

          <BarChart data={sizes}>

            <CartesianGrid
              stroke="#1e1b4b"
              strokeDasharray="3 3"
              vertical={false}
            />

            <XAxis
              dataKey="name"
              stroke="#64748b"
              tickLine={false}
              axisLine={false}
              fontSize={9}
            />

            <YAxis
              stroke="#64748b"
              tickLine={false}
              axisLine={false}
              fontSize={9}
            />

            <Bar
              dataKey="value"
              fill="#818cf8"
              radius={[2, 2, 0, 0]}
            />

          </BarChart>

        </ResponsiveContainer>

      </section>


      <section className="panel analytics-mini">

        <SectionHeader
          eyebrow="TRAFFIC ORIGINS"
          title="Top source IPs"
        />

        <ResponsiveContainer
          width="100%"
          height={185}
        >

          <BarChart
            data={sources}
            layout="vertical"
            margin={{
              left: 20,
              right: 10,
            }}
          >

            <CartesianGrid
              stroke="#1e1b4b"
              strokeDasharray="3 3"
              horizontal={false}
            />

            <XAxis
              type="number"
              hide
            />

            <YAxis
              type="category"
              dataKey="name"
              stroke="#64748b"
              tickLine={false}
              axisLine={false}
              fontSize={8}
              width={78}
            />

            <Bar
              dataKey="value"
              fill="#c084fc"
              radius={[0, 2, 2, 0]}
            />

          </BarChart>

        </ResponsiveContainer>

      </section>

    </>
  )
}


// ============================================================
// TRAFFIC TABLE
// ============================================================

function TrafficTable({
  packets,
}) {

  const [query, setQuery] = useState('')
  const [protocol, setProtocol] =
    useState('All protocols')

  const [status, setStatus] =
    useState('All statuses')

  const [page, setPage] =
    useState(1)


  const filtered = packets.filter(
    (packet) => {

      const source =
        String(packet.src_ip || '')

      const destination =
        String(packet.dst_ip || '')

      const protocolMatch =
        protocol === 'All protocols' ||
        packet.protocol === protocol

      const statusMatch =
        status === 'All statuses' ||
        packet.status === status

      return (
        (source.includes(query) ||
          destination.includes(query)) &&
        protocolMatch &&
        statusMatch
      )
    }
  )


  const PAGE_SIZE = 25
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))

  const safePage = Math.min(page, totalPages)

  const visiblePackets = filtered.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE
  )

  return (
    <>

      <div className="page-heading">

        <div>

          <p className="eyebrow">
            PACKET INSPECTION
          </p>

          <h2>
            Network traffic
          </h2>

          <p>
            Network flow metadata from the
            Scapy processing pipeline.
          </p>

        </div>

        <div className="capture-state">
          <span className="live-dot" />
          Backend stream active
        </div>

      </div>


      <section className="panel full-panel">

        <div className="table-toolbar">

          <div>
            <strong>
              Latest network flows
            </strong>

            <span>
              Data supplied by FastAPI
            </span>
          </div>

          <button className="secondary-button">
            <Table2 size={15} />
            Export view
          </button>

        </div>


        <div className="filter-bar traffic-filters">

          <div className="search-box">

            <Search size={16} />

            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
                setPage(1)
              }}
              placeholder="Search source or destination IP"
            />

          </div>


          <select
            value={protocol}
            onChange={(event) => {
              setProtocol(event.target.value)
              setPage(1)
            }}
          >
            <option>
              All protocols
            </option>

            <option>TCP</option>
            <option>UDP</option>
          </select>


          <select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value)
              setPage(1)
            }}
          >
            <option>
              All statuses
            </option>

            <option>Normal</option>
            <option>Warning</option>
            <option>Anomaly</option>
          </select>


          <span className="filter-date">
            Backend data
          </span>

        </div>


        <PacketTable
          packets={visiblePackets}
        />


        <div className="pagination">

          <span>
            Showing {filtered.length} loaded flows
          </span>

          <div>

            <button
              disabled={safePage === 1}
              onClick={() =>
                setPage(Math.max(1, safePage - 1))
              }
            >
              Previous
            </button>

            <b>
              {safePage} / {totalPages}
            </b>

            <button
              disabled={safePage >= totalPages}
              onClick={() =>
                setPage(Math.min(totalPages, safePage + 1))
              }
            >
              Next
            </button>

          </div>

        </div>

      </section>

    </>
  )
}


// ============================================================
// PACKET TABLE
// ============================================================

function PacketTable({
  packets,
}) {

  return (
    <div className="table-scroll">

      <table className="packet-table">

        <thead>

          <tr>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Source port</th>
            <th>Destination port</th>
            <th>Flow bytes</th>
            <th>Status</th>
            <th>Anomaly score</th>
          </tr>

        </thead>

        <tbody>

          {packets.map(
            (packet, index) => (

              <tr
                key={`${packet.timestamp}-${packet.src_ip}-${index}`}
              >

                <td className="muted mono">
                  {packet.timestamp}
                </td>

                <td className="mono">
                  {packet.src_ip}
                </td>

                <td className="mono">
                  {packet.dst_ip}
                </td>

                <td>
                  <span className="protocol-tag">
                    {packet.protocol}
                  </span>
                </td>

                <td className="mono">
                  {packet.src_port}
                </td>

                <td className="mono">
                  {packet.dst_port}
                </td>

                <td>
                  {formatNumber(
                    packet.packet_size
                  )}{' '}
                  B
                </td>

                <td>
                  <span
                    className={`packet-status ${
                      packet.status?.toLowerCase() || ''
                    }`}
                  >
                    {packet.status || 'Normal'}
                  </span>
                </td>

                <td>

                  <span
                    className={
                      Number(packet.score) > 60
                        ? 'score score-high'
                        : 'score'
                    }
                  >
                    {packet.score || 0}%
                  </span>

                </td>

              </tr>

            )
          )}

        </tbody>

      </table>

      {!packets.length && (
        <div className="empty-state">
          No network flows available.
        </div>
      )}

    </div>
  )
}


// ============================================================
// SETTINGS
// ============================================================

function SettingsPage() {

  return (
    <div className="page-heading">

      <div>

        <p className="eyebrow">
          SYSTEM CONFIGURATION
        </p>

        <h2>
          Settings
        </h2>

        <p>
          Detection backend is connected
          through FastAPI.
        </p>

      </div>


      <section className="panel placeholder-panel">

        <Settings size={24} />

        <strong>
          Configuration controls
        </strong>

        <span>
          Backend configuration controls
          can be added here later.
        </span>

      </section>

    </div>
  )
}


// ============================================================
// ANOMALY MODAL
// ============================================================

function AnomalyModal({
  anomaly,
  onClose,
}) {

  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
    >

      <div
        className="modal"
        onClick={(e) =>
          e.stopPropagation()
        }
      >

        <div className="modal-header">

          <div>

            <p className="eyebrow">
              DETECTION DETAIL / #
              {String(anomaly.id)
                .padStart(4, '0')}
            </p>

            <h2>
              {anomaly.type}
            </h2>

          </div>

          <button
            className="icon-button"
            onClick={onClose}
          >
            <X size={18} />
          </button>

        </div>


        <div className="modal-severity">

          <span
            className={severityClass(
              anomaly.severity
            )}
          >
            {anomaly.severity}
          </span>

          <span className="score score-high">
            {anomaly.score}% anomaly score
          </span>

          <span className="status-text">
            {anomaly.status}
          </span>

        </div>


        <div className="detail-grid">

          {[
            ['Source IP', anomaly.source],
            ['Destination IP', anomaly.destination],
            ['Protocol', anomaly.protocol],
            ['Source port', anomaly.srcPort],
            ['Destination port', anomaly.dstPort],
            ['Packet size', `${anomaly.packetSize} bytes`],
            ['Timestamp', anomaly.timestamp],
            ['Detection reason', anomaly.reason],
          ].map(
            ([label, value]) => (

              <div key={label}>

                <span>
                  {label}
                </span>

                <strong
                  className={
                    label.includes('IP') ||
                    label.includes('port')
                      ? 'mono'
                      : ''
                  }
                >
                  {value}
                </strong>

              </div>

            )
          )}

        </div>


        <button
          className="secondary-button modal-close"
          onClick={onClose}
        >
          Close investigation
        </button>

      </div>

    </div>
  )
}


// ============================================================
// EXPORT
// ============================================================

export default App