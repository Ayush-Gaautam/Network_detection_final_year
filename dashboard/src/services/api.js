const API_URL =
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'


const request = async (endpoint) => {
  const response = await fetch(`${API_URL}${endpoint}`)

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`)
  }

  return response.json()
}


/* ================================
   DASHBOARD
================================ */

export const getDashboardStats = () => {
  return request('/stats')
}


/* ================================
   TRAFFIC
================================ */

export const getTraffic = async () => {
  const data = await request('/analytics')
  return data.traffic || []
}


/* ================================
   ANOMALIES
================================ */

export const getAnomalies = () => {
  return request('/anomalies')
}


/* ================================
   NETWORK FLOWS
================================ */

export const getPackets = () => {
  return request('/packets')
}


/* ================================
   ANALYTICS
================================ */

export const getAnalytics = () => {
  return request('/analytics')
}


/* ================================
   COMPATIBILITY ALIASES
================================ */

export const getNetworkStats = getDashboardStats

export const getLivePackets = getPackets


/* ================================
   NETWORK TOPOLOGY
================================ */

export const getNetworkTopology = () => {
  return Promise.resolve({
    nodes: [],
    links: []
  })
}