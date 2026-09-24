const API_URL = 'http://127.0.0.1:8000'

const request = async (endpoint) => {
  const response = await fetch(`${API_URL}${endpoint}`)

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`)
  }

  return response.json()
}


export const getDashboardStats = () => {
  return request('/stats')
}


export const getTraffic = async () => {
  const data = await request('/analytics')
  return data.traffic
}


export const getAnomalies = () => {
  return request('/anomalies')
}


export const getPackets = () => {
  return request('/packets')
}


export const getAnalytics = () => {
  return request('/analytics')
}


export const getNetworkStats = getDashboardStats

export const getLivePackets = getPackets


export const getNetworkTopology = () => {
  return Promise.resolve({
    nodes: [],
    links: []
  })
}