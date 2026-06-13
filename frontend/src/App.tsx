import { useEffect } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { NewScan } from './pages/NewScan'
import { ScanHistory } from './pages/ScanHistory'
import { ScanDetail } from './pages/ScanDetail'
import { Schedules } from './pages/Schedules'
import { rootApi } from './api/client'

// Silently ping the backend on app load so Render wakes up before the user
// tries to do anything (free tier sleeps after 15 min of inactivity).
function useWakeBackend() {
  useEffect(() => {
    rootApi.get('/health').catch(() => {})
  }, [])
}

export default function App() {
  useWakeBackend()

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/history/:id" element={<ScanDetail />} />
          <Route path="/schedules" element={<Schedules />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
