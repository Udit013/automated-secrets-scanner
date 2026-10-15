import { BrowserRouter, Navigate, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Gate } from './components/Gate'
import { Landing } from './pages/Landing'
import { Dashboard } from './pages/Dashboard'
import { NewScan } from './pages/NewScan'
import { Projects } from './pages/Projects'
import { ProjectDetail } from './pages/ProjectDetail'
import { ScanHistory } from './pages/ScanHistory'
import { ScanDetail } from './pages/ScanDetail'
import { Schedules } from './pages/Schedules'
import { EmptyState } from './components/ui'
import { useHealth } from './hooks/useHealth'

export default function App() {
  // Fetching /health on load also wakes a sleeping free-tier backend before
  // the visitor clicks anything.
  useHealth()

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          element={
            <Gate>
              <Layout />
            </Gate>
          }
        >
          <Route path="/overview" element={<Dashboard />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/projects/:owner/:repo" element={<ProjectDetail />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/history/:id" element={<ScanDetail />} />
          <Route path="/schedules" element={<Schedules />} />
          <Route path="/dashboard" element={<Navigate to="/overview" replace />} />
          <Route
            path="*"
            element={<EmptyState title="page not found" action={{ to: '/overview', label: 'Go to overview' }} />}
          />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
