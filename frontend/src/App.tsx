import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { NewScan } from './pages/NewScan'
import { ScanHistory } from './pages/ScanHistory'
import { ScanDetail } from './pages/ScanDetail'
import { Schedules } from './pages/Schedules'

export default function App() {
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
