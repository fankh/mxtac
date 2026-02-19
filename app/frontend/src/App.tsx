import { Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/layout/Sidebar'
import { OverviewPage } from './components/features/overview/OverviewPage'
import { DetectionsPage } from './components/features/detections/DetectionsPage'

function Placeholder({ title }: { title: string }) {
  return (
    <div className="flex items-center justify-center h-full text-text-muted text-sm">
      {title} — coming soon
    </div>
  )
}

export default function App() {
  return (
    <div className="flex min-h-screen bg-page">
      <Sidebar />
      <main className="ml-[52px] flex-1 min-h-screen">
        <Routes>
          <Route path="/"           element={<OverviewPage />} />
          <Route path="/detections" element={<DetectionsPage />} />
          <Route path="/attack"     element={<Placeholder title="ATT&CK Map" />} />
          <Route path="/rules"      element={<Placeholder title="Sigma Rules" />} />
          <Route path="/incidents"  element={<Placeholder title="Incidents" />} />
          <Route path="/intel"      element={<Placeholder title="Threat Intel" />} />
          <Route path="/assets"     element={<Placeholder title="Assets" />} />
          <Route path="/reports"    element={<Placeholder title="Reports" />} />
        </Routes>
      </main>
    </div>
  )
}
