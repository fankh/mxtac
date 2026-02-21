import { Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/layout/Sidebar'
import { OverviewPage } from './components/features/overview/OverviewPage'
import { DetectionsPage } from './components/features/detections/DetectionsPage'
import { CoveragePage } from './components/features/coverage/CoveragePage'
import { RulesPage } from './components/features/rules/RulesPage'
import { ConnectorsPage } from './components/features/connectors/ConnectorsPage'
import { AdminPage } from './components/features/admin/AdminPage'
import { HuntPage } from './components/features/hunt/HuntPage'
import { AssetsPage } from './components/features/assets/AssetsPage'
import { IncidentsPage } from './components/features/incidents/IncidentsPage'
import { ThreatIntelPage } from './components/features/intel/ThreatIntelPage'
import { ReportsPage } from './components/features/reports/ReportsPage'
import { LoginPage } from './components/features/auth/LoginPage'
import { ProtectedRoute } from './components/shared/ProtectedRoute'
import { ErrorBoundary } from './components/shared/ErrorBoundary'
import { NotificationToast } from './components/shared/NotificationToast'


export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <div className="flex min-h-screen bg-page">
              <Sidebar />
              <main className="ml-[52px] flex-1 min-h-screen">
                <ErrorBoundary>
                  <Routes>
                    <Route path="/"             element={<OverviewPage />} />
                    <Route path="/detections"   element={<DetectionsPage />} />
                    <Route path="/hunt"         element={<HuntPage />} />
                    <Route path="/attack"       element={<CoveragePage />} />
                    <Route path="/rules"        element={<RulesPage />} />
                    <Route path="/integrations" element={<ConnectorsPage />} />
                    <Route path="/admin"        element={<AdminPage />} />
                    <Route path="/incidents"    element={<IncidentsPage />} />
                    <Route path="/intel"        element={<ThreatIntelPage />} />
                    <Route path="/assets"       element={<AssetsPage />} />
                    <Route path="/reports"      element={<ReportsPage />} />
                  </Routes>
                </ErrorBoundary>
              </main>
              <NotificationToast />
            </div>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}
