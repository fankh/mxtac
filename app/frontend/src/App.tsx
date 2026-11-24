import { Navigate, Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/layout/Sidebar'
import { CoveragePage } from './components/features/coverage/CoveragePage'
import { HuntPage } from './components/features/hunt/HuntPage'
import { SourcesPage } from './components/features/sources/SourcesPage'
import { SettingsPage } from './components/features/settings/SettingsPage'
import { OverviewPage } from './components/features/overview/OverviewPage'
import { DetectionsPage } from './components/features/detections/DetectionsPage'
import { IncidentsPage } from './components/features/incidents/IncidentsPage'
import { RulesPage } from './components/features/rules/RulesPage'
import { LoginPage } from './components/features/auth/LoginPage'
import { ProtectedRoute } from './components/shared/ProtectedRoute'
import { ErrorBoundary } from './components/shared/ErrorBoundary'
import { NotificationToast } from './components/shared/NotificationToast'
import { KeyboardShortcutsModal } from './components/shared/KeyboardShortcutsModal'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { useUIStore } from './stores/uiStore'

function MainLayout() {
  useKeyboardShortcuts()
  const showShortcutsModal = useUIStore(s => s.showShortcutsModal)

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-y-auto">
        <ErrorBoundary>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/detections" element={<DetectionsPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/hunt" element={<HuntPage />} />
            <Route path="/coverage" element={<CoveragePage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/sources" element={<SourcesPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </ErrorBoundary>
      </main>
      <NotificationToast />
      {showShortcutsModal && <KeyboardShortcutsModal />}
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <MainLayout />
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}
