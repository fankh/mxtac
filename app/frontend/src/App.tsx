import { Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/layout/Sidebar'
import { OverviewPage } from './components/features/overview/OverviewPage'
import { CoveragePage } from './components/features/coverage/CoveragePage'
import { HuntPage } from './components/features/hunt/HuntPage'
import { NetworkLogsPage } from './components/features/network/NetworkLogsPage'
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
    <div className="flex min-h-screen bg-page">
      <Sidebar />
      <main className="ml-[52px] flex-1 min-h-screen">
        <ErrorBoundary>
          <Routes>
            <Route path="/"        element={<OverviewPage />} />
            <Route path="/attack"  element={<CoveragePage />} />
            <Route path="/hunt"    element={<HuntPage />} />
            <Route path="/network" element={<NetworkLogsPage />} />
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
