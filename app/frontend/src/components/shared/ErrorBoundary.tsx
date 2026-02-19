import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback
      return (
        <div className="flex flex-col items-center justify-center h-full min-h-[200px] gap-3 p-6">
          <div className="text-[13px] font-semibold text-text-primary">Something went wrong</div>
          <div className="text-[11px] text-text-muted max-w-md text-center">
            {this.state.error?.message ?? 'An unexpected rendering error occurred.'}
          </div>
          <button
            className="px-4 h-[30px] bg-blue text-white text-[12px] rounded-md hover:opacity-90"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
