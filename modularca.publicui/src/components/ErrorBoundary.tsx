import React from 'react';

interface ErrorBoundaryState {
    hasError: boolean;
}

interface ErrorBoundaryProps {
    children: React.ReactNode;
}

/**
 * Top-level React error boundary for the public UI. The shown
 * message is intentionally generic — raw error.message strings may include
 * backend type names or paths from ASP.NET ProblemDetails.
 */
class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false };
    }

    static getDerivedStateFromError(_error: Error): ErrorBoundaryState {
        return { hasError: true };
    }

    componentDidCatch(_error: Error, _info: React.ErrorInfo): void {
        // Backend logging endpoint not yet implemented; React's own logger
        // already writes to the browser console.
    }

    handleReload = () => {
        this.setState({ hasError: false });
        window.location.reload();
    };

    render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen flex items-center justify-center bg-ground p-6">
                    <div className="max-w-md w-full bg-raised border border-line rounded-xl shadow-lg p-8 text-center">
                        <div className="w-16 h-16 mx-auto mb-4 bg-crit-soft rounded-full flex items-center justify-center">
                            <svg className="w-8 h-8 text-crit" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </div>
                        <h1 className="text-xl font-semibold text-ink mb-2">Something went wrong</h1>
                        <p className="text-sm text-ink-muted mb-6">
                            The page encountered an unexpected error. Reload to recover.
                        </p>
                        <button
                            type="button"
                            onClick={this.handleReload}
                            className="inline-block px-6 py-2 bg-accent hover:bg-accent-hover text-on-accent font-medium rounded-lg transition-colors"
                        >
                            Reload
                        </button>
                    </div>
                </div>
            );
        }
        return this.props.children;
    }
}

export default ErrorBoundary;
