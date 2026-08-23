import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@shared/context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import ErrorBoundary from './components/ErrorBoundary';
import Layout from './components/Layout';
import Landing from './pages/Landing';
import CaCertificates from './pages/CaCertificates';
import CrlDownload from './pages/CrlDownload';
import AcmeDirectory from './pages/AcmeDirectory';
import NotFound from './pages/NotFound';
import { ScrollToTop } from '@shared/components/ScrollToTop';
import TitleManager from './components/TitleManager';

function App() {
    return (
        <ErrorBoundary>
            <ThemeProvider>
                <ToastProvider>
                    <BrowserRouter basename="/public">
                        <ScrollToTop />
                        <TitleManager />
                        <Routes>
                            <Route element={<Layout />}>
                                <Route path="/" element={<Landing />} />
                                <Route path="/certificates" element={<CaCertificates />} />
                                <Route path="/crl" element={<CrlDownload />} />
                                <Route path="/acme" element={<AcmeDirectory />} />
                                <Route path="*" element={<NotFound />} />
                            </Route>
                        </Routes>
                    </BrowserRouter>
                </ToastProvider>
            </ThemeProvider>
        </ErrorBoundary>
    );
}

export default App;
