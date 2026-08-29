import React, { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useParams } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import ErrorBoundary from './components/ErrorBoundary';
import { StepUpMfaProvider } from './components/StepUpMfaContext';
import { ThemeProvider } from '@shared/context/ThemeContext';
import { TablePrefsProvider } from '@shared/context/TablePrefsContext';
import { AuthClientProvider } from '@shared-auth/api/AuthClientContext';
import { apiGet, apiPut, authClient } from './api/client';
import { ToastProvider } from '@shared/context/ToastContext';
import { TenantProvider } from './context/TenantContext';
import { AuthProvider } from './context/AuthContext';
import { ScrollToTop } from '@shared/components/ScrollToTop';
import TitleManager from './components/TitleManager';

// Auth pages — eagerly loaded (entry points, must render immediately)
import LoginPage from './pages/Login';
import LoginBannerPage from './pages/LoginBanner';
import MfaSetupPage from './pages/MfaSetup';
import MfaVerifyPage from './pages/MfaVerify';
import MfaCallbackPage from './pages/MfaCallback';

// All other pages — lazily loaded per route
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Certificates = React.lazy(() => import('./pages/Certificates'));
const CertificateDetail = React.lazy(() => import('./pages/CertificateDetail'));
const CertificateRequestDetail = React.lazy(() => import('./pages/CertificateRequestDetail'));
const IssueCertificate = React.lazy(() => import('./pages/IssueCertificate'));
const ExpiryCalendar = React.lazy(() => import('./pages/ExpiryCalendar'));
const CertificateRequests = React.lazy(() => import('./pages/CertificateRequests'));
const CaManagement = React.lazy(() => import('./pages/CaManagement'));
const CaDetail = React.lazy(() => import('./pages/CaDetail'));
const ProtocolConfig = React.lazy(() => import('./pages/ProtocolConfig'));
const Distribution = React.lazy(() => import('./pages/Distribution'));
const CrlScheduleDetail = React.lazy(() => import('./pages/CrlScheduleDetail'));
const LdapPublisherDetail = React.lazy(() => import('./pages/LdapPublisherDetail'));
const ProfileManagement = React.lazy(() => import('./pages/ProfileManagement'));
const RequestProfileDetail = React.lazy(() => import('./pages/RequestProfileDetail'));
const CertProfileDetail = React.lazy(() => import('./pages/CertProfileDetail'));
const SigningProfileDetail = React.lazy(() => import('./pages/SigningProfileDetail'));
const SshSigningProfileDetail = React.lazy(() => import('./pages/SshSigningProfileDetail'));
const SshCertProfileDetail = React.lazy(() => import('./pages/SshCertProfileDetail'));
const SshRequestProfileDetail = React.lazy(() => import('./pages/SshRequestProfileDetail'));
const AcmeManagement = React.lazy(() => import('./pages/AcmeManagement'));
const SshCertificates = React.lazy(() => import('./pages/SshCertificates'));
const SshCaKeyDetail = React.lazy(() => import('./pages/SshCaKeyDetail'));
const SshCertDetail = React.lazy(() => import('./pages/SshCertDetail'));
const Users = React.lazy(() => import('./pages/Users'));
const UserDetail = React.lazy(() => import('./pages/UserDetail'));
const GroupManagement = React.lazy(() => import('./pages/GroupManagement'));
const GroupDetail = React.lazy(() => import('./pages/GroupDetail'));
const RoleManagement = React.lazy(() => import('./pages/RoleManagement'));
const RoleDetail = React.lazy(() => import('./pages/RoleDetail'));
const EnrollmentManagement = React.lazy(() => import('./pages/EnrollmentManagement'));
const AuditLogs = React.lazy(() => import('./pages/AuditLogs'));
const AuditLogDetail = React.lazy(() => import('./pages/AuditLogDetail'));
const NotificationManagement = React.lazy(() => import('./pages/NotificationManagement'));
const CertificateTemplates = React.lazy(() => import('./pages/CertificateTemplates'));
const Settings = React.lazy(() => import('./pages/Settings'));
const BackupRestore = React.lazy(() => import('./pages/BackupRestore'));
const WebTlsManagement = React.lazy(() => import('./pages/WebTlsManagement'));
const SystemHealth = React.lazy(() => import('./pages/SystemHealth'));
const TrustAnchors = React.lazy(() => import('./pages/TrustAnchors'));
// Shared with the other authenticated SPA. Named export, so the lazy import maps it onto
// the `default` shape React.lazy expects — shared/README rule 3 forbids default exports.
const AccountDetail = React.lazy(() =>
    import('@shared-auth/pages/AccountDetail').then((m) => ({ default: m.AccountDetail })));
const CertInventory = React.lazy(() => import('./pages/CertInventory'));
const Compliance = React.lazy(() => import('./pages/Compliance'));
const Ceremonies = React.lazy(() => import('./pages/Ceremonies'));
const TenantsAndQuotas = React.lazy(() => import('./pages/TenantsAndQuotas'));
const TenantDetail = React.lazy(() => import('./pages/TenantDetail'));
const Whitelists = React.lazy(() => import('./pages/Whitelists'));
const WhitelistDetail = React.lazy(() => import('./pages/WhitelistDetail'));
const Schedules = React.lazy(() => import('./pages/Schedules'));
const SchedulerJobDetail = React.lazy(() => import('./pages/SchedulerJobDetail'));
const NotFound = React.lazy(() => import('./pages/NotFound'));

// Role gating constants. Admin-only routes carry the role list
// in App.tsx so a future doctrine change (e.g. allowing Operators into Settings) is
// a single edit. Mirror these in Layout.tsx's sidenav definitions.
const ADMIN_ONLY = ['Administrator'];
const ADMIN_OPERATOR = ['Administrator', 'Operator'];

// The per-CA LDAP route is retired in favor of the unified Distribution page.
// Redirect it (preserving the CA) so old links/bookmarks land on the LDAP tab.
const LdapCaRedirect: React.FC = () => {
    const { caId } = useParams<{ caId: string }>();
    return <Navigate to={`/distribution?tab=ldap${caId ? `&caId=${caId}` : ''}`} replace />;
};

const PageLoader = () => (
    <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
    </div>
);

const App: React.FC = () => {
    return (
        <ErrorBoundary>
            <ThemeProvider>
                {/* Supplies this app's API client to the shared table preference store. */}
                {/* Hands this app's API client to shared pages — see AuthClientContext. */}
                <AuthClientProvider client={authClient}>
                <TablePrefsProvider transport={{ apiGet, apiPut }}>
                <ToastProvider>
                    <AuthProvider>
                        <TenantProvider>
                            <Router basename="/admin">
                                <ScrollToTop />
                                <TitleManager />
                                <Routes>
                                    <Route path="/banner" element={<LoginBannerPage />} />
                                    <Route path="/login" element={<LoginPage />} />
                                    <Route path="/mfa-setup" element={<MfaSetupPage />} />
                                    <Route path="/mfa-verify" element={<MfaVerifyPage />} />
                                    <Route path="/mfa-callback" element={<MfaCallbackPage />} />
                                    <Route path="/*" element={
                                        <ProtectedRoute>
                                            <StepUpMfaProvider>
                                                <Layout>
                                                    <Suspense fallback={<PageLoader />}>
                                                        <Routes>
                                                            {/* Overview */}
                                                            <Route path="/" element={<Dashboard />} />
                                                            <Route path="/dashboard" element={<Dashboard />} />
                                                            <Route path="/health" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><SystemHealth /></ProtectedRoute>} />

                                                            {/* Certificates */}
                                                            <Route path="/certificates" element={<Certificates />} />
                                                            <Route path="/certificates/request" element={<IssueCertificate />} />
                                                            {/* Certificate Search merged into the Certificates page (advanced filters). */}
                                                            <Route path="/certificates/search" element={<Navigate to="/certificates" replace />} />
                                                            <Route path="/certificates/expiry" element={<ExpiryCalendar />} />
                                                            <Route path="/certificates/requests" element={<CertificateRequests />} />
                                                            <Route path="/certificates/requests/:id" element={<CertificateRequestDetail />} />
                                                            <Route path="/certificates/:serial" element={<CertificateDetail />} />

                                                            {/* CA Management */}
                                                            <Route path="/authorities/manage" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><CaManagement /></ProtectedRoute>} />
                                                            <Route path="/authorities/manage/:id" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><CaDetail /></ProtectedRoute>} />
                                                            <Route path="/authorities/protocols" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><ProtocolConfig /></ProtectedRoute>} />
                                                            <Route path="/distribution" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><Distribution /></ProtectedRoute>} />
                                                            <Route path="/distribution/crl/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><CrlScheduleDetail /></ProtectedRoute>} />
                                                            <Route path="/distribution/ldap/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><LdapPublisherDetail /></ProtectedRoute>} />
                                                            {/* CRL Management merged into the Distribution page; redirect old paths. */}
                                                            <Route path="/crl" element={<Navigate to="/distribution" replace />} />
                                                            <Route path="/authorities/:caId/ldap" element={<LdapCaRedirect />} />
                                                            <Route path="/trust-anchors" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><TrustAnchors /></ProtectedRoute>} />

                                                            {/* Profiles */}
                                                            <Route path="/profiles" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><ProfileManagement /></ProtectedRoute>} />
                                                            <Route path="/profiles/request/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><RequestProfileDetail /></ProtectedRoute>} />
                                                            <Route path="/profiles/cert/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><CertProfileDetail /></ProtectedRoute>} />
                                                            <Route path="/profiles/signing/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><SigningProfileDetail /></ProtectedRoute>} />
                                                            <Route path="/profiles/ssh-signing/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><SshSigningProfileDetail /></ProtectedRoute>} />
                                                            <Route path="/profiles/ssh-cert/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><SshCertProfileDetail /></ProtectedRoute>} />
                                                            <Route path="/profiles/ssh-request/:id" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><SshRequestProfileDetail /></ProtectedRoute>} />
                                                            <Route path="/templates" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><CertificateTemplates /></ProtectedRoute>} />

                                                            {/* Protocols */}
                                                            <Route path="/acme" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><AcmeManagement /></ProtectedRoute>} />
                                                            <Route path="/ssh" element={<SshCertificates />} />
                                                            <Route path="/ssh/ca-keys/:id" element={<SshCaKeyDetail />} />
                                                            <Route path="/ssh/certs/:id" element={<SshCertDetail />} />

                                                            {/* Access Control */}
                                                            <Route path="/users" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><Users /></ProtectedRoute>} />
                                                            <Route path="/users/:id" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><UserDetail /></ProtectedRoute>} />
                                                            <Route path="/groups" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><GroupManagement /></ProtectedRoute>} />
                                                            <Route path="/groups/:id" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><GroupDetail /></ProtectedRoute>} />
                                                            <Route path="/roles" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><RoleManagement /></ProtectedRoute>} />
                                                            <Route path="/roles/:id" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><RoleDetail /></ProtectedRoute>} />
                                                            <Route path="/enrollment" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><EnrollmentManagement /></ProtectedRoute>} />
                                                            <Route path="/ceremonies" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><Ceremonies /></ProtectedRoute>} />
                                                            {/* Quotas merged into Tenants & Quotas — redirect the old path. */}
                                                            <Route path="/quotas" element={<Navigate to="/tenants" replace />} />

                                                            {/* Intelligence */}
                                                            <Route path="/intel/inventory" element={<CertInventory />} />
                                                            {/* Vulnerabilities merged into Compliance — redirect the old path. */}
                                                            <Route path="/intel/vulnerabilities" element={<Navigate to="/intel/compliance" replace />} />
                                                            <Route path="/intel/compliance" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><Compliance /></ProtectedRoute>} />

                                                            {/* Monitoring */}
                                                            <Route path="/audit" element={<ProtectedRoute requiredRoles={['Administrator', 'Auditor']}><AuditLogs /></ProtectedRoute>} />
                                                            <Route path="/audit/:type/:id" element={<ProtectedRoute requiredRoles={['Administrator', 'Auditor']}><AuditLogDetail /></ProtectedRoute>} />
                                                            <Route path="/notifications" element={<ProtectedRoute requiredRoles={ADMIN_OPERATOR}><NotificationManagement /></ProtectedRoute>} />

                                                            {/* My Account */}
                                                            <Route path="/account" element={<AccountDetail />} />
                                                            {/* Old self-service security route → consolidated into the account page. */}
                                                            <Route path="/security" element={<Navigate to="/account" replace />} />

                                                            {/* Administration */}
                                                            <Route path="/tenants" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><TenantsAndQuotas /></ProtectedRoute>} />
                                                            <Route path="/tenants/:id" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><TenantDetail /></ProtectedRoute>} />
                                                            <Route path="/whitelists" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><Whitelists /></ProtectedRoute>} />
                                                            <Route path="/whitelists/:id" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><WhitelistDetail /></ProtectedRoute>} />
                                                            <Route path="/settings" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><Settings /></ProtectedRoute>} />
                                                            <Route path="/backup" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><BackupRestore /></ProtectedRoute>} />
                                                            <Route path="/schedules" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><Schedules /></ProtectedRoute>} />
                                                            <Route path="/schedules/jobs/:name" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><SchedulerJobDetail /></ProtectedRoute>} />
                                                            <Route path="/webtls" element={<ProtectedRoute requiredRoles={ADMIN_ONLY}><WebTlsManagement /></ProtectedRoute>} />

                                                            {/* Catch-all 404 — must come last. Renders inside the authenticated
                                                                Layout so the operator keeps the sidebar and tenant context
                                                                while seeing the page-not-found message. */}
                                                            <Route path="*" element={<NotFound />} />
                                                        </Routes>
                                                    </Suspense>
                                                </Layout>
                                            </StepUpMfaProvider>
                                        </ProtectedRoute>
                                    } />
                                </Routes>
                            </Router>
                        </TenantProvider>
                    </AuthProvider>
                </ToastProvider>
                </TablePrefsProvider>
                </AuthClientProvider>
            </ThemeProvider>
        </ErrorBoundary>
    );
};

export default App;
