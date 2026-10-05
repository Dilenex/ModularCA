import React, { useMemo, useState } from 'react';
import { useAutoFocus } from '../hooks/useAutoFocus';

export interface AdminAccountData {
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
}

interface AdminAccountProps {
    data: AdminAccountData;
    onChange: (data: AdminAccountData) => void;
}

interface PasswordRule {
    label: string;
    test: (pw: string) => boolean;
}

const passwordRules: PasswordRule[] = [
    { label: '16 or more characters', test: pw => pw.length >= 16 },
    { label: 'At least one uppercase letter', test: pw => /[A-Z]/.test(pw) },
    { label: 'At least one lowercase letter', test: pw => /[a-z]/.test(pw) },
    { label: 'At least one digit', test: pw => /\d/.test(pw) },
    { label: 'At least one symbol', test: pw => /[^A-Za-z0-9]/.test(pw) },
];

const AdminAccount: React.FC<AdminAccountProps> = ({ data, onChange }) => {
    const autoFocusRef = useAutoFocus<HTMLInputElement>();
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirm, setShowConfirm] = useState(false);

    const passwordsMatch = useMemo(() => {
        return data.password.length > 0 && data.password === data.confirmPassword;
    }, [data.password, data.confirmPassword]);

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-ink">Admin Account</h2>
                <p className="text-ink-muted mt-1">
                    Create the initial administrator account for managing ModularCA.
                </p>
            </div>

            <div className="space-y-4">
                <div>
                    <label htmlFor="username" className="block text-sm font-medium text-ink mb-1">
                        Username <span className="text-crit">*</span>
                    </label>
                    <input
                        ref={autoFocusRef}
                        id="username"
                        type="text"
                        required
                        value={data.username}
                        onChange={e => onChange({ ...data, username: e.target.value })}
                        placeholder="admin"
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                    />
                </div>

                <div>
                    <label htmlFor="email" className="block text-sm font-medium text-ink mb-1">
                        Email
                    </label>
                    <input
                        id="email"
                        type="email"
                        value={data.email}
                        onChange={e => onChange({ ...data, email: e.target.value })}
                        placeholder="admin@example.com"
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                    />
                </div>

                <div>
                    <label htmlFor="password" className="block text-sm font-medium text-ink mb-1">
                        Password <span className="text-crit">*</span>
                    </label>
                    <div className="relative">
                        <input
                            id="password"
                            type={showPassword ? 'text' : 'password'}
                            required
                            autoComplete="new-password"
                            value={data.password}
                            onChange={e => onChange({ ...data, password: e.target.value })}
                            className="w-full px-3 py-2 pr-10 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute inset-y-0 right-0 flex items-center pr-3 text-ink-muted hover:text-ink"
                            aria-label={showPassword ? 'Hide password' : 'Show password'}
                        >
                            {showPassword ? (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                                    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                                    <line x1="1" y1="1" x2="23" y2="23" />
                                </svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                    <circle cx="12" cy="12" r="3" />
                                </svg>
                            )}
                        </button>
                    </div>
                </div>

                <div>
                    <label htmlFor="confirmPassword" className="block text-sm font-medium text-ink mb-1">
                        Confirm Password <span className="text-crit">*</span>
                    </label>
                    <div className="relative">
                        <input
                            id="confirmPassword"
                            type={showConfirm ? 'text' : 'password'}
                            required
                            autoComplete="new-password"
                            value={data.confirmPassword}
                            onChange={e => onChange({ ...data, confirmPassword: e.target.value })}
                            className={`w-full px-3 py-2 pr-10 bg-raised border rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent ${
                                data.confirmPassword.length > 0 && !passwordsMatch
                                    ? 'border-crit'
                                    : 'border-line-strong'
                            }`}
                        />
                        <button
                            type="button"
                            onClick={() => setShowConfirm(!showConfirm)}
                            className="absolute inset-y-0 right-0 flex items-center pr-3 text-ink-muted hover:text-ink"
                            aria-label={showConfirm ? 'Hide password' : 'Show password'}
                        >
                            {showConfirm ? (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                                    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                                    <line x1="1" y1="1" x2="23" y2="23" />
                                </svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                    <circle cx="12" cy="12" r="3" />
                                </svg>
                            )}
                        </button>
                    </div>
                    {data.confirmPassword.length > 0 && !passwordsMatch && (
                        <p className="text-sm text-crit mt-1">Passwords do not match</p>
                    )}
                </div>
            </div>

            {/* Password requirements */}
            <div className="bg-ground border border-line rounded-lg p-4">
                <p className="text-sm font-medium text-ink mb-2">Password Requirements</p>
                <ul className="space-y-1">
                    {passwordRules.map((rule, i) => {
                        const met = rule.test(data.password);
                        return (
                            <li key={i} className="flex items-center gap-2 text-sm">
                                <span className={met ? 'text-ok' : 'text-ink-muted'}>
                                    {met ? '\u2713' : '\u25CB'}
                                </span>
                                <span className={met ? 'text-ok' : 'text-ink-muted'}>
                                    {rule.label}
                                </span>
                            </li>
                        );
                    })}
                    <li className="flex items-center gap-2 text-sm">
                        <span className={passwordsMatch ? 'text-ok' : 'text-ink-muted'}>
                            {passwordsMatch ? '\u2713' : '\u25CB'}
                        </span>
                        <span className={passwordsMatch ? 'text-ok' : 'text-ink-muted'}>
                            Passwords match
                        </span>
                    </li>
                </ul>
            </div>
        </div>
    );
};

export default AdminAccount;
