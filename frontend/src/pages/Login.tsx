/**
 * Authentication placeholder.
 *
 * Honest by design: it does not pretend to sign anyone in, and it does not
 * collect credentials it would have nowhere to send. A fake login form that
 * accepts any password would be worse than no form at all -- it teaches the
 * wrong habit and implies a security control that does not exist.
 */

import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldMark } from '../components/Brand';
import { useFetch } from '../hooks/useAsync';
import { api, setAccessToken } from '../services/api';

/**
 * Token entry for instances running behind the optional shared-token gate.
 *
 * Shown only when the backend actually rejects an unauthenticated request, so
 * a local instance still sees the honest "authentication is not enabled"
 * message rather than a login form that gates nothing.
 */
function TokenForm() {
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setChecking(true);
    setError(null);
    setAccessToken(token.trim());
    try {
      // Verified against a gated endpoint rather than stored on trust, so a
      // wrong token fails here instead of on the next page the user opens.
      await api.config();
      navigate('/dashboard');
    } catch {
      setAccessToken('');
      setError('That token was not accepted.');
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="card-padded">
      <h2 className="text-sm font-semibold text-content-primary">Access token required</h2>
      <p className="mt-2 text-sm leading-relaxed text-content-secondary">
        This instance is published behind a shared-token gate. Enter the token to continue.
      </p>

      <form onSubmit={handleSubmit} className="mt-5 space-y-3">
        <div>
          <label htmlFor="token" className="label-text mb-2 block">
            Access token
          </label>
          <input
            id="token"
            type="password"
            value={token}
            autoComplete="off"
            className="input-field font-mono"
            onChange={(event) => setToken(event.target.value)}
            aria-invalid={Boolean(error)}
          />
        </div>

        {error && (
          <p role="alert" className="text-sm text-verdict-critical">
            {error}
          </p>
        )}

        <button type="submit" className="btn-primary w-full" disabled={!token.trim() || checking}>
          {checking ? 'Checking…' : 'Continue'}
        </button>
      </form>

      <p className="mt-4 text-xs leading-relaxed text-content-muted">
        A single shared secret, not a user account. It identifies no one and cannot be revoked
        individually — appropriate for a temporary deployment, not for real multi-user access.
      </p>
    </div>
  );
}

export default function Login() {
  // Probe rather than assume: the page shows a token form only if the backend
  // genuinely rejects an unauthenticated request. A login form that gates
  // nothing would imply a control that does not exist.
  const { error } = useFetch(() => api.config(), []);
  const gated = error?.status === 401;

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-0 px-4 py-12">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <ShieldMark className="h-11 w-11" />
          <h1 className="mt-4 text-2xl font-semibold tracking-tight text-content-primary">
            SentinelCTI
          </h1>
          <p className="mt-1.5 text-sm text-content-secondary">
            Cyber Threat Intelligence Platform
          </p>
        </div>

        {gated ? (
          <TokenForm />
        ) : (
          <div className="card-padded">
            <h2 className="text-sm font-semibold text-content-primary">
              Authentication is not enabled
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-content-secondary">
              This MVP runs without user accounts so that the threat-analysis engine remains the
              focus. The backend is structured so that authentication can be added without reworking
              the API: every route is mounted through a single router, so one global dependency
              would protect all of them.
            </p>

            <div className="mt-5 rounded-lg border border-verdict-suspicious/30 bg-verdict-suspicious/10 px-4 py-3 text-xs leading-relaxed text-verdict-suspicious">
              Because there is no access control, deploy this instance on a trusted network only.
              Anything submitted is readable by anyone who can reach the application.
            </div>

            <Link to="/dashboard" className="btn-primary mt-5 w-full">
              Continue to dashboard
            </Link>
          </div>
        )}

        <p className="mt-6 text-center text-xs text-content-muted">
          Defensive analysis only · Files are never executed · URLs are never fetched
        </p>
      </div>
    </div>
  );
}
