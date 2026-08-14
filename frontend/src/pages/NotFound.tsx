import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <p className="font-mono text-5xl font-semibold text-content-muted">404</p>
      <h1 className="mt-4 text-xl font-semibold text-content-primary">Page not found</h1>
      <p className="mt-2 max-w-sm text-sm text-content-secondary">
        That route does not exist in SentinelCTI.
      </p>
      <Link to="/dashboard" className="btn-primary mt-6">
        Back to dashboard
      </Link>
    </div>
  );
}
