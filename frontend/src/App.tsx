/**
 * Route table.
 *
 * `/` is the public front page, deliberately outside the application shell: a
 * first-time visitor should be told what the platform does and what it refuses
 * to do before being handed a console full of aggregate numbers. Everything
 * from `/dashboard` onwards is the console proper.
 */

import { useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { setUnauthorizedHandler } from './services/api';
import Layout from './components/Layout';
import Analyze from './pages/Analyze';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Privacy from './pages/legal/Privacy';
import Terms from './pages/legal/Terms';
import NotFound from './pages/NotFound';
import Report from './pages/Report';
import Settings from './pages/Settings';
import { AnalyzeDomain, AnalyzeFile, AnalyzeHash, AnalyzeIp, AnalyzeUrl } from './pages/analyzers';

/**
 * Sends the user to the token form when the API refuses them.
 *
 * Lives inside the router so it can navigate, and is registered once for the
 * whole app rather than handled per page — otherwise every new page would have
 * to remember to deal with 401 itself.
 */
function UnauthorizedRedirect() {
  const navigate = useNavigate();
  const { pathname } = useLocation();

  useEffect(() => {
    setUnauthorizedHandler((method) => {
      // Only redirect when a *page* could not load. A refused action — the
      // delete button on an otherwise-public instance — must stay put and show
      // its error in place; navigating away would lose the report the user is
      // looking at to fix a problem they may not even want to fix.
      if (method !== 'GET' && method !== 'HEAD') return;
      // Already on /login: the form shows its own error, and redirecting to
      // the page we are on would discard what the user just typed.
      if (pathname !== '/login') navigate('/login', { replace: true });
    });
    return () => setUnauthorizedHandler(null);
  }, [navigate, pathname]);

  return null;
}

export default function App() {
  return (
    <BrowserRouter>
      <UnauthorizedRedirect />
      <Routes>
        {/* Standalone pages: neither belongs inside the console shell. The
            front page addresses someone who has not decided to use the tool
            yet, and a real sign-in page would not be reachable from inside the
            authenticated shell. */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />

        {/* Policies sit outside the shell too: they have to be readable by
            someone deciding whether to use the tool at all. */}
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/terms" element={<Terms />} />

        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />

          <Route path="/analyze" element={<Analyze />}>
            <Route index element={<Navigate to="/analyze/url" replace />} />
            <Route path="url" element={<AnalyzeUrl />} />
            <Route path="file" element={<AnalyzeFile />} />
            <Route path="hash" element={<AnalyzeHash />} />
            <Route path="ip" element={<AnalyzeIp />} />
            <Route path="domain" element={<AnalyzeDomain />} />
          </Route>

          <Route path="/analysis/:id" element={<Report />} />
          <Route path="/history" element={<History />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
