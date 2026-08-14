/** Route table. The dashboard is the default landing page. */

import { useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { setUnauthorizedHandler } from './services/api';
import Layout from './components/Layout';
import Analyze from './pages/Analyze';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import Login from './pages/Login';
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
        {/* Standalone: the login placeholder has no sidebar, as a real sign-in
            page would not be reachable from inside the authenticated shell. */}
        <Route path="/login" element={<Login />} />

        <Route element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
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
