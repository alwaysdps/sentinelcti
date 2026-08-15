import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { purgeWorkspaceOnExit } from './services/api';
import './index.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root element #root not found in index.html');

// Registered here rather than in a component: it must be attached exactly once
// for the life of the page, and StrictMode deliberately double-invokes effects.
purgeWorkspaceOnExit();

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
