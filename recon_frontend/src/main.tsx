import { ThemeProvider } from 'next-themes';
import { createRoot } from 'react-dom/client';

import App from './app/App.tsx';
import { Toaster } from './app/components/ui/sonner.tsx';
import { AuthProvider } from './app/context/AuthContext.tsx';
import './styles/index.css';

createRoot(document.getElementById('root')!).render(
  <ThemeProvider attribute="class" defaultTheme="light" enableSystem>
    <AuthProvider>
      <App />
      <Toaster richColors position="top-right" />
    </AuthProvider>
  </ThemeProvider>,
);
