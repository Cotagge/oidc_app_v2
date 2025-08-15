import React, { useState, useEffect } from 'react';
import './App.css';

// TypeScript interface pro uživatelské informace
interface UserInfo {
  name: string;
  email: string;
  roles: string[];
}

// TypeScript interface pro Keycloak konfiguraci
interface KeycloakConfig {
  url: string;
  realm: string;
  clientId: string;
}

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Konfigurace pro Keycloak - použije environment variables
  const KEYCLOAK_CONFIG: KeycloakConfig = {
    url: process.env.REACT_APP_KEYCLOAK_URL || 'https://your-keycloak-server.com',
    realm: process.env.REACT_APP_KEYCLOAK_REALM || 'your-realm',
    clientId: process.env.REACT_APP_KEYCLOAK_CLIENT_ID || 'your-client-id'
  };

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = (): void => {
    const token = localStorage.getItem('access_token');
    if (token) {
      setIsAuthenticated(true);
      setUserInfo({
        name: 'Demo Uživatel',
        email: 'demo@example.com',
        roles: ['user']
      });
    }
    setLoading(false);
  };

  const login = (): void => {
    const authUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth` +
      `?client_id=${KEYCLOAK_CONFIG.clientId}` +
      `&redirect_uri=${encodeURIComponent(window.location.origin)}` +
      `&response_type=code` +
      `&scope=openid profile email`;
    
    console.log('Auth URL:', authUrl);
    
    // Pro demo simulujeme úspěšné přihlášení
    setTimeout(() => {
      localStorage.setItem('access_token', 'demo-token-123');
      setIsAuthenticated(true);
      setUserInfo({
        name: 'Demo Uživatel',
        email: 'demo@example.com',
        roles: ['user']
      });
    }, 1000);
  };

  const logout = (): void => {
    localStorage.removeItem('access_token');
    setIsAuthenticated(false);
    setUserInfo(null);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Načítám...</p>
      </div>
    );
  }

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-content">
          <div className="nav-left">
            <h1>OIDC Demo App</h1>
            {process.env.NODE_ENV === 'development' && (
              <span className="demo-badge">Demo Mode</span>
            )}
          </div>
          <div className="nav-right">
            {isAuthenticated ? (
              <>
                <span className="user-greeting">Vítej, {userInfo?.name}</span>
                <button onClick={logout} className="btn btn-danger">
                  Odhlásit se
                </button>
              </>
            ) : (
              <button onClick={login} className="btn btn-primary">
                Přihlásit se
              </button>
            )}
          </div>
        </div>
      </nav>

      <main className="main-content">
        {!isAuthenticated ? (
          <div className="login-container">
            <div className="login-card">
              <h2>Přihlášení vyžadováno</h2>
              <p>Pro přístup do aplikace se musíte přihlásit pomocí Keycloak OIDC.</p>
              
              {process.env.NODE_ENV === 'development' && (
                <div className="debug-info">
                  <h4>Debug informace:</h4>
                  <div><strong>Keycloak URL:</strong> {KEYCLOAK_CONFIG.url}</div>
                  <div><strong>Realm:</strong> {KEYCLOAK_CONFIG.realm}</div>
                  <div><strong>Client ID:</strong> {KEYCLOAK_CONFIG.clientId}</div>
                </div>
              )}
              
              <button onClick={login} className="btn btn-primary btn-large">
                🔐 Přihlásit přes Keycloak
              </button>
            </div>
          </div>
        ) : (
          <div className="dashboard">
            <div className="card">
              <h2>Vítejte v aplikaci!</h2>
              <p>Úspěšně jste se přihlásili pomocí OIDC. Zde jsou vaše informace:</p>
              
              <div className="user-info">
                <h3>Uživatelské informace:</h3>
                <div><strong>Jméno:</strong> {userInfo?.name}</div>
                <div><strong>Email:</strong> {userInfo?.email}</div>
                <div><strong>Role:</strong> {userInfo?.roles?.join(', ')}</div>
              </div>
            </div>

            <div className="card">
              <h3>Chráněný obsah</h3>
              <p>Tento obsah je viditelný pouze po úspěšném přihlášení.</p>
              <div className="feature-grid">
                <div className="feature-card blue">
                  <h4>Dashboard</h4>
                  <p>Přehled vašich dat</p>
                </div>
                <div className="feature-card green">
                  <h4>Profil</h4>
                  <p>Správa profilu</p>
                </div>
                <div className="feature-card purple">
                  <h4>Nastavení</h4>
                  <p>Konfigurace aplikace</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default App;