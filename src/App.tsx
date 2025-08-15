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
        roles: ['user'],
        authLevel: 'basic' // Začínáme se základní úrovní
      });
    }
    setLoading(false);
  };

  const login = (): void => {
    const authUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth` +
      `?client_id=${KEYCLOAK_CONFIG.clientId}` +
      `&redirect_uri=${encodeURIComponent(window.location.origin)}` +
      `&response_type=code` +
      `&scope=openid profile email` +
      `&claims=${encodeURIComponent(JSON.stringify({
        "id_token": {
          "acr": {"essential": true, "values": ["1", "2", "3"]},
          "amr": {"essential": true}
        }
      }))}`;
    
    console.log('Auth URL:', authUrl);
    
    // SKUTEČNÉ PŘIHLÁŠENÍ - přesměrování na Keycloak
    window.location.href = authUrl;
    
    // Pro demo simulaci můžeš zakomentovat výše a odkomentovat níže:
    /*
    setTimeout(() => {
      localStorage.setItem('access_token', 'demo-token-123');
      setIsAuthenticated(true);
      setUserInfo({
        name: 'Demo Uživatel',
        email: 'demo@example.com',
        roles: ['user'],
        acr: '1', // Simulace základního přihlášení
        amr: ['pwd'],
        authTime: Math.floor(Date.now() / 1000)
      });
    }, 1000);
    */
  };

  const logout = (): void => {
    // Smaž všechny auth related údaje
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('id_token');
    sessionStorage.clear();
    
    setIsAuthenticated(false);
    setUserInfo(null);
    
    // V reálné aplikaci by to přesměrovalo na Keycloak logout
    // const logoutUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/logout?redirect_uri=${encodeURIComponent(window.location.origin)}`;
    // window.location.href = logoutUrl;
  };

  // Debug funkce pro smazání všech dat
  const clearAllData = (): void => {
    localStorage.clear();
    sessionStorage.clear();
    console.log('🧹 Všechna data smazána');
    window.location.reload();
  };

  // Step-up authentication pomocí Keycloak
  const requestStepUp = (requiredAcrLevel: string, maxAge?: number): void => {
    const stepUpUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth` +
      `?client_id=${KEYCLOAK_CONFIG.clientId}` +
      `&redirect_uri=${encodeURIComponent(window.location.origin)}` +
      `&response_type=code` +
      `&scope=openid profile email` +
      `&prompt=login` + // Vynutí re-autentizaci
      `&claims=${encodeURIComponent(JSON.stringify({
        "id_token": {
          "acr": {
            "essential": true, 
            "value": requiredAcrLevel
          },
          "amr": {"essential": true}
        }
      }))}` +
      (maxAge ? `&max_age=${maxAge}` : '') +
      `&state=step_up_${requiredAcrLevel}`;
    
    console.log('Step-up URL:', stepUpUrl);
    
    // Skutečný step-up - přesměrování na Keycloak
    window.location.href = stepUpUrl;
  };

  // Funkce pro kontrolu ACR úrovně
  const hasRequiredAcr = (required: string): boolean => {
    if (!userInfo?.acr) return false;
    return parseInt(userInfo.acr) >= parseInt(required);
  };

  // Funkce pro kontrolu času autentizace (pro max_age)
  const isAuthenticationFresh = (maxAgeSeconds: number): boolean => {
    if (!userInfo?.authTime) return false;
    const now = Math.floor(Date.now() / 1000);
    return (now - userInfo.authTime) <= maxAgeSeconds;
  };

  // Funkce pro přístup k citlivým sekcím
  const accessSensitiveArea = (area: string, requiredAcr: string, maxAge?: number): void => {
    const hasAcr = hasRequiredAcr(requiredAcr);
    const isFresh = maxAge ? isAuthenticationFresh(maxAge) : true;
    
    if (hasAcr && isFresh) {
      alert(`🔓 Přístup povolen do sekce: ${area}\nACR: ${userInfo?.acr}, AMR: ${userInfo?.amr.join(', ')}`);
    } else {
      const reason = !hasAcr ? 
        `Vyžadována ACR úroveň ${requiredAcr}, máte ${userInfo?.acr}` :
        `Autentizace je příliš stará (max ${maxAge}s)`;
      
      if (confirm(`🔒 ${reason}\n\nChcete provést step-up autentizaci?`)) {
        requestStepUp(requiredAcr, maxAge);
      }
    }
  };

  // Získání popisku ACR úrovně
  const getAcrLabel = (acr: string): string => {
    switch (acr) {
      case '1': return 'Základní (heslo)';
      case '2': return 'Dvou-faktorová (2FA)';
      case '3': return 'Multi-faktorová (MFA/PKI)';
      default: return `Úroveň ${acr}`;
    }
  };

  // Získání popisku AMR
  const getAmrLabel = (amr: string[]): string => {
    const labels: {[key: string]: string} = {
      'pwd': 'Heslo',
      'sms': 'SMS',
      'otp': 'OTP/TOTP',
      'pki': 'PKI certifikát',
      'hwk': 'Hardware klíč',
      'bio': 'Biometrie'
    };
    return amr.map(method => labels[method] || method).join(', ');
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
              
              <button 
                onClick={clearAllData} 
                className="btn btn-danger"
                style={{marginTop: '16px', fontSize: '14px'}}
              >
                🧹 Smazat všechna data (debug)
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
                <div>
                  <strong>ACR úroveň:</strong> 
                  <span className={`auth-level acr-${userInfo?.acr}`}>
                    {userInfo?.acr} - {getAcrLabel(userInfo?.acr || '1')}
                  </span>
                </div>
                <div>
                  <strong>Metody autentizace:</strong> {getAmrLabel(userInfo?.amr || [])}
                </div>
                <div>
                  <strong>Čas autentizace:</strong> {new Date((userInfo?.authTime || 0) * 1000).toLocaleString()}
                </div>
              </div>
            </div>

            <div className="card">
              <h3>Chráněný obsah</h3>
              <p>Tento obsah je viditelný pouze po úspěšném přihlášení.</p>
              <div className="feature-grid">
                <div className="feature-card blue" onClick={() => accessSensitiveArea('Dashboard')}>
                  <h4>Dashboard</h4>
                  <p>Přehled vašich dat</p>
                  <small>🔒 Základní přístup</small>
                </div>
                <div className="feature-card green">
                  <h4>Profil</h4>
                  <p>Správa profilu</p>
                  <small>🔒 Základní přístup</small>
                </div>
                <div className="feature-card purple">
                  <h4>Nastavení</h4>
                  <p>Konfigurace aplikace</p>
                  <small>🔒 Základní přístup</small>
                </div>
              </div>
            </div>

            <div className="card">
              <h3>Citlivé operace podle ACR úrovní</h3>
              <p>Různé sekce vyžadují různé úrovně autentizace podle citlivosti dat.</p>
              
              <div className="feature-grid">
                <div 
                  className={`feature-card orange ${hasRequiredAcr('2') ? 'unlocked' : 'locked'}`}
                  onClick={() => accessSensitiveArea('Finanční údaje', '2')}
                >
                  <h4>💰 Finanční údaje</h4>
                  <p>Bankovní účty a platby</p>
                  <small>
                    🔒 Vyžaduje ACR ≥ 2 (2FA) | Máte: ACR {userInfo?.acr}
                  </small>
                </div>
                
                <div 
                  className={`feature-card red ${hasRequiredAcr('3') ? 'unlocked' : 'locked'}`}
                  onClick={() => accessSensitiveArea('Administrace', '3')}
                >
                  <h4>⚙️ Admin konzole</h4>
                  <p>Správa uživatelů a systému</p>
                  <small>
                    🔒 Vyžaduje ACR ≥ 3 (MFA/PKI) | Máte: ACR {userInfo?.acr}
                  </small>
                </div>
                
                <div 
                  className={`feature-card dark ${hasRequiredAcr('2') && isAuthenticationFresh(300) ? 'unlocked' : 'locked'}`}
                  onClick={() => accessSensitiveArea('Bezpečnostní logy', '2', 300)}
                >
                  <h4>🛡️ Security Logs</h4>
                  <p>Audit trail (fresh auth required)</p>
                  <small>
                    🔒 Vyžaduje ACR ≥ 2 + max 5min | Auth: {Math.floor((Date.now()/1000 - (userInfo?.authTime || 0))/60)}min
                  </small>
                </div>
              </div>
              
              <div className="step-up-controls">
                <h4>🔐 Step-up Authentication možnosti:</h4>
                <div className="step-up-buttons">
                  <button 
                    onClick={() => requestStepUp('2')} 
                    className="btn btn-primary"
                    disabled={hasRequiredAcr('2')}
                  >
                    🔐 ACR 2 (2FA)
                  </button>
                  <button 
                    onClick={() => requestStepUp('3')} 
                    className="btn btn-primary"
                    disabled={hasRequiredAcr('3')}
                  >
                    🔐 ACR 3 (MFA/PKI)
                  </button>
                  <button 
                    onClick={() => requestStepUp(userInfo?.acr || '1', 60)} 
                    className="btn btn-secondary"
                  >
                    🕐 Re-auth (fresh)
                  </button>
                </div>
                
                <div className="acr-legend">
                  <h5>ACR úrovně:</h5>
                  <ul>
                    <li><strong>ACR 1:</strong> Heslo</li>
                    <li><strong>ACR 2:</strong> Dva faktory (heslo + SMS/OTP)</li>
                    <li><strong>ACR 3:</strong> Multi-faktor nebo PKI certifikát</li>
                  </ul>
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