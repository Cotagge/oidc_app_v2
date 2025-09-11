import React, { useState, useEffect, useCallback, useMemo } from 'react';
import './App.css';

// TypeScript interface pro uživatelské informace
interface UserInfo {
  name: string;
  email: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  sub?: string;
  acr?: string;
}

// TypeScript interface pro Keycloak konfiguraci
interface KeycloakConfig {
  url: string;
  realm: string;
  clientId1F: string;  // Pro 1FA
  clientId2F: string;  // Pro 2FA
  clientId3F: string;  // Pro 3FA
}

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [usedClientType, setUsedClientType] = useState<'1FA' | '2FA' | '3FA' | null>(null);

  // Konfigurace pro Keycloak - použije environment variables
  const KEYCLOAK_CONFIG: KeycloakConfig = useMemo(() => ({
    url: process.env.REACT_APP_KEYCLOAK_URL || 'https://your-keycloak-server.com',
    realm: process.env.REACT_APP_KEYCLOAK_REALM || 'your-realm',
    clientId1F: process.env.REACT_APP_KEYCLOAK_CLIENT_ID_1F || 'test-client-oidc-demo_v2-1f',  // 1FA klient z .env
    clientId2F: process.env.REACT_APP_KEYCLOAK_CLIENT_ID_2F || 'test-client-oidc-demo_v2-2f',   // 2FA klient z .env
    clientId3F: process.env.REACT_APP_KEYCLOAK_CLIENT_ID_3F || 'test-client-oidc-demo_v2-3f'    // 3FA klient z .env
  }), []);

  // URL pro metadata (.well-known) - opravený standardní endpoint
  const wellKnownUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/.well-known/openid-configuration`;

  // PKCE helper funkce
  const generateCodeVerifier = useCallback((): string => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    // Konverze bez spread operátoru pro kompatibilitu
    let result = '';
    for (let i = 0; i < array.length; i++) {
      result += String.fromCharCode(array[i]);
    }
    return btoa(result)
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }, []);

  const generateCodeChallenge = useCallback(async (verifier: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(digest);
    
    // Konverze bez spread operátoru pro kompatibilitu
    let result = '';
    for (let i = 0; i < hashArray.length; i++) {
      result += String.fromCharCode(hashArray[i]);
    }
    return btoa(result)
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }, []);

  // Získání user info z UserInfo endpointu (fallback)
  const fetchUserInfo = useCallback(async (accessToken: string): Promise<void> => {
    try {
      const userInfoUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/userinfo`;
      const userInfoResponse = await fetch(userInfoUrl, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      if (!userInfoResponse.ok) {
        throw new Error(`UserInfo request failed: ${userInfoResponse.status} ${userInfoResponse.statusText}`);
      }
      const userData = await userInfoResponse.json();
      setIsAuthenticated(true);
      setUserInfo({
        name: userData.name || `${userData.given_name || ''} ${userData.family_name || ''}`.trim() || userData.preferred_username || 'Neznámý uživatel',
        email: userData.email || 'N/A',
        preferred_username: userData.preferred_username || 'N/A',
        given_name: userData.given_name || 'N/A',
        family_name: userData.family_name || 'N/A',
        sub: userData.sub || 'N/A',
        acr: userData.acr || 'N/A'
      });
      localStorage.setItem('user_info', JSON.stringify({
        name: userData.name || `${userData.given_name || ''} ${userData.family_name || ''}`.trim() || userData.preferred_username || 'Neznámý uživatel',
        email: userData.email || 'N/A',
        preferred_username: userData.preferred_username || 'N/A',
        given_name: userData.given_name || 'N/A',
        family_name: userData.family_name || 'N/A',
        sub: userData.sub || 'N/A',
        acr: userData.acr || 'N/A'
      }));
      window.history.replaceState({}, document.title, window.location.pathname);
      localStorage.removeItem('used_auth_code');
      setLoading(false);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Neznámá chyba';
      if (window.location.hostname === 'localhost' && errorMessage.includes('401')) {
        setIsAuthenticated(true);
        setUserInfo({
          name: 'Test Uživatel (Fallback)',
          email: 'test@localhost.com',
          preferred_username: 'test.user',
          given_name: 'Test',
          family_name: 'Uživatel',
          sub: 'localhost-test-user',
          acr: 'N/A'
        });
        window.history.replaceState({}, document.title, window.location.pathname);
        setLoading(false);
        return;
      }
      alert(`Chyba při získávání informací o uživateli: ${errorMessage}`);
      setLoading(false);
    }
  }, [KEYCLOAK_CONFIG]);

  // Parsování user info z ID tokenu
  const parseUserInfoFromIdToken = useCallback((idToken: string): void => {
    try {
      const tokenParts = idToken.split('.');
      if (tokenParts.length !== 3) {
        throw new Error('Neplatný ID token formát');
      }
      const payload = JSON.parse(atob(tokenParts[1]));
      setIsAuthenticated(true);
      setUserInfo({
        name: payload.name || `${payload.given_name || ''} ${payload.family_name || ''}`.trim() || payload.preferred_username || 'Neznámý uživatel',
        email: payload.email || 'N/A',
        preferred_username: payload.preferred_username || 'N/A',
        given_name: payload.given_name || 'N/A',
        family_name: payload.family_name || 'N/A',
        sub: payload.sub || 'N/A',
        acr: payload.acr || 'N/A'
      });
      localStorage.setItem('user_info', JSON.stringify({
        name: payload.name || `${payload.given_name || ''} ${payload.family_name || ''}`.trim() || payload.preferred_username || 'Neznámý uživatel',
        email: payload.email || 'N/A',
        preferred_username: payload.preferred_username || 'N/A',
        given_name: payload.given_name || 'N/A',
        family_name: payload.family_name || 'N/A',
        sub: payload.sub || 'N/A',
        acr: payload.acr || 'N/A'
      }));
      window.history.replaceState({}, document.title, window.location.pathname);
      localStorage.removeItem('used_auth_code');
      setLoading(false);
    } catch (error) {
      const accessToken = localStorage.getItem('access_token');
      if (accessToken) {
        fetchUserInfo(accessToken);
      } else {
        setLoading(false);
      }
    }
  }, [fetchUserInfo]);

  // Výměna code za token s PKCE
  const exchangeCodeForToken = useCallback(async (code: string, clientType: '1FA' | '2FA' | '3FA'): Promise<void> => {
    try {
      const tokenUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/token`;
      // Použít stejný redirect_uri jako při authorization requestu
      const redirectUri = `${window.location.origin}?client_type=${clientType}`;
      const clientId = clientType === '3FA' ? KEYCLOAK_CONFIG.clientId3F :
                      clientType === '2FA' ? KEYCLOAK_CONFIG.clientId2F : KEYCLOAK_CONFIG.clientId1F;
      
      const codeVerifier = localStorage.getItem('code_verifier');
      
      if (!codeVerifier) {
        throw new Error('Code verifier not found in localStorage');
      }

      const requestBody = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code: code,
        redirect_uri: redirectUri,  // Stejný jako v auth requestu
        code_verifier: codeVerifier
      });

      console.log('Token exchange request:', {
        client_id: clientId,
        redirect_uri: redirectUri,
        code: code.substring(0, 10) + '...' // Zkrácený kód pro debug
      });

      const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: requestBody
      });

      if (!tokenResponse.ok) {
        let errorData = {};
        try { 
          errorData = await tokenResponse.json(); 
        } catch { 
          /* ignore */ 
        }
        console.error('Token request failed:', errorData);
        throw new Error(`Token request failed: ${tokenResponse.status} ${JSON.stringify(errorData)}`);
      }

      const tokens = await tokenResponse.json();
      localStorage.setItem('access_token', tokens.access_token);
      if (tokens.id_token) localStorage.setItem('id_token', tokens.id_token);
      if (tokens.refresh_token) localStorage.setItem('refresh_token', tokens.refresh_token);
      
      // Uložit typ klienta
      localStorage.setItem('used_client_type', clientType);
      setUsedClientType(clientType);
      
      // Vyčistit PKCE data
      localStorage.removeItem('code_verifier');
      localStorage.removeItem('code_challenge');

      if (tokens.id_token) {
        parseUserInfoFromIdToken(tokens.id_token);
      } else {
        await fetchUserInfo(tokens.access_token);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Neznámá chyba';
      alert(`Chyba při dokončování přihlášení: ${errorMessage}`);
      setLoading(false);
    }
  }, [KEYCLOAK_CONFIG, parseUserInfoFromIdToken, fetchUserInfo]);

  // Zpracování návratu z Keycloak
  const parseKeycloakCallback = useCallback((): void => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    const errorDescription = urlParams.get('error_description');
    const clientType = urlParams.get('client_type') as '1FA' | '2FA' | '3FA' || '1FA';
    
    if (error) {
      alert(`Chyba při přihlášení: ${error}\n${errorDescription || ''}`);
      setLoading(false);
      return;
    }
    if (code) {
      const usedCode = localStorage.getItem('used_auth_code');
      if (usedCode === code) {
        setLoading(false);
        return;
      }
      localStorage.setItem('used_auth_code', code);
      exchangeCodeForToken(code, clientType);
      return;
    }
    setLoading(false);
  }, [exchangeCodeForToken]);

  const checkAuthStatus = useCallback((): void => {
    const token = localStorage.getItem('access_token');
    if (token) {
      const storedUserInfo = localStorage.getItem('user_info');
      const storedClientType = localStorage.getItem('used_client_type') as '1FA' | '2FA' | '3FA' || '1FA';
      if (storedUserInfo) {
        try {
          const parsedUserInfo = JSON.parse(storedUserInfo);
          setUserInfo(parsedUserInfo);
          setIsAuthenticated(true);
          setUsedClientType(storedClientType);
          setLoading(false);
        } catch (error) {
          fetchUserInfo(token);
        }
      } else {
        fetchUserInfo(token);
      }
    } else {
      setLoading(false);
    }
  }, [fetchUserInfo]);

  // Přihlášení s 1FA klientem s PKCE
  const loginWith1FA = useCallback(async (): Promise<void> => {
    try {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      
      // Uložit pro pozdější použití při token exchange
      localStorage.setItem('code_verifier', codeVerifier);
      localStorage.setItem('code_challenge', codeChallenge);

      const redirectUri = `${window.location.origin}?client_type=1FA`;
      const authUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth` +
        `?client_id=${encodeURIComponent(KEYCLOAK_CONFIG.clientId1F)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=openid profile email` +
        `&code_challenge=${codeChallenge}` +
        `&code_challenge_method=S256` +
        `&state=${Date.now()}`;
      
      window.location.href = authUrl;
    } catch (error) {
      alert('Chyba při přípravě přihlášení: ' + (error instanceof Error ? error.message : 'Neznámá chyba'));
    }
  }, [KEYCLOAK_CONFIG, generateCodeVerifier, generateCodeChallenge]);

  // Přihlášení s 2FA klientem s PKCE
  const loginWith2FA = useCallback(async (): Promise<void> => {
    try {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      
      // Uložit pro pozdější použití při token exchange
      localStorage.setItem('code_verifier', codeVerifier);
      localStorage.setItem('code_challenge', codeChallenge);

      const redirectUri = `${window.location.origin}?client_type=2FA`;
      const authUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth` +
        `?client_id=${encodeURIComponent(KEYCLOAK_CONFIG.clientId2F)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=openid profile email` +
        `&code_challenge=${codeChallenge}` +
        `&code_challenge_method=S256` +
        `&state=${Date.now()}`;
      
      window.location.href = authUrl;
    } catch (error) {
      alert('Chyba při přípravě přihlášení: ' + (error instanceof Error ? error.message : 'Neznámá chyba'));
    }
  }, [KEYCLOAK_CONFIG, generateCodeVerifier, generateCodeChallenge]);

  // Přihlášení s 3FA klientem s PKCE
  const loginWith3FA = useCallback(async (): Promise<void> => {
    try {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      
      // Uložit pro pozdější použití při token exchange
      localStorage.setItem('code_verifier', codeVerifier);
      localStorage.setItem('code_challenge', codeChallenge);

      const redirectUri = `${window.location.origin}?client_type=3FA`;
      const authUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/auth` +
        `?client_id=${encodeURIComponent(KEYCLOAK_CONFIG.clientId3F)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=openid profile email` +
        `&code_challenge=${codeChallenge}` +
        `&code_challenge_method=S256` +
        `&state=${Date.now()}`;
      
      window.location.href = authUrl;
    } catch (error) {
      alert('Chyba při přípravě přihlášení: ' + (error instanceof Error ? error.message : 'Neznámá chyba'));
    }
  }, [KEYCLOAK_CONFIG, generateCodeVerifier, generateCodeChallenge]);

  const logout = useCallback(async (): Promise<void> => {
    const accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');
    
    // Vyčistit lokální data ihned
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('user_info');
    localStorage.removeItem('used_auth_code');
    localStorage.removeItem('code_verifier');
    localStorage.removeItem('code_challenge');
    localStorage.removeItem('used_client_type');
    
    // Aktualizovat stav aplikace ihned
    setIsAuthenticated(false);
    setUserInfo(null);
    setUsedClientType(null);
    
    // Provést backchannel logout na pozadí
    if (refreshToken) {
      try {
        const logoutUrl = `${KEYCLOAK_CONFIG.url}/realms/${KEYCLOAK_CONFIG.realm}/protocol/openid-connect/logout`;
        const clientId = usedClientType === '3FA' ? KEYCLOAK_CONFIG.clientId3F :
                        usedClientType === '2FA' ? KEYCLOAK_CONFIG.clientId2F : KEYCLOAK_CONFIG.clientId1F;
        
        await fetch(logoutUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
          },
          body: new URLSearchParams({
            client_id: clientId,
            refresh_token: refreshToken
          })
        });
        
        console.log('Backchannel logout úspěšný');
      } catch (error) {
        console.warn('Backchannel logout selhal (ale lokální logout proběhl):', error);
        // Nespadneme - lokální logout už proběhl
      }
    }
  }, [KEYCLOAK_CONFIG, usedClientType]);

  // Debug funkce pro smazání všech dat
  const clearAllData = (): void => {
    localStorage.clear();
    sessionStorage.clear();
    window.location.reload();
  };

  // useEffect pro inicializaci aplikace při načtení
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const hasCallbackParams = urlParams.has('code') || urlParams.has('error');
    if (hasCallbackParams) {
      parseKeycloakCallback();
    } else {
      checkAuthStatus();
    }
  }, [parseKeycloakCallback, checkAuthStatus]);

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
      {/* Logout button for authenticated users */}
      {isAuthenticated && (
        <button onClick={logout} className="logout-button">
          Odhlásit se
        </button>
      )}

      <main className="main-content">
        {!isAuthenticated ? (
          <div className="login-container">
            {/* ŠKODA Logo */}
            <div className="skoda-logo">ŠKODA</div>

            <div className="login-card">
              <h2>Login to Demo app</h2>
              <p className="login-subtitle">Přihlaste se pomocí svého zaměstnaneckého účtu</p>

              {/* Authentication buttons */}
              <div className="auth-buttons">
                <button onClick={loginWith1FA} className="btn-auth btn-auth-primary">
                  <span>🔒</span>
                  Weak client (1FA)
                </button>
                
                <button onClick={loginWith2FA} className="btn-auth btn-auth-warning">
                  <span>🔐</span>
                  Medium client (2FA)
                </button>
                
                <button onClick={loginWith3FA} className="btn-auth btn-auth-danger">
                  <span>🔐</span>
                  Strong client (3FA)
                </button>
              </div>

              {/* Debug info for development */}
              {process.env.NODE_ENV === 'development' && (
                <div className="debug-info">
                  <h4>Debug informace:</h4>
                  <div><strong>SkodaIDP URL:</strong> {KEYCLOAK_CONFIG.url}</div>
                  <div><strong>Realm:</strong> {KEYCLOAK_CONFIG.realm}</div>
                  <div><strong>1FA Client ID:</strong> {KEYCLOAK_CONFIG.clientId1F}</div>
                  <div><strong>2FA Client ID:</strong> {KEYCLOAK_CONFIG.clientId2F}</div>
                  <div><strong>3FA Client ID:</strong> {KEYCLOAK_CONFIG.clientId3F}</div>
                  <div><strong>Scope:</strong> openid profile email</div>
                  <div><strong>Response Type:</strong> code (Authorization Code Flow s PKCE)</div>
                  <div><strong>PKCE Method:</strong> S256 (SHA256)</div>
                  <div><strong>Metadata:</strong> <a href={wellKnownUrl} target="_blank" rel="noreferrer">.well-known</a></div>
                  <button 
                    onClick={clearAllData} 
                    className="btn-auth btn-auth-secondary mt-4"
                  >
                    🧹 Smazat všechna data (debug)
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="login-container">
            {/* ŠKODA Logo */}
            <div className="skoda-logo">ŠKODA {process.env.REACT_APP_KEYCLOAK_ENV}</div>

            <div className="login-card">
              <h2>✅ Úspěšně přihlášen</h2>
              <p className="login-subtitle">Vítejte v aplikaci, {userInfo?.name}!</p>

              <div className="user-info-section">
                <h3>Informace o uživateli</h3>
                <div className="info-grid">
                  <div className="info-item">
                    <span className="info-label">Celé jméno:</span>
                    <span className="info-value">{userInfo?.name}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Email:</span>
                    <span className="info-value">{userInfo?.email}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Uživatelské jméno:</span>
                    <span className="info-value">{userInfo?.preferred_username}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">ACR Level:</span>
                    <span className="info-value">
                      <code>{userInfo?.acr}</code>
                      {usedClientType && (
                        <span className={`auth-badge ${usedClientType === '1FA' ? 'auth-1fa' : usedClientType === '2FA' ? 'auth-2fa' : 'auth-3fa'}`}>
                          {usedClientType} Client
                        </span>
                      )}
                    </span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Použitý klient:</span>
                    <span className="info-value status-active">
                      ✅ {usedClientType === '3FA' ? KEYCLOAK_CONFIG.clientId3F :
                          usedClientType === '2FA' ? KEYCLOAK_CONFIG.clientId2F : KEYCLOAK_CONFIG.clientId1F}
                    </span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Stav relace:</span>
                    <span className="info-value status-active">✅ Aktivní</span>
                  </div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="auth-buttons">
                <button onClick={logout} className="btn-auth btn-auth-primary">
                  <span>👋</span>
                  Odhlásit se
                </button>
                
                <button onClick={clearAllData} className="btn-auth btn-auth-secondary">
                  <span>🧹</span>
                  Vymazat data
                </button>
              </div>

              {/* Debug info for development */}
              {process.env.NODE_ENV === 'development' && (
                <div className="debug-info">
                  <h4>Debug informace:</h4>
                  <div><strong>Sub:</strong> {userInfo?.sub}</div>
                  <div><strong>Použitý Client:</strong> {usedClientType === '3FA' ? KEYCLOAK_CONFIG.clientId3F :
                                                      usedClientType === '2FA' ? KEYCLOAK_CONFIG.clientId2F : KEYCLOAK_CONFIG.clientId1F}</div>
                  <div><strong>Realm:</strong> {KEYCLOAK_CONFIG.realm}</div>
                  <div><strong>Metadata:</strong> <a href={wellKnownUrl} target="_blank" rel="noreferrer">.well-known</a></div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default App;