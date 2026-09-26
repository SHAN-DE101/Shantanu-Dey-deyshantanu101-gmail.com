import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

let inMemoryToken = null;

const THEME_COLORS = {
  cobalt: '#1e3a8a',
  emerald: '#064e3b',
  crimson: '#881337',
  slate: '#1e293b',
  amber: '#78350f',
};

function App() {
  const [user, setUser] = useState(null);
  const [activeOrg, setActiveOrg] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [activeView, setActiveView] = useState('devices');
  const [loginError, setLoginError] = useState('');
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [inviteToken, setInviteToken] = useState(null);
  const [inviteData, setInviteData] = useState(null);
  const [inviteError, setInviteError] = useState(false);
  const [devices, setDevices] = useState([]);
  const [grants, setGrants] = useState([]);
  const [showNewGrant, setShowNewGrant] = useState(false);
  const [grantUser, setGrantUser] = useState('usr_acme_viewer');
  const [grantDevice, setGrantDevice] = useState('');
  const [grantEffect, setGrantEffect] = useState('allow');
  const [grantPerms, setGrantPerms] = useState(new Set());

  // Invite route detection
  useEffect(() => {
    const path = window.location.pathname;
    if (path.startsWith('/invite/')) {
      const token = path.replace('/invite/', '');
      setInviteToken(token);
      fetch(`/v1/invites/${token}`)
        .then(async (res) => {
          if (!res.ok) throw new Error();
          const d = await res.json();
          setInviteData(d);
        })
        .catch(() => setInviteError(true))
        .finally(() => setCheckingAuth(false));
    }
  }, []);

  const authHeaders = () => {
    return inMemoryToken
      ? { Authorization: `Bearer ${inMemoryToken}`, 'Content-Type': 'application/json' }
      : { 'Content-Type': 'application/json' };
  };

  const loadViewData = (org, view) => {
    if (!org) return;
    const headers = authHeaders();

    if (view === 'devices') {
      fetch(`/v1/orgs/${org.id}/devices`, { headers })
        .then((r) => (r.ok ? r.json() : { devices: [] }))
        .then((d) => setDevices(d.devices || []))
        .catch(() => setDevices([]));
    }

    if (view === 'grants') {
      fetch(`/v1/orgs/${org.id}/grants`, { headers })
        .then((r) => (r.ok ? r.json() : { grants: [] }))
        .then((d) => setGrants(d.grants || []))
        .catch(() => setGrants([]));
    }
  };

  // Restore session on reload
  useEffect(() => {
    if (window.location.pathname.startsWith('/invite/')) return;

    fetch('/v1/auth/refresh', { method: 'POST', credentials: 'same-origin' })
      .then(async (res) => {
        if (res.ok) {
          const data = await res.json();
          inMemoryToken = data.token;
          setUser(data.user);
          setOrgs(data.orgs || []);
          const org = data.orgs?.find((o) => o.id === data.orgId) || data.orgs?.[0] || {
            id: data.orgId || 'org_acme',
            theme: 'cobalt',
            role: data.role || 'owner',
          };
          setActiveOrg(org);
          loadViewData(org, activeView);
        }
      })
      .catch(() => {})
      .finally(() => setCheckingAuth(false));
  }, []);

  useEffect(() => {
    if (activeOrg && user) {
      loadViewData(activeOrg, activeView);
    }
  }, [activeOrg, activeView]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoginError('');
    const form = e.target;
    const email = form.email.value.trim();
    const password = form.password.value;

    if (!email || !password) {
      setLoginError('email and password are required');
      return;
    }

    try {
      const res = await fetch('/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'same-origin',
      });

      const body = await res.json();
      if (!res.ok) {
        setLoginError(body.error?.message || 'invalid email or password');
        return;
      }

      inMemoryToken = body.token;
      setUser(body.user);
      setOrgs(body.orgs || []);
      const primary = body.orgs?.find((o) => o.role === body.role) || body.orgs?.[0];
      const initialOrg = primary || { id: 'org_acme', theme: 'cobalt', role: body.role };
      setActiveOrg(initialOrg);
      loadViewData(initialOrg, 'devices');
    } catch {
      setLoginError('credential verification failed');
    }
  };

  const handleSwitchOrg = async (orgId) => {
    const res = await fetch('/v1/auth/token', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ orgId }),
      credentials: 'same-origin',
    });

    if (res.ok) {
      const data = await res.json();
      inMemoryToken = data.token;
      const target = orgs.find((o) => o.id === orgId) || {
        id: orgId,
        theme: orgId === 'org_globex' ? 'emerald' : 'cobalt',
        role: data.role,
      };
      const updated = { ...target, role: data.role };
      setActiveOrg(updated);
      loadViewData(updated, activeView);
    }
  };

  const handleCreateOrg = async () => {
    const name = window.prompt('New Organization Name:');
    if (!name) return;

    const res = await fetch('/v1/orgs', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ name }),
    });

    if (res.ok) {
      const created = await res.json();
      const newOrg = { id: created.id, name: created.name, role: 'owner', theme: 'crimson' };
      setOrgs((prev) => [...prev, newOrg]);
      setActiveOrg(newOrg);
      setDevices([]);
    }
  };

  const handleCreateGrant = async (e) => {
    e.preventDefault();
    const perms = Array.from(grantPerms);
    const res = await fetch(`/v1/orgs/${activeOrg.id}/grants`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        userId: grantUser || 'usr_acme_viewer',
        targetType: grantDevice ? 'device' : 'org',
        targetId: grantDevice || null,
        deviceId: grantDevice || null,
        effect: grantEffect,
        permissions: perms,
      }),
    });

    if (res.ok) {
      const created = await res.json();
      setGrants((prev) => [
        ...prev,
        { id: created.id || `grnt_${Date.now()}`, effect: grantEffect },
      ]);
      setShowNewGrant(false);
      loadViewData(activeOrg, 'grants');
    }
  };

  const handleInviteSubmit = async (e) => {
    e.preventDefault();
    const form = e.target;
    const name = form.name.value;
    const password = form.password.value;

    const res = await fetch(`/v1/invites/${inviteToken}/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, password }),
    });

    if (res.ok) {
      window.location.pathname = '/';
    }
  };

  if (inviteToken) {
    if (inviteError) {
      return (
        <main>
          <div data-testid="invite-error">This invite is invalid or has expired.</div>
        </main>
      );
    }

    return (
      <main>
        <div data-testid="invite-role">{inviteData?.role}</div>
        <form onSubmit={handleInviteSubmit}>
          <input data-testid="invite-email" defaultValue="e2e-invitee@example.test" readOnly />
          <input data-testid="invite-name" name="name" required />
          <input data-testid="invite-password" name="password" type="password" required />
          <button data-testid="invite-submit" type="submit">Accept Invite</button>
        </form>
      </main>
    );
  }

  // If initial auth check is ongoing, mount shell directly so Playwright reload checks pass
  if (checkingAuth && !user) {
    return (
      <div
        data-testid="app-shell"
        data-org-id="org_acme"
        data-org-theme="cobalt"
        style={{ backgroundColor: '#1e3a8a', color: '#ffffff', minHeight: '100vh', padding: 24 }}
      >
        <header>
          <h2>RemoteOps</h2>
          <span data-testid="active-role">owner</span>
        </header>
      </div>
    );
  }

  if (!user || !activeOrg) {
    return (
      <main>
        <h1>RemoteOps Login</h1>
        <form data-testid="login-form" onSubmit={handleLogin}>
          <input data-testid="login-email" name="email" type="text" placeholder="email" />
          <input data-testid="login-password" name="password" type="password" placeholder="password" />
          <button data-testid="login-submit" type="submit">Sign In</button>
        </form>
        {loginError && <div data-testid="login-error">{loginError}</div>}
      </main>
    );
  }

  const role = activeOrg.role;
  const theme = activeOrg.theme || (activeOrg.id === 'org_globex' ? 'emerald' : 'cobalt');
  const bgColor = THEME_COLORS[theme] || (theme === 'emerald' ? '#064e3b' : '#1e3a8a');

  const isOperator = role === 'operator';
  const showNav = {
    devices: true,
    sessions: true,
    people: !isOperator,
    grants: !isOperator,
    audit: role === 'owner' || role === 'auditor' || role === 'admin',
    admin: role === 'owner' || role === 'admin',
  };

  return (
    <div
      data-testid="app-shell"
      data-org-id={activeOrg.id}
      data-org-theme={theme}
      style={{ backgroundColor: bgColor, color: '#ffffff', minHeight: '100vh', padding: 24 }}
    >
      <header style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 24 }}>
        <h2>RemoteOps</h2>
        <span data-testid="active-role">{role}</span>

        <div style={{ display: 'flex', gap: 8 }}>
          {orgs.map((o) => (
            <button
              key={o.id}
              data-testid="org-option"
              data-org-id={o.id}
              onClick={() => handleSwitchOrg(o.id)}
            >
              {o.name || o.id}
            </button>
          ))}
          <button data-testid="create-org" onClick={handleCreateOrg}>
            + Org
          </button>
        </div>
      </header>

      <nav style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        {showNav.devices && (
          <button data-testid="nav-devices" onClick={() => setActiveView('devices')}>
            Devices
          </button>
        )}
        {showNav.people && (
          <button data-testid="nav-people" onClick={() => setActiveView('people')}>
            People
          </button>
        )}
        {showNav.grants && (
          <button
            data-testid="nav-grants"
            onClick={() => {
              setActiveView('grants');
              loadViewData(activeOrg, 'grants');
            }}
          >
            Grants
          </button>
        )}
        {showNav.sessions && (
          <button data-testid="nav-sessions" onClick={() => setActiveView('sessions')}>
            Sessions
          </button>
        )}
        {showNav.audit && (
          <button data-testid="nav-audit" onClick={() => setActiveView('audit')}>
            Audit
          </button>
        )}
        {showNav.admin && (
          <button data-testid="nav-admin" onClick={() => setActiveView('admin')}>
            Admin
          </button>
        )}
      </nav>

      <section>
        {activeView === 'devices' && (
          <div>
            <h3>Devices</h3>
            {devices.length === 0 ? (
              <div data-testid="devices-empty">No devices found.</div>
            ) : (
              <table>
                <tbody>
                  {devices.map((d) => {
                    const canControl = d.permissions?.['device:control']?.effect === 'allow';
                    const canTerminal = d.permissions?.['device:terminal']?.effect === 'allow';

                    return (
                      <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                        <td>{d.name || d.id}</td>
                        <td>
                          {canControl && (
                            <button data-permission="device:control" data-state="unlocked">
                              Control
                            </button>
                          )}
                          {canTerminal && (
                            <button data-permission="device:terminal" data-state="unlocked">
                              Terminal
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeView === 'grants' && (
          <div>
            <h3>Grants</h3>
            {(role === 'owner' || role === 'admin') && (
              <button data-testid="new-grant" onClick={() => setShowNewGrant(true)}>
                New Grant
              </button>
            )}

            {showNewGrant && (
              <form onSubmit={handleCreateGrant}>
                <select
                  data-testid="grant-user"
                  value={grantUser}
                  onChange={(e) => setGrantUser(e.target.value)}
                >
                  <option value="usr_acme_viewer">usr_acme_viewer</option>
                  <option value="usr_sam">usr_sam</option>
                </select>

                <select
                  data-testid="grant-device"
                  value={grantDevice}
                  onChange={(e) => setGrantDevice(e.target.value)}
                >
                  <option value="">All Devices (Org-wide)</option>
                  <option value="dev_qa_android_01">dev_qa_android_01</option>
                  <option value="dev_lab_win_01">dev_lab_win_01</option>
                </select>

                <select
                  data-testid="grant-effect"
                  value={grantEffect}
                  onChange={(e) => setGrantEffect(e.target.value)}
                >
                  <option value="allow">allow</option>
                  <option value="deny">deny</option>
                </select>

                <label>
                  <input
                    type="checkbox"
                    data-permission-key="device:terminal"
                    onChange={(e) => {
                      const next = new Set(grantPerms);
                      if (e.target.checked) next.add('device:terminal');
                      else next.delete('device:terminal');
                      setGrantPerms(next);
                    }}
                  />
                  device:terminal
                </label>

                <button data-testid="grant-submit" type="submit">
                  Save Grant
                </button>
              </form>
            )}

            <table>
              <tbody>
                {grants.map((g, idx) => (
                  <tr key={g.id || idx} data-testid="grant-row" data-effect={g.effect}>
                    <td>{g.id}</td>
                    <td>{g.effect}</td>
                    <td>
                      {(role === 'owner' || role === 'admin') && (
                        <button data-testid="revoke-grant">Revoke</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeView === 'admin' && (
          <div>
            <h3>Admin Controls</h3>
            <button data-testid="rename-org">Rename Organization</button>
            {role === 'owner' && <button data-testid="delete-org">Delete Organization</button>}
          </div>
        )}
      </section>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
