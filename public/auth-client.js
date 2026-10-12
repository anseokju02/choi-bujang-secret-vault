
const listeners = new Set();
let session = null;
let refreshTimer = null;
let refreshInFlight = null;
let revision = 0;

async function authRequest(method, body) {
  const response = await fetch('/api/auth', {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: body === undefined
      ? {}
      : { 'Content-Type': 'application/json' },
    body: body === undefined
      ? undefined
      : JSON.stringify(body)
  });

  if (response.status === 204) return null;

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data.error || 'AUTH_REQUEST_FAILED');
    error.status = response.status;
    throw error;
  }

  return data;
}

function updateSession(data, event) {
  clearTimeout(refreshTimer);
  refreshTimer = null;

  session = data?.accessToken
    ? {
        access_token: data.accessToken,
        expires_at: data.expiresAt,
        user: { email: data.user?.email ?? null }
      }
    : null;

  for (const callback of listeners) {
    try {
      callback(event, session);
    } catch {
      // 다른 이벤트 처리에 영향을 주지 않음
    }
  }

  if (session && Number.isFinite(session.expires_at)) {
    const delay = Math.max(
      10000,
      session.expires_at * 1000 - Date.now() - 90000
    );

    refreshTimer = setTimeout(() => {
      void refreshSession(false);
    }, delay);
  }
}

async function refreshSession(initial) {
  if (refreshInFlight) return refreshInFlight;

  const requestedRevision = revision;

  refreshInFlight = authRequest('GET')
    .then(data => {
      if (requestedRevision === revision) {
        updateSession(
          data,
          initial ? 'INITIAL_SESSION' : 'TOKEN_REFRESHED'
        );
      }
    })
    .catch(error => {
      if (requestedRevision !== revision) return;

      if (initial || error.status === 401) {
        updateSession(
          null,
          initial ? 'INITIAL_SESSION' : 'SIGNED_OUT'
        );
      } else {
        refreshTimer = setTimeout(() => {
          void refreshSession(false);
        }, 30000);
      }
    })
    .finally(() => {
      refreshInFlight = null;
    });

  return refreshInFlight;
}

export const supabase = {
  auth: {
    async signInWithPassword({ email, password }) {
      if (refreshInFlight) await refreshInFlight;
      revision++;

      try {
        const data = await authRequest('POST', {
          email,
          password
        });

        updateSession(data, 'SIGNED_IN');

        return {
          data: { session },
          error: null
        };
      } catch (error) {
        return {
          data: { session: null },
          error
        };
      }
    },

    async signOut() {
      if (refreshInFlight) await refreshInFlight;
      revision++;

      try {
        await authRequest('DELETE');
        updateSession(null, 'SIGNED_OUT');

        return { error: null };
      } catch (error) {
        return { error };
      }
    },

    onAuthStateChange(callback) {
      listeners.add(callback);

      if (listeners.size === 1) {
        void refreshSession(true);
      } else {
        callback('INITIAL_SESSION', session);
      }

      return {
        data: {
          subscription: {
            unsubscribe: () => listeners.delete(callback)
          }
        }
      };
    }
  }
};
