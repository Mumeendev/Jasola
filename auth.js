(function () {
    const token = sessionStorage.getItem('token');
    const page = window.location.pathname.split('/').pop();

    if (!token && page !== 'login.html' && page !== 'index.html' && page !== '') {
        window.location.replace('login.html');
        return;
    }

    const originalFetch = window.fetch.bind(window);
    let apiBasePromise;
    let portalConfigPromise;

    async function getConfiguredApiBase() {
        if (!portalConfigPromise) {
            portalConfigPromise = (async function () {
                if (window.location.protocol === 'file:') return null;

                const response = await originalFetch(
                    new URL('portal-config.json', document.baseURI),
                    { cache: 'no-store' }
                );
                if (response.status === 404) return null;
                if (!response.ok) {
                    throw new Error('Unable to load portal-config.json.');
                }

                const config = await response.json();
                if (!config || typeof config.apiBaseUrl !== 'string') {
                    throw new Error('portal-config.json must contain an apiBaseUrl string.');
                }
                if (!config.apiBaseUrl.trim()) return null;

                let apiUrl;
                try {
                    apiUrl = new URL(config.apiBaseUrl.trim());
                } catch (error) {
                    throw new Error('Set apiBaseUrl in portal-config.json to a valid backend URL.');
                }
                const isLocalHttp = apiUrl.protocol === 'http:' &&
                    ['localhost', '127.0.0.1'].includes(apiUrl.hostname);
                if ((apiUrl.protocol !== 'https:' && !isLocalHttp) ||
                    apiUrl.pathname !== '/' || apiUrl.search || apiUrl.hash) {
                    throw new Error('apiBaseUrl must be an HTTPS origin (or a local development URL).');
                }
                return apiUrl.origin;
            })();
        }
        return portalConfigPromise;
    }

    window.resolvePortalApiBase = function () {
        if (!apiBasePromise) {
            apiBasePromise = (async function () {
                const configuredBase = await getConfiguredApiBase();
                const candidates = [
                    configuredBase,
                    window.location.protocol === 'http:' || window.location.protocol === 'https:'
                        ? window.location.origin
                        : null,
                    'http://127.0.0.1:3000',
                    'http://localhost:3000'
                ].filter(Boolean);

                for (const candidate of [...new Set(candidates)]) {
                    try {
                        const response = await originalFetch(`${candidate}/api/health`, {
                            cache: 'no-store'
                        });
                        if (!response.ok) continue;
                        const health = await response.json();
                        if (health.ok === true && typeof health.database === 'string') return candidate;
                    } catch (error) {
                        // Try the next candidate.
                    }
                }
                throw new Error(
                    'Cannot reach the portal backend. On Render, deploy this repository as a Node Web Service using render.yaml. If the frontend is a separate Static Site, set apiBaseUrl in portal-config.json to the backend service URL.'
                );
            })();
        }
        return apiBasePromise;
    };

    window.fetch = async function (input, options) {
        const requestOptions = options || {};
        let url = typeof input === 'string' ? input : input.url;
        const headers = new Headers(typeof input === 'string' ? undefined : input.headers);
        new Headers(requestOptions.headers).forEach((value, key) => headers.set(key, value));
        if (url.includes('/api/')) {
            const apiBase = await window.resolvePortalApiBase();
            const parsedUrl = new URL(url, window.location.href);
            url = `${apiBase}${parsedUrl.pathname}${parsedUrl.search}${parsedUrl.hash}`;
        }
        if (token && url.includes('/api/') && !url.includes('/api/login')) {
            headers.set('Authorization', `Bearer ${token}`);
        }

        const response = await originalFetch(url, { ...requestOptions, headers });
        if (response.status === 401 && token && url.includes('/api/')) {
            sessionStorage.clear();
            window.location.replace('login.html');
        }
        return response;
    };
})();
