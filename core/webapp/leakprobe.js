// GeoTunnel leak-test probe. Read-only: it reports what the current page can
// observe and changes nothing. Evaluated in a container page (desktop: CDP
// Runtime.evaluate; mobile: WebView.evaluateJavascript / WKWebView
// callAsyncJavaScript). Resolves to the JSON shape of engine.BrowserObserved.
//
// __ECHO_URL__ is replaced with a CORS-enabled header echo endpoint that
// returns {"headers": {"Accept-Language": ...}} (default httpbin.org/headers).
(async () => {
  const out = {};
  try {
    out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    out.offsetMin = -new Date().getTimezoneOffset();
    out.dateString = new Date().toString();
    out.intlLocale = Intl.NumberFormat().resolvedOptions().locale;
  } catch (e) { out.timeError = String(e); }
  out.language = navigator.language;
  out.languages = Array.from(navigator.languages || []);

  try {
    const r = await fetch('__ECHO_URL__', { credentials: 'omit', cache: 'no-store' });
    const j = await r.json();
    const h = j.headers || j;
    for (const k of Object.keys(h)) {
      if (k.toLowerCase() === 'accept-language') out.acceptLanguage = String(h[k]);
    }
  } catch (e) { out.acceptLanguageError = String(e); }

  out.geo = await new Promise((resolve) => {
    if (!navigator.geolocation) return resolve({ error: 'geolocation API unavailable' });
    const timer = setTimeout(() => resolve({ error: 'timeout' }), 8000);
    navigator.geolocation.getCurrentPosition(
      (p) => { clearTimeout(timer); resolve({ lat: p.coords.latitude, lon: p.coords.longitude, accuracy: p.coords.accuracy }); },
      (e) => { clearTimeout(timer); resolve({ error: e.message || ('code ' + e.code) }); },
      { timeout: 7000, maximumAge: 0 });
  });

  out.webrtc = { available: typeof RTCPeerConnection === 'function', candidates: [] };
  if (out.webrtc.available) {
    try {
      out.webrtc.candidates = await new Promise((resolve) => {
        const found = new Set();
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        const finish = () => { try { pc.close(); } catch (e) {} resolve(Array.from(found)); };
        pc.onicecandidate = (e) => {
          if (!e.candidate) return finish();
          // candidate:<foundation> <component> <transport> <priority> <address> <port> typ <type> ...
          const f = e.candidate.candidate.split(' ');
          if (f.length > 4) found.add(f[4]);
        };
        pc.createDataChannel('probe');
        pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(finish);
        setTimeout(finish, 5000);
      });
    } catch (e) { out.webrtc.error = String(e); }
  }
  return out;
})()
