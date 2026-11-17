/* মুহাসিব সার্ভার-মোড সার্ভিস ওয়ার্কার
   - অনুমোদিত ইউজারের অ্যাপ (HTML) ক্যাশে রাখে, যাতে সম্পূর্ণ অফলাইনেও চলে।
   - সার্ভার "login" পেজ পাঠালে (লগআউট/ব্লক/বাতিল) ক্যাশ করা অ্যাপ মুছে দেয়। */
const STATIC = 'muhasib-static-v1', APP = 'muhasib-app';
self.addEventListener('install', e => {
  e.waitUntil(caches.open(STATIC).then(c => c.addAll(['/login.html', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'])).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== STATIC && k !== APP).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const r = await fetch(req), kind = r.headers.get('X-Muh');
        if (kind === 'app') { const c = await caches.open(APP); await c.put('/__app', r.clone()); }
        else if (kind === 'login') { const c = await caches.open(APP); await c.delete('/__app'); }
        return r;
      } catch (err) {
        const a = await (await caches.open(APP)).match('/__app');
        return a || (await (await caches.open(STATIC)).match('/login.html')) || new Response('Offline', { status: 503 });
      }
    })());
    return;
  }
  e.respondWith(caches.match(req).then(m => m || fetch(req).then(r => { if (r.ok) { const cp = r.clone(); caches.open(STATIC).then(c => c.put(req, cp)); } return r; })));
});
