/* Throwaway SW: cache the WebTransport shell so it cold-loads with WAN down. Does not intercept the
 * WebTransport session (that's not a fetch); only caches the shell's own origin assets. */
const CACHE='cs-wt-poc-v1';
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['./','./index.html','./sw.js'])));});
self.addEventListener('activate',e=>{e.waitUntil(self.clients.claim());});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url); if(u.origin===self.location.origin){e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)));}});
