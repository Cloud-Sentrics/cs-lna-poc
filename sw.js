/* Throwaway SW v2: reliably serve the shell offline. Navigations = network-first, fall back to cached
 * index.html when WAN is down. Other same-origin = cache-first. Does not touch the WebTransport session. */
const CACHE='cs-wt-poc-v3';
const ASSETS=['./','./index.html','./sw.js'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)));});
self.addEventListener('activate',e=>{e.waitUntil((async()=>{await self.clients.claim();})());});
self.addEventListener('fetch',e=>{
  const req=e.request;
  if(req.mode==='navigate'){
    e.respondWith((async()=>{
      try{return await fetch(req);}
      catch(err){const c=await caches.open(CACHE);return (await c.match('./index.html'))||(await c.match('./'))||Response.error();}
    })());
    return;
  }
  if(new URL(req.url).origin===self.location.origin){
    e.respondWith(caches.match(req).then(r=>r||fetch(req).catch(()=>caches.match('./index.html'))));
  }
});
