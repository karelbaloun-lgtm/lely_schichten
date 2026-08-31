// Service Worker für Lely Schichten — Netzwerk zuerst (aktuelle Version, wenn
// online), sonst aus dem Cache (funktioniert offline nach dem ersten Besuch).
const CACHE_VERSION = 'lely-schichten-v5';
const CORE_FILES = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-512-maskable.png'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then(function (cache) { return cache.addAll(CORE_FILES); })
    // Kein automatisches skipWaiting() mehr: die neue Version soll erst
    // aktiv werden, wenn die App das per Update-Banner vom Nutzer bestätigt
    // hat (siehe 'message'-Listener unten) — sonst wird eine offene Eingabe
    // mitten in der Nutzung durch den Reload unter dem Nutzer weggerissen.
    // Ohne dieses Banner blieb die App nach jedem Deploy auf altem
    // gecachtem JS hängen, bis der Nutzer manuell den App-Speicher löschte
    // (und dabei seine lokalen Daten verlor) — das soll ab jetzt nicht mehr
    // passieren.
  );
});
self.addEventListener('message', function (event) {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(keys.filter(function (k) { return k !== CACHE_VERSION; }).map(function (k) { return caches.delete(k); }));
      })
      .then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request).then(function (response) {
      const copy = response.clone();
      caches.open(CACHE_VERSION).then(function (cache) { cache.put(event.request, copy); });
      return response;
    }).catch(function () {
      return caches.match(event.request).then(function (cached) {
        return cached || caches.match('./index.html');
      });
    })
  );
});
