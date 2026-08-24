// netlify/functions/sync.js
// Speichert/liefert einen JSON-Datensatz {shifts, config, lastModified} pro
// 6-stelligem Sync-Code in Netlify Blobs. Kein CORS-Header nötig, da die App
// die Function immer same-origin aufruft (sie läuft auf derselben
// Netlify-Domain wie index.html).
//
// Modernes ESM-"export default"-Format: Netlify Blobs' automatische
// Zero-Config-Anbindung (getStore(name) ohne manuelle siteID/token) ist an
// diese Function-Laufzeit gekoppelt — im klassischen CommonJS-Handler-Format
// (exports.handler) schlug getStore() mit "environment has not been
// configured to use Netlify Blobs" fehl, obwohl die Function selbst lief.
//
// consistency:'strong' ist nötig: der Standardmodus (eventual) lieferte in
// Tests direkt nach einem Schreibvorgang noch mehrere Sekunden lang "not
// found" zurück — für den Pairing-Ablauf (Gerät A schreibt, Gerät B liest
// kurz danach denselben Code) inakzeptabel.
import { getStore } from '@netlify/blobs';

// Reine Funktion (kein I/O) -> separat testbar, siehe tests/sync.test.mjs.
export function resolveSyncWrite(existing, incoming) {
  if (existing && existing.lastModified !== incoming.baseLastModified) {
    return { conflict: true, existing };
  }
  return {
    conflict: false,
    record: {
      shifts: incoming.shifts,
      config: incoming.config,
      lastModified: Date.now()
    }
  };
}

function jsonResponse(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

export default async (req) => {
  const url = new URL(req.url);
  const code = url.searchParams.get('code') || '';
  if (!/^\d{6}$/.test(code)) {
    return jsonResponse({ error: 'invalid code' }, 400);
  }
  const store = getStore({ name: 'syncs', consistency: 'strong' });

  if (req.method === 'GET') {
    const existing = await store.get(code, { type: 'json' });
    if (!existing) return jsonResponse({ error: 'not found' }, 404);
    return jsonResponse(existing, 200);
  }

  if (req.method === 'POST') {
    let incoming;
    try {
      incoming = await req.json();
    } catch (e) {
      return jsonResponse({ error: 'invalid body' }, 400);
    }
    const existing = await store.get(code, { type: 'json' });
    const result = resolveSyncWrite(existing, incoming);
    if (result.conflict) return jsonResponse(result.existing, 409);
    await store.setJSON(code, result.record);
    return jsonResponse({ lastModified: result.record.lastModified }, 200);
  }

  return jsonResponse({ error: 'method not allowed' }, 405);
};
