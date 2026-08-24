// netlify/functions/sync.js
// Speichert/liefert einen JSON-Datensatz {shifts, config, lastModified} pro
// 6-stelligem Sync-Code in Netlify Blobs. Kein CORS-Header nötig, da die App
// die Function immer same-origin aufruft (sie läuft auf derselben
// Netlify-Domain wie index.html).
//
// Klassisches CommonJS-Handler-Format (statt der neueren ESM
// "export default"-Variante) — maximal kompatibel, unabhängig davon, welche
// Functions-Laufzeitversion dieser Netlify-Account standardmäßig verwendet.
const { getStore } = require('@netlify/blobs');

// Reine Funktion (kein I/O) -> separat testbar, siehe sync.test.mjs.
function resolveSyncWrite(existing, incoming) {
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

function jsonResult(body, statusCode) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

exports.resolveSyncWrite = resolveSyncWrite;

exports.handler = async function (event) {
  const code = (event.queryStringParameters && event.queryStringParameters.code) || '';
  if (!/^\d{6}$/.test(code)) {
    return jsonResult({ error: 'invalid code' }, 400);
  }
  const store = getStore('syncs');

  if (event.httpMethod === 'GET') {
    const existing = await store.get(code, { type: 'json' });
    if (!existing) return jsonResult({ error: 'not found' }, 404);
    return jsonResult(existing, 200);
  }

  if (event.httpMethod === 'POST') {
    let incoming;
    try {
      incoming = JSON.parse(event.body || '{}');
    } catch (e) {
      return jsonResult({ error: 'invalid body' }, 400);
    }
    const existing = await store.get(code, { type: 'json' });
    const result = resolveSyncWrite(existing, incoming);
    if (result.conflict) return jsonResult(result.existing, 409);
    await store.setJSON(code, result.record);
    return jsonResult({ lastModified: result.record.lastModified }, 200);
  }

  return jsonResult({ error: 'method not allowed' }, 405);
};
