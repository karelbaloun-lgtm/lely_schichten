// netlify/functions/sync.test.mjs
// Reiner Logik-Test für resolveSyncWrite — läuft ohne Netlify, ohne Netzwerk,
// mit einfachem node:assert (kein Test-Framework nötig für eine einzelne
// Funktion). Aufruf: node netlify/functions/sync.test.mjs
import assert from 'node:assert/strict';
import { resolveSyncWrite } from './sync.js';

// 1) Erster Push zu einem neuen Code: kein bestehender Eintrag -> kein Konflikt.
{
  const result = resolveSyncWrite(null, { shifts: [1], config: { lastName: 'Baloun' }, baseLastModified: null });
  assert.equal(result.conflict, false);
  assert.deepEqual(result.record.shifts, [1]);
  assert.deepEqual(result.record.config, { lastName: 'Baloun' });
  assert.equal(typeof result.record.lastModified, 'number');
}

// 2) Push mit passendem baseLastModified -> kein Konflikt, neuer Stand wird übernommen.
{
  const existing = { shifts: [1], config: {}, lastModified: 1000 };
  const result = resolveSyncWrite(existing, { shifts: [1, 2], config: {}, baseLastModified: 1000 });
  assert.equal(result.conflict, false);
  assert.deepEqual(result.record.shifts, [1, 2]);
  assert.ok(result.record.lastModified >= 1000);
}

// 3) Push mit veraltetem baseLastModified -> Konflikt, bestehende Daten werden zurückgegeben.
{
  const existing = { shifts: [1, 2], config: {}, lastModified: 2000 };
  const result = resolveSyncWrite(existing, { shifts: [9], config: {}, baseLastModified: 1000 });
  assert.equal(result.conflict, true);
  assert.deepEqual(result.existing, existing);
}

// 4) baseLastModified=null, obwohl schon Daten existieren (z.B. Code-Kollision beim
//    Erzeugen) -> Konflikt, kein stilles Überschreiben.
{
  const existing = { shifts: [1], config: {}, lastModified: 500 };
  const result = resolveSyncWrite(existing, { shifts: [9], config: {}, baseLastModified: null });
  assert.equal(result.conflict, true);
}

console.log('Alle sync.js Tests bestanden ✓');
