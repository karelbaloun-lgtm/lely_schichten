// netlify/functions/api.js
// Tenký obal: Netlify Blobs → createHandler (veškerá logika je v
// lib/api-core.mjs, kde je i otestovaná). ESM "export default" je nutné —
// automatické napojení Blobs funguje jen v tomhle formátu funkce. Store se
// vytváří až uvnitř požadavku (getStores se volá per request), ne při načtení
// modulu.
import { getStore } from '@netlify/blobs';
import { createHandler } from '../../lib/api-core.mjs';

const handler = createHandler(() => ({
  accounts: getStore({ name: 'accounts', consistency: 'strong' }),
  sessions: getStore({ name: 'sessions', consistency: 'strong' }),
  userdata: getStore({ name: 'userdata', consistency: 'strong' })
}));

export default (req) => handler(req);
