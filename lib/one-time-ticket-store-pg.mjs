/**
 * Distributed, atomic, TTL-bound ticket store for the Site's pending OAuth
 * states and the relay's short-lived link codes. The values are ENCRYPTED by
 * the caller. Never persist raw bridge credentials or raw PKCE verifiers here.
 *
 * Requires a restricted PostgreSQL-compatible pool.query(sql, params).
 */
export class TeslaTicketStoreError extends Error {
  constructor(code) {super(code);this.name='TeslaTicketStoreError';this.code=code;}
}
const fail=c=>{throw new TeslaTicketStoreError(c)};
const validHash=h=>typeof h==='string' && /^[0-9a-f]{64}$/.test(h);
const validSealed=s=>typeof s==='string' && /^[A-Za-z0-9_-]{40,30000}$/.test(s);

export function createPgOneTimeTicketStore({pool, namespace}) {
  if (!pool || typeof pool.query!=='function') fail('ticket_database_unavailable');
  if (!['relay-link','site-pkce'].includes(namespace)) fail('invalid_ticket_namespace');
  return Object.freeze({
    async put(hash, envelope, ttlSeconds) {
      if (!validHash(hash) || !validSealed(envelope?.sealed) ||
          !Number.isInteger(ttlSeconds) || ttlSeconds<30 || ttlSeconds>600) {
        fail('invalid_ticket');
      }
      try {
        const result=await pool.query(
          `INSERT INTO tesla_one_time_tickets (namespace, ticket_hash, sealed_payload, expires_at)
           VALUES ($1,$2,$3,CURRENT_TIMESTAMP + $4 * INTERVAL '1 second')
           ON CONFLICT (namespace,ticket_hash) DO NOTHING`,
          [namespace,hash,envelope.sealed,ttlSeconds]);
        if (result.rowCount!==1) fail('ticket_conflict');
      } catch(e) {
        if(e instanceof TeslaTicketStoreError) throw e;
        fail('ticket_database_unavailable');
      }
    },
    async take(hash) {
      if (!validHash(hash)) fail('invalid_ticket');
      try {
        // DELETE RETURNING is a single atomic operation across replicas.
        const result=await pool.query(
          `DELETE FROM tesla_one_time_tickets
           WHERE namespace=$1 AND ticket_hash=$2 AND expires_at>CURRENT_TIMESTAMP
           RETURNING sealed_payload`,
          [namespace,hash]);
        return result.rows?.[0] ? {sealed:result.rows[0].sealed_payload} : null;
      } catch {fail('ticket_database_unavailable');}
    }
  });
}
