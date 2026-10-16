# Private Sajat Tesla integration — development only

Published Site v2: https://sajat-tesla.lbit-7431.chatgpt.site
Canonical MCP URL: https://sajat-tesla.lbit-7431.chatgpt.site/mcp
Plugin ID: plugin_asdk_app_sites_06c8f1d5ece481918ed1b77ede0aea7d
Live Tesla reads are DISABLED. Site v2 has gateway:null and no owner pin.

Added tested modules:
- oauth-bridge-broker.mjs: original v0.2.3 one-time encrypted PKCE exchange.
- one-time-ticket-store-pg.mjs: original durable atomic broker ticket adapter.
- site-link-flow.mjs: verified-owner start, official Tesla consent URL,
  atomic callback-state consumption, code exchange, read-scope validation,
  broker issuance, authenticated server-to-server redemption.
- site-owner-binding.mjs: official Sites identity helper binding, requiring an
  independently verified Site-scoped owner pin; no email or request-body fallback.

These modules are NOT yet imported by api/callback.js or lib/relay.js.
They intentionally do not alter existing relay operation or production secrets.
The pendingStore required by site-link-flow must use a separate durable
namespace/table from the broker tickets; never use the test-only Map adapter.
Tokens and pending envelopes must be encrypted using independent runtime keys.

Next runtime wiring requires:
1. Complete an authorized ChatGPT sign-in to the private Site and securely
   validate/pin its Site-scoped user ID. Browser sign-in permission was declined
   during this run; no alternate browser/session was used to bypass that refusal.
2. Provision preview-only relay broker storage and independent secrets.
3. Register an exact preview Tesla callback through the official developer
   configuration; do not modify the existing production callback unchecked.
4. Bind the controller into preview-only start/callback/redeem HTTP handlers,
   enforcing method, origin, body limits and server authentication.
   Existing relay rejects preview hosts, so review that restriction explicitly.
5. Request the owner's official Tesla consent, then run live integration tests.
6. Local disconnection deletes Site credentials; Tesla app-consent revocation
   is a distinct owner operation and has NOT been tested.

Tesla's documented confidential-client flow uses client_secret at the relay.
PKCE is enforced for the relay-to-Site one-time ticket exchange. No undocumented
Tesla PKCE support is assumed. Reference:
https://developer.tesla.com/docs/fleet-api/authentication/third-party-tokens

No merge, production Vercel change, Tesla secret read/change, vehicle control,
or successful live Tesla status test occurred in this run.
