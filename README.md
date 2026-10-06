# Saját Tesla – EU Fleet API

Előkészített integráció a tesla-oauth-relay.vercel.app domainhez. Csak olvasási scope-ok: openid, offline_access, vehicle_device_data, vehicle_location. A tokeneket a szerver AES-256-GCM titkosítással tárolja Secure, HttpOnly, hosthoz kötött cookie-kban; a JavaScript nem kap nyers tokent. Nincs külső adatbázis. A böngésző munkamenete és a védőkulcs szükséges az adatok olvasásához. A kijelentkezés törli a helyi cookie-kat; a Tesla-fiókban az alkalmazás engedélyét külön lehet visszavonni.

## Beállítás

1. A kódot töltsd fel a bodilevente/Tesla-oauth-relay repositoryba. A Vercel meglévő main-ág kapcsolata deployolja.
2. Production környezeti változók: TESLA_CLIENT_ID és TESLA_CLIENT_SECRET (már léteznek), valamint TESLA_SETUP_KEY (legalább 32 kriptográfiailag véletlen karakter, Secret típussal). A védőkulcsot ne tedd a repositoryba vagy chatbe. Beállítás után új deploy szükséges.
3. Tesla Developer allowed origin: https://tesla-oauth-relay.vercel.app. Engedélyezett redirect URI: https://tesla-oauth-relay.vercel.app/api/callback. Ellenőrizd, hogy az app támogatja az authorization_code és client_credentials folyamatokat, valamint a két járműadat-scope-ot.
4. A saját weboldalon jelentkezz be a védőkulccsal. Indítsd el az EU partner-regisztráció ellenőrzését, majd a Tesla-fiók összekötését. A Tesla jóváhagyását a tulajdonos végzi.
5. Kérd le az autólistát, válaszd ki a Model Y-t, majd egyszer kérd le az állapotot. Ha alszik, a Tesla mobilappban ébreszd fel.

## Ellenőrzés és korlátok

Helyi ellenőrzés: node --test (7 biztonsági teszt). Valódi deploy, partner-token, partner-regisztráció, OAuth és autóadat-lekérés még ellenőrizendő. Az alkalmazás szándékosan nem működik a production domaintől eltérő hoston. A titkosított cookie-khoz mindkét szerveroldali titok kell; valamelyik módosításakor újra be kell lépni. Párhuzamos tokenfrissítést kerüld: egy böngészőlapon használd. Az admin munkamenet 8 órás. Automatikus lekérdezés nincs. Az AI ebben a bejelentkezett böngészőben használhatja a felületet; önálló ChatGPT/Codex connector nincs telepítve.

Hivatalos források:
- https://developer.tesla.com/docs/fleet-api/authentication/partner-tokens
- https://developer.tesla.com/docs/fleet-api/authentication/third-party-tokens
- https://developer.tesla.com/docs/fleet-api/endpoints/partner-endpoints
- https://developer.tesla.com/docs/fleet-api/endpoints/vehicle-endpoints
