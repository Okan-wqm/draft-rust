# Mimari genel bakış

`rust-authentication`, B2C web, B2B SaaS ve native mobil uygulamaların ortak kullandığı, Rust ile yazılmış bir kimlik doğrulama sistemidir. Bu belge yapının özetidir; bağlayıcı kurallar [`contracts.md`](contracts.md), gereksinimler [`../spec/requirements.md`](../spec/requirements.md) içindedir.

## Katmanlar ve crate bağımlılık grafiği

```mermaid
flowchart BT
    core[authn-core<br/>tipler · hata · config · portlar · istek bağlamı]
    crypto[authn-crypto]
    store[authn-store]
    testkit[authn-testkit<br/><i>dev-dependency</i>]

    subgraph waveA[Dalga A — birbirine bağımlı değil, portlarla konuşur]
        password[authn-password]
        account[authn-account]
        mfa[authn-mfa]
        webauthn[authn-webauthn]
        org[authn-org]
        protect[authn-protect]
        audit[authn-audit]
        notify[authn-notify]
    end

    subgraph waveB[Dalga B — Dalga A'yı kullanır, birbirini kullanmaz]
        session[authn-session]
        oidc[authn-oidc-client]
        admin[authn-admin]
    end

    server[authn-server<br/>binary: rust-authentication]

    crypto --> core
    store --> crypto
    store --> core
    waveA --> store
    waveB --> waveA
    server --> waveB
    server --> waveA
    testkit -.-> core
```

- **Hexagonal yapı (ARC-02):** e-posta, SMS, CAPTCHA, saat, risk, DNS, HTTP, oturum kapatma/açma gibi tüm yan etkiler `authn-core::ports` içindeki trait'ler arkasındadır. Uygulamalar sahip modüllerdedir; testlerde `authn-testkit` sahteleri kullanılır.
- **Paralel geliştirme:** Aynı dalgadaki modüller birbirini derleme zamanında görmez; ortak sözleşme yalnızca `authn-core`'dur. Bu sayede her modül diğerleri bitmeden derlenir ve test edilir.
- **Uygulama durumu (ARC-03):** `AppState` yalnızca `authn-server`'dadır. Modüller `router<S>()` + `FromRef<S>` ile servislerini ister.
- **Modül kancaları:** Bir Dalga A modülü başka bir Dalga A modülünün verisine ihtiyaç duyduğunda kendi crate'inde küçük bir trait tanımlar; uygulamasını diğer modüllerin API'leriyle authn-server yazar (aşağıdaki şema, ayrıntı: [`contracts.md` §4 ve §15](contracts.md#15-sunucu-bağlama-tablosu)).

## Dalga A sonrası bağlama (server adaptörleri)

```mermaid
flowchart LR
    subgraph server[authn-server adaptörleri]
        lmi[LoginMethodInventory]
        prof[ProfileLookup]
        own[OrganizationOwnership]
        mps[MfaPolicySource]
        ams[AccountMethodsSource]
        pps[PasskeyPolicySource]
        aap[AuditAccessPolicy]
        bridge[OutboxHandler 'notification']
    end
    password[authn-password] -- kullanır --> lmi
    password -- kullanır --> prof
    account[authn-account] -- kullanır --> own
    mfa[authn-mfa] -- kullanır --> mps
    webauthn[authn-webauthn] -- kullanır --> ams
    webauthn -- kullanır --> pps
    audit[authn-audit] -- kullanır --> aap
    audit -- outbox işçisi --> bridge
    lmi -. passkey_count_in .-> webauthn
    prof -. profile_of .-> account
    own -. sole_owner_organizations .-> org[authn-org]
    mps -. policies_for_user .-> org
    mps -. passkey_count_in .-> webauthn
    ams -. MFA durumu .-> mfa
    pps -. org politikası .-> org
    aap -. authorize_from .-> org
    bridge -. NotificationDeliverer .-> notify[authn-notify]
```

Kancalar çağıranın bağlantısıyla (çoğu zaman `users` satırı `FOR UPDATE` kilitliyken) çalışır ve yalnızca o bağlantıdan okur; böylece "son giriş yöntemi" (PWD-11, PKY-04) ve "son MFA faktörü" (MFA-07) kuralları eşzamanlı silmelere karşı serileşir.

## İstek yaşam döngüsü

```mermaid
sequenceDiagram
    participant C as İstemci
    participant RC as request context (core)
    participant L as tracing · panik · timeout · limitler (server)
    participant P as host · başlıklar · CORS · rate limit (protect)
    participant S as kimlik doğrulama · CSRF (session)
    participant H as Modül handler'ı
    C->>RC: HTTP isteği
    RC->>RC: istek kimliği (UUIDv7), istemci IP (güvenilir proxy), dil, cihaz kimliği
    RC->>L: RequestContext extension
    L->>P: devam
    P->>S: devam
    S->>H: Principal extension
    H-->>RC: yanıt veya AuthError
    RC-->>C: hata zarfı yerelleştirildi + x-request-id
```

## Veri modeli (Faz 1)

```mermaid
erDiagram
    users ||--o| user_profiles : ""
    users ||--o| password_credentials : ""
    users ||--o{ sessions : ""
    sessions ||--o{ refresh_tokens : "token ailesi"
    users ||--o{ auth_challenges : "bekleyen giriş"
    users ||--o{ one_time_tokens : ""
    users ||--o{ mfa_factors : ""
    users ||--o{ recovery_codes : ""
    users ||--o{ trusted_devices : ""
    users ||--o| webauthn_user_handles : ""
    users ||--o{ webauthn_credentials : ""
    users ||--o{ identities : "sosyal / federe"
    users ||--o{ memberships : ""
    organizations ||--o{ memberships : ""
    roles ||--o{ memberships : ""
    organizations ||--o{ roles : "özel roller"
    roles ||--o{ role_permissions : ""
    organizations ||--o{ invitations : ""
    organizations ||--o{ org_domains : ""
    organizations ||--o| org_policies : ""
    organizations ||--o{ service_accounts : ""
    organizations ||--o{ api_keys : ""
    service_accounts ||--o{ api_keys : ""
    organizations ||--o{ webhook_endpoints : ""
    webhook_endpoints ||--o{ webhook_deliveries : ""
    users ||--o| audit_subjects : "takma ad"
    audit_events ||--o| audit_event_pii : "silinebilir PII"
    users ||--o{ consents : ""
    terms_versions ||--o{ consents : ""
    users ||--o{ email_reservations : "ayrılmış eski adres (ACC-07)"
    organizations ||--o{ org_auto_join_exclusions : ""
    users ||--o{ org_auto_join_exclusions : "otomatik katılım dışı (ORG-06)"
    users ||--o{ pending_registrations : "bekleyen kayıt (ADR 0002, 1201)"
    users ||--o{ admin_passkey_enrollments : "break-glass kayıt bağlantısı (K-11, 2201)"
    audit_events ||--o| admin_action_reasons : "gerekçe (ADM-08, 2200)"
    users ||--o{ admin_action_reasons : "hedef / admin"
    admin_action_reasons ||--o| admin_reason_restrictions : "yasal kısıtlama (K-39, 2201)"
    audit_events ||--o{ admin_reason_restrictions : "kısıtlama işlemi"
    users ||--o{ oauth_states : "bağlama akışı (session_id FK'sız, K-03, 2101)"
```

Bağımsız tablolar: `outbox` (transactional outbox), `audit_chain_head` / `audit_chain_checkpoints` (hash zinciri), `signing_keys` (JWT anahtar yaşam döngüsü), `data_encryption_keys` (**ayrılmış, kullanılmıyor**: CRY-08 zarfı kendi sarılmış DEK'ini taşır; ileride KMS önbelleği için, bkz. `0014`), `rate_limit_buckets` (UNLOGGED), `captcha_pow_challenges`, `webauthn_ceremonies` (oturuma **veya** break-glass bağlantı hash'ine bağlı, 1401), `account_deletions`, `known_devices` / `known_networks`, `login_soft_locks`, `oauth_token_revocations` (silinmiş/ayrılmış kimliklerin sağlayıcı token iptal kuyruğu; kullanıcı kimliği **yok**, 2102), `admin_operation_leases` (küme genelinde tek eşzamanlı pahalı admin işlemi, 2201). Wave 3B'nin eklediği admin/audit tabloları (`admin_approvals`, `admin_reason_restriction_periods`, `audit_subject_view_holds`; migration `2202`, `1701`) authn-admin / authn-audit README'lerinde.

Öne çıkan tasarım kararları:

| Konu | Karar |
|------|-------|
| Kimlikler | Uygulamada üretilen UUIDv7; dışa sıralı tamsayı açılmaz |
| Sırlar | Token/kod → 32 baytlık hash; geri dönüştürülebilir sırlar → zarf şifreli `*_ciphertext` |
| Tek kullanımlık token | `one_time_tokens` genel tablo; atomik `UPDATE … WHERE consumed_at IS NULL … RETURNING`; purpose kayıt defteri `authn_store::TokenPurpose` enum'u |
| Bakım işleri | `FOR UPDATE SKIP LOCKED` ile satır talebi (`UserRepository::claim_next`, outbox kiralama); çoklu instance güvenli (OPS-06) |
| Refresh rotasyonu | Oturum = token ailesi; aile başına tek canlı token (kısmi benzersiz indeks); yeniden kullanım → aile iptali |
| Kiracı izolasyonu | `org_id` her kapsamlı tabloda; rol ataması tetikleyicisi ve bileşik FK'lar |
| Audit | Ekleme-yalnızca tetikleyici, hash zinciri, kişisel veri zincir dışında (takma ad + silinebilir PII tablosu) |
| Hesap silme | `users` satırı silinir, kaskadlar tüm modül verisini temizler, audit'te yalnızca bağlantısız takma ad kalır |
| Faz 2 hazırlığı | `identities` (kurumsal SSO), `signing_keys` + JWKS (OIDC sağlayıcısı), `org_domains.sso_required`, `sessions.amr/acr` |

## Konfigürasyon ve çalışma

- Konfigürasyon: TOML + `AUTHN__` ortam değişkenleri, tipli ve doğrulanmış (fail-fast); örnek: [`config/example.toml`](../../config/example.toml).
- Binary alt komutları: `serve`, `migrate`, `check-config`, `create-admin` (`--passkey-link [--ttl]`), `admin-enrollment-link`, `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions`, `seal-apple-key`, `rotate-signing-key`, `rotate-kek` (`reencrypt`), `verify-audit-chain`, `migrate-legacy-hashes`.
- Veritabanı rolleri (OPS-10): uygulama rolü (`database.url`), bakım rolü (`database.maintenance_url`; audit saklama temizliği), şema sahibi (yalnızca `migrate`). Yetkiler: `SELECT authn_apply_least_privilege('<uygulama>', '<bakım>')` (migration `2900`); runbook [`docs/operations/least-privilege.md`](../operations/least-privilege.md).
- Yerel bağımlılıklar: `docker compose up -d` (PostgreSQL 16, Redis 7, Mailpit). Mailpit, depodaki sabit ve **herkese açık** geliştirme sertifikasıyla STARTTLS sunar (`config/dev-certs/`); örnek konfigürasyondaki yorumlu `notify.email.smtp.extra_ca_file` satırı açılınca sunucu ona güvenir. Bu ayar `development`/`test` dışında reddedilir.
- Sağlık: `GET /health/live`, `GET /health/ready` (veritabanı + migration durumu). Metrikler ayrı dinleyicide (`server.metrics_bind_addr`).

## Lisans politikası

Yalnızca ticari kullanımı kısıtlamayan izin verici lisanslar (LIC-01; `deny.toml`). Tek onaylı istisna `webauthn-rs` ailesi (MPL-2.0, crate bazında). Ayrıntılar ve gerekçeli advisory istisnaları için `contracts.md` §14.
