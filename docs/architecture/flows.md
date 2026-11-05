# Akış diyagramları (DOC-02)

Başlıca kimlik doğrulama akışlarının sıra diyagramları. Her diyagram kodla doğrulanmıştır (dosya yolları her bölümün başında). Bileşen ve veri modeli diyagramları: [`overview.md`](overview.md). İstek/yanıt ayrıntıları: [`docs/api/`](../api/README.md).

Kısaltmalar: **T** = tarayıcı / istemci, **S** = `rust-authentication` sunucusu, **DB** = PostgreSQL, **Q** = outbox (aynı transaction'da yazılır, arka plan işçisi teslim eder).

## 1. Kayıt ve e-posta doğrulama (ACC-01, ACC-02, ACC-04, ADR 0002)

Kaynak: `crates/authn-account/src/service/{signup,registration,verification}.rs`, ADR [0002](adr/0002-registration-pre-hijacking.md).

```mermaid
sequenceDiagram
    autonumber
    participant T as Tarayıcı
    participant S as Sunucu
    participant DB as PostgreSQL
    participant Q as Outbox / e-posta

    T->>S: POST /v1/signup {email, password, …}
    Note over S: Senkron kısım her adres için aynı:<br/>IP sınırı → CAPTCHA politikası → adres sözdizimi →<br/>tek kullanımlık domain → şifre politikası → Argon2id hash
    S->>S: kayıt tutamacı üret (256 bit, adresten bağımsız)
    S-->>T: 202 {status: "accepted", registration}<br/>Set-Cookie: __Host-authn_registration (Strict)
    Note over S,DB: Arka plan işi (adres başına advisory lock)
    alt Yeni adres
        S->>DB: users (pending_verification, kimlik bilgisi YOK)<br/>pending_registrations (şifre hash'i, profil, onaylar,<br/>link/kod/tutamaç hash'leri)
        S->>Q: doğrulama e-postası (link + 6 haneli kod)
    else Kayıtlı ama hiç doğrulanmamış
        S->>DB: aynı yer tutucuya ikinci bir pending_registrations satırı<br/>(var olan hiçbir şey değişmez)
        S->>Q: doğrulama e-postası (bu kaydın link/kodu)
    else Doğrulanmış hesap / geri alma için rezerve adres
        S->>Q: "adresinizle kayıt denendi" bildirimi (adres başına sınırlı)
    end
    Q-->>T: e-posta: {public_base_url}/verify-email#token=…
    T->>S: POST /v1/email/verify {token} (+ tutamaç çerezi)
    S->>DB: link token'ını tüket, tutamacın aynı kayda ait olduğunu doğrula
    alt Link + aynı kaydın tutamacı (veya kayıtta seçilen şifre / yeni şifre)
        S->>DB: o kaydın kimlik bilgisini etkinleştir, diğer bekleyen kayıtları sil,<br/>adres doğrulandı, hesap active
        S-->>T: 200 (oturum açılmaz)
    else Yalnızca link (başka cihaz, tutamaç yok)
        S-->>T: 403 registration_confirmation_required<br/>(istemci password veya new_password ile tekrar gönderir)
    end
```

Kod yolu (mobil): `POST /v1/email/verify {code, registration}` — kod yalnızca o kaydın tutamacıyla geçerlidir; tutamaçsız kod `invalid_code`.

## 2. Giriş + MFA (web) (SES-01, SES-02, SES-04, MFA-*)

Kaynak: `crates/authn-session/src/login/{routes,password,pipeline,challenge}.rs`, `crates/authn-session/src/{csrf,cookies}.rs`, `crates/authn-protect/src/login.rs`.

```mermaid
sequenceDiagram
    autonumber
    participant T as Tarayıcı
    participant S as Sunucu
    participant DB as PostgreSQL

    T->>S: GET /v1/csrf
    S-->>T: {csrf_token, kind: "pre_session"}<br/>Set-Cookie: __Host-authn_csrf (Strict)
    T->>S: POST /v1/login/password {email, password}<br/>Origin + X-CSRF-Token
    S->>S: login CSRF (Origin izinli + HMAC(pre-session))
    S->>DB: LoginProtection.check_attempt: IP sınırı,<br/>hesap CAPTCHA eşiği, yumuşak kilit
    S->>S: Argon2id doğrulama (hesap yoksa eşdeğer sahte doğrulama)
    alt Şifre yanlış / hesap yok
        S->>DB: record_failure
        S-->>T: 401 invalid_credentials (tek tip)
    else Şifre doğru
        Note over S: Planla (bağlantı tutmadan): hesap durumu → istenen organizasyon<br/>(üyelik, IP, izinli yöntem) → MFA politikası → risk (RSK-03) →<br/>güvenilir cihaz (MFA-09)
        alt MFA veya zorunlu adım gerekmiyor
            S->>DB: oturum kur (yeni kimlik + token), audit, record_login
            S-->>T: 200 authenticated + csrf_token<br/>Set-Cookie: __Host-authn_session (Lax), pre-session silinir
        else MFA gerekiyor
            S->>DB: auth_challenges (allowed_factors, required_actions)
            S-->>T: 200 challenge_required {allowed_factors, …}<br/>Set-Cookie: __Host-authn_challenge (Strict)
            T->>S: POST /v1/login/challenge/verify {method: "totp", code, trust_device}<br/>(challenge çerezi + CSRF)
            S->>DB: open_challenge (satır kilidi, kullanılmış/süresi dolmuş/başka cihaz → 401 challenge_invalid)
            S->>S: method ∈ allowed_factors? (değilse doğrulamadan önce ret)
            S->>S: faktörü doğrula (kilit dışında)
            alt Yanlış kod
                S->>DB: record_challenge_failure (sınırda challenge yanar)
                S-->>T: 401/400 (faktöre göre)
            else Doğru kod
                S->>DB: challenge'ı tüket + oturum kur (aynı transaction),<br/>sessions.mfa_factors = [totp], amr = [pwd, otp, mfa]
                S-->>T: 200 authenticated + csrf_token<br/>Set-Cookie: __Host-authn_session [+ __Host-authn_trusted_device]
            end
        end
    end
```

Native istemcide aynı akış `X-Authn-Client: native` ile çalışır: CSRF adımları yoktur, challenge token'ı gövdede döner ve `X-Authn-Challenge` başlığıyla gönderilir, başarıda gövdede `access_token` + `refresh_token` gelir.

## 3. Refresh token rotasyonu ve yeniden kullanım tespiti (SES-05)

Kaynak: `crates/authn-session/src/service/refresh.rs`, `crates/authn-session/src/store/refresh.rs`.

```mermaid
sequenceDiagram
    autonumber
    participant A as Native istemci
    participant X as Saldırgan (çalınmış token)
    participant S as Sunucu
    participant DB as PostgreSQL

    A->>S: POST /v1/token/refresh {refresh_token: R1}
    S->>DB: IP sınırı, oturum satırını kilitle, sonra R1 satırını
    S->>DB: R1 emekli, R2 canlı (aynı aile = oturum,<br/>mutlak bitiş değişmez, R2 ↔ yeni access token jti)
    S-->>A: 200 {access_token, refresh_token: R2, expires_in, …}
    X->>S: POST /v1/token/refresh {refresh_token: R1}
    S->>DB: R1 emekli → yeniden kullanım
    alt refresh_reuse_grace penceresi içinde ve R2 henüz kullanılmamış
        S->>DB: R1'e mühürlenmiş aynı ardılı (R2) aç
        S-->>X: 200 aynı R2 (asla ikinci canlı token)
    else Varsayılan (grace = 0) veya ardıl kullanılmış
        S->>DB: aileyi (oturumu) iptal et: refresh_token_reuse<br/>audit session.refresh_token_reused, metrik
        S-->>X: 401 invalid_refresh_token
    end
    A->>S: POST /v1/token/refresh {refresh_token: R2}
    S-->>A: 401 invalid_refresh_token (oturum iptal edildi → yeniden giriş)
```

Bilinmeyen, süresi dolmuş, iptal edilmiş ve tekrar kullanılmış token'ların hepsi aynı `401 invalid_refresh_token`'ı alır. Eşzamanlı iki yenilemede satır kilidi sırası (oturum → token) birini kazandırır; diğeri tekrar sayılır.

## 4. Şifre sıfırlama (PWD-07, PWD-08, PWD-09)

Kaynak: `crates/authn-password/src/service/reset.rs`.

```mermaid
sequenceDiagram
    autonumber
    participant T as İstemci
    participant S as Sunucu
    participant DB as PostgreSQL
    participant Q as Outbox / e-posta

    T->>S: POST /v1/password/forgot {email}
    S->>DB: IP sınırı + adres sınırı (hesap olsun olmasın aynı sayaç)
    S-->>T: 202 (her adres için aynı durum, gövde, süre)
    Note over S,DB: Arka plan işi
    alt Uygun hesap var
        S->>DB: önceki sıfırlama token'larını iptal et,<br/>link token'ı (256 bit, SHA-256) + 6 haneli kod (HMAC), aynı group_id,<br/>target = gönderildiği adres
        S->>Q: e-posta: /reset-password#token=… + kod
    else Hesap yok / uygun değil
        S->>S: eşdeğer iş, gönderim yok
    end
    T->>S: POST /v1/password/reset {token, new_password}<br/>(veya {email, code, new_password})
    S->>DB: tamamlama IP sınırı (kodda adres başına deneme sınırı)
    S->>DB: token'ı atomik tüket (adres hâlâ target ile aynı olmalı)
    S->>S: şifre politikası + HIBP + Argon2id
    S->>DB: şifreyi yaz, TÜM oturumlar, refresh token'lar,<br/>güvenilir cihazlar ve bekleyen girişler iptal (password_reset)
    S->>Q: "şifreniz değişti" bildirimi
    S-->>T: 200 (oturum açılmaz, sonraki giriş MFA dahil normal akış)
```

## 5. Sosyal giriş (web) (SOC-01 … SOC-05, SOC-09)

Kaynak: `crates/authn-oidc-client/src/{routes,cookies,service/…}.rs`, `crates/authn-session/src/service/issuer.rs`.

```mermaid
sequenceDiagram
    autonumber
    participant T as Tarayıcı
    participant S as Sunucu
    participant P as Sağlayıcı (Google/Apple/…)
    participant DB as PostgreSQL

    T->>S: GET /v1/oauth/{provider}/start?return_to=/app
    S->>S: return_to doğrula (göreli güvenli yol / izin listesi)
    S->>DB: oauth_states: SHA-256(state), SHA-256(nonce),<br/>SHA-256(bağlama), şifreli PKCE doğrulayıcısı, return_to (10 dk)
    S-->>T: 303 → sağlayıcı (state, nonce, PKCE challenge)<br/>Set-Cookie: __Host-authn_oauth (SameSite=None)
    T->>P: kullanıcı kimlik doğrular
    P-->>T: 303 / form_post → /v1/oauth/{provider}/callback?code&state
    T->>S: GET|POST /v1/oauth/{provider}/callback (+ bağlama çerezi)
    S->>DB: IP sınırı, state'i ATOMİK tüket
    S->>S: sağlayıcı yol ile eşleşmeli, bağlama çerezi hash'i eşleşmeli
    S->>P: code + PKCE doğrulayıcısı → token (SSRF korumalı HTTP)
    S->>S: ID token: imza (sağlayıcı JWKS), iss, aud, nonce
    alt (provider, sub) bağlı
        S->>S: o hesap
    else Bağlı değil
        S->>S: sağlayıcı e-postayı doğrulamış olmalı<br/>(değilse 403 oauth_email_not_verified — hesap sorgusundan önce)
        alt Adres boş
            S->>DB: hesap aç (active, doğrulanmış) + kimliği bağla
        else Adres bir hesaba ait
            S-->>T: 409 oauth_link_required (otomatik birleştirme yok,<br/>yalnızca auto_link_* açık ve güvenilir sağlayıcıysa bağlanır)
        end
    end
    S->>S: SessionIssuer: hesap durumu → organizasyon → MFA politikası → risk<br/>(amr = [fed], sağlayıcı MFA'sı yalnızca trust_provider_mfa ile)
    alt MFA gerekmiyor
        S->>DB: oturum kur
        S-->>T: 303 → return_to + Set-Cookie: __Host-authn_session
    else MFA gerekiyor
        S-->>T: 303 → return_to + Set-Cookie: __Host-authn_challenge<br/>(sayfa /v1/login/challenge/verify ile devam eder)
    end
```

Hata olursa `oidc_client.error_redirect` ayarlıysa `303 …?error=<kod>`, değilse JSON hata zarfı. Native akış (`POST /v1/oauth/nonce` → SDK → `POST /v1/oauth/{provider}/native`) state/çerez yerine sunucunun verdiği tek kullanımlık nonce'u tüketir ve token'ları gövdede döner.

## 6. Davet kabulü (ORG-05)

Kaynak: `crates/authn-org/src/service/invitations.rs`, `crates/authn-org/src/authz.rs`.

```mermaid
sequenceDiagram
    autonumber
    participant Y as Organizasyon yöneticisi
    participant S as Sunucu
    participant DB as PostgreSQL
    participant Q as Outbox / e-posta
    participant D as Davetli

    Y->>S: POST /v1/orgs/{org_id}/invitations {email, role_id}
    S->>S: authorize: members:invite, politika (IP, MFA, yöntem),<br/>yükseltme koruması (verilen rolün izinleri ⊆ yöneticininki,<br/>owner daveti step-up)
    S->>DB: organizasyon ve organizasyon+alıcı gönderim bütçeleri,<br/>bekleyen davet sınırı
    S->>DB: invitations (token SHA-256, expires_at = +7 g)
    S->>Q: davet e-postası: /invitations/accept#token=…<br/>+ invitation.created olayı
    S-->>Y: 201
    D->>S: (oturum açar) POST /v1/invitations/preview {token}
    S-->>D: org adı, rol, maskeli adres, email_matches
    D->>S: POST /v1/invitations/accept {token}
    S->>DB: kullanıcı başına deneme sınırı, daveti kilitle
    alt Token bilinmiyor/kullanılmış/iptal/süresi dolmuş
        S-->>D: 400 invalid_or_expired_token (ayırt edilemez)
    else Adres eşleşmiyor / doğrulanmamış
        S-->>D: 403 org_invitation_email_mismatch / org_email_verification_required
    else Uygun
        S->>DB: üyelik ekle (davetteki rol), daveti kabul edildi işaretle,<br/>otomatik katılım istisnasını sil, audit,<br/>member.added + invitation.accepted olayları
        S-->>D: 200 (eşzamanlı kabullerde tam olarak biri başarılı)
    end
```
