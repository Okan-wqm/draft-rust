# Olay müdahalesi runbook'ları (DOC-06)

Her runbook: **belirtiler → hemen yap → incele → kapat**. Komutlar ve uçlar koddan doğrulanmıştır. Admin API uçları `/v1/admin/...` platform admini + passkey oturumu + step-up ister; her işlemde `reason` (gerekçe) zorunludur ve dört göz onayı açıksa (üretimde varsayılan) acil işlemler ve başka admini hedefleyen işlemler önce `POST /v1/admin/approvals` ile ikinci bir adminin onayını ister. Admin hesaplarının kendisi ele geçirildiyse: [admin-recovery.md §6](admin-recovery.md#6-prosedürler). Anahtar rotasyon adımları: [key-management.md](key-management.md). Alarmlar: [monitoring.md](monitoring.md).

Genel ilkeler:

- **Önce durdur, sonra incele.** Oturum iptali her bearer isteğinde etkilidir (`session.access_token_session_check`, üretimde zorunlu `true`); askıya alma ve iptal bir sonraki istekte geçerlidir.
- **Kanıtı koru:** audit log ekleme-yalnızca ve anahtarlı zincirlidir; müdahaleye başlamadan en yeni dış çıpayla (`anchor` alanlı `audit chain scheduled checkpoint` log satırları, K-107) `rust-authentication verify-audit-chain --anchor <seq>:<hash>` çalıştırın, ardından `rust-authentication audit-checkpoint | tail -n1` ile yeni bir çıpa alıp dışarıda saklayın. Veritabanı anlık görüntüsü alın ([backup.md](backup.md)).
- Her istekte `x-request-id` (UUIDv7) loglarla eşleştirme anahtarıdır.

## 1. Tek hesabın ele geçirilmesi

**Belirtiler:** kullanıcı "bu ben değilim" e-postasındaki linke tıkladı (`POST /v1/login/not-me` → audit'te ilgili olay); bilinmeyen cihazdan giriş bildirimi; şikâyet; `authn_refresh_token_reuse_total` artışı (çalınmış refresh token); beklenmeyen e-posta değişikliği.

**Hemen yap:**

1. Kullanıcının kendi tepkisi zaten güçlüdür: "bu ben değilim" linki **tüm oturumları, güvenilir cihazları ve bekleyen girişleri kapatır, şifre değişikliğini zorunlu kılar** ve sıfırlama e-postası gönderir (RSK-04).
2. Destek/admin tarafında (sırayla, ihtiyaca göre):
   - Oturumları kapat: `POST /v1/admin/users/{user_id}/revoke-sessions` (tüm oturumlar + güvenilir cihazlar).
   - Askıya al (inceleme sürerken): `POST /v1/admin/users/{user_id}/suspend` — oturumlar ve güvenilir cihazlar da kapanır; askıdaki hesap kimlik doğrulayamaz.
   - Şifreyi geçersiz kıl: `POST /v1/admin/users/{user_id}/force-password-reset` (şifre çalışmaz, oturumlar kapanır, sıfırlama linki gider).
   - Saldırgan MFA kaydettiyse: `POST /v1/admin/users/{user_id}/reset-mfa` (faktörler, kurtarma kodları ve passkey'ler silinir, kullanıcıya bildirilir).
3. E-posta adresi değiştirildiyse: eski adrese giden "geri al" linki `account.email_change_revert_ttl` (7 g) boyunca geçerlidir; kullanıcı `POST /v1/email/change/revert` ile adresi geri alır — her yerden çıkış yapılır, şifre sıfırlaması zorunlu olur ve bağlı sosyal kimliklerin tümü kaldırılır. Eski adres bu süre boyunca başkasına verilmez (rezerve).

**İncele:**

- Kullanıcının olayları: `GET /v1/admin/audit-events?subject_user_id=<id>&since=<RFC3339>` (ve `actor_user_id`); hesap ayrıntısı `GET /v1/admin/users/{user_id}` (erişim audit'lenir).
- Bakılacaklar: girişler ve IP'ler, `session.refresh_token_reused`, yeni passkey/MFA faktörü/bağlı kimlik, e-posta değişikliği, API anahtarı oluşturma (`api_key.created` olayı), organizasyon üyelik/rol değişiklikleri, veri dışa aktarma (`POST /v1/me/export`).
- Kullanıcı bir organizasyonda yetkiliyse o organizasyonun audit log'una ve API anahtarlarına bakın; şüpheli anahtarları organizasyon yöneticisi `DELETE /v1/orgs/{org_id}/api-keys/{key_id}` ile iptal eder.

**Kapat:** askıyı kaldır (`POST /v1/admin/users/{user_id}/unsuspend`), kullanıcı yeni şifre + MFA ile girer; gerekirse `must-change-password`.

## 2. Toplu oturum kapatma (yaygın token/çerez sızıntısı)

**Ne zaman:** oturum çerezlerinin veya refresh token'ların toplu sızdığından şüphe (ör. bir log/izleme aracına düşmeleri, istemci tarafı açık).

1. Tümünü kapat (dört göz):
   ```http
   POST /v1/admin/emergency/revoke-all-sessions
   {"reason": "INC-123 çerez sızıntısı", "confirm": "revoke_all_sessions", "approval_id": "…"}
   ```
   Varsayılan olarak **çağıranın kendi oturumu korunur** (müdahale sürsün diye); `"include_own_session": true` ile o da kapanır. Diğer her oturum (impersonation dahil) kapanır.
2. Şifrelerden de şüpheleniliyorsa toplu şifre değişikliği:
   ```http
   POST /v1/admin/emergency/force-password-change
   {"reason": "…", "confirm": "force_password_change", "changed_before": "2026-11-05T12:00:00Z", "revoke_sessions": true, "approval_id": "…"}
   ```
   Şifresi `changed_before`'dan önce değişmiş her hesap sonraki girişte değiştirmek zorundadır (partiler hâlinde; başarısız bir parti `batch_failed` olarak audit'lenir).
3. Acil işlemler admin başına (3/saat) ve küresel (6/saat) sınırlı, aynı işlem için 5 dk soğuma süresi var; `429` + `Retry-After` alırsanız bekleyin. Break-glass hesabı paylaşılan limitlerden muaftır ([admin-recovery.md](admin-recovery.md)).
4. Admin API'sine erişilemiyorsa: veritabanında oturumları elle silmeyin (audit'siz); önce bir admin hesabını CLI ile kurtarın ([admin-recovery.md §5](admin-recovery.md#5-çevrimdışı-cli-komutları)).

## 3. JWT imza anahtarı sızıntısı

**Belirtiler:** özel anahtar materyalinin (veritabanı + KEK birlikte) sızdığı şüphesi; tanımadığınız `jti`'li geçerli token'lar.

1. Acil rotasyon (CLI veya API):
   ```bash
   rust-authentication --config prod.toml rotate-signing-key --emergency
   ```
   veya `POST /v1/admin/emergency/rotate-signing-key` (`"confirm": "rotate_signing_key"`). Etkin anahtar iptal edilir ve JWKS'ten hemen düşer; tüm örnekler `LISTEN/NOTIFY` ile önbelleğini milisaniyeler içinde boşaltır. Sızan anahtarla imzalanmış token'lar bizim sunucumuzda anında reddedilir.
2. **Kaynak sunucularınızı** uyarın: JWKS önbelleklerini hemen yenilesinler (aksi hâlde `max-age` = `jwks_cache_ttl` boyunca sahte token kabul edebilirler).
3. Native istemciler refresh token'la yeni access token alır; ek işlem gerekmez. Refresh token'lar ayrıca sızdıysa §2.
4. Özel anahtarlar KEK ile şifreli saklandığı için sızıntı veritabanı + KEK birlikteliğini gösterir: §4 KEK adımlarını da uygulayın.

## 4. Pepper, KEK veya HMAC kök anahtarı sızıntısı

Hangi anahtarın neyi koruduğu: [key-management.md §0](key-management.md#0-envanter).

**Pepper sızdı (veritabanı sızmadan):** tek başına doğrudan bir zarar yok; şifre hash'leri olmadan pepper işe yaramaz. Yeni pepper sürümü ekleyin ([key-management.md §1](key-management.md#1-pepper-rotasyonu-cry-02-cry-03)); hash'ler girişlerde taşınır.

**Pepper + `password_credentials` sızdı:** çevrimdışı tahmin mümkündür (Argon2id maliyetiyle). Yeni pepper sürümü + `POST /v1/admin/emergency/force-password-change` (`changed_before` = olay anı, `revoke_sessions: true`). Kullanıcılara bildirin.

**KEK sızdı:** KEK yalnızca DEK'leri sarar ve `rotate-kek` veriyi yeniden şifrelemez, yalnızca DEK'leri yeni KEK ile yeniden sarar. Sızan KEK + **herhangi bir** veritabanı kopyası (eski yedekler dahil) o kopyadaki zarfları açar. Bu yüzden:

1. Yeni KEK + `rotate-kek` (gelecekteki kopyalar için).
2. Zarf içindeki sırları **kendileri** döndürün:
   - JWT imza anahtarları: `rotate-signing-key --emergency` (§3).
   - Webhook imza sırları: organizasyonlardan `rotate-secret?immediate=true` istemesini isteyin (platform tarafında toplu bir komut yok).
   - TOTP sırları (`mfa_factors.secret_ciphertext`): kullanıcıların TOTP'yi yeniden kaydetmesi gerekir; zorunlu tutmak için etkilenen kullanıcılarda `reset-mfa`.
   - Saklanan sağlayıcı token'ları (`identities.*_token_ciphertext`; Apple refresh token'ları varsayılan olarak saklanır): sağlayıcı tarafında iptal edin / bağlantıları yeniden kurdurun.
   - Apple özel anahtarı (`private_key_ciphertext` kullanıyorsanız): Apple'da yeni anahtar + `seal-apple-key`.
   - Outbox yükleri (bildirim token'ları, kısa ömürlü) ve refresh ardılları kendiliğinden süresi dolar.
3. Eski yedeklerin erişimini gözden geçirin.

**HMAC kök anahtarı sızdı:** saldırgan geçerli CSRF token'ı, güvenilir cihaz token'ı, PoW çözümü üretebilir ve (veritabanıyla birlikte) OTP/kurtarma kodu hash'lerine çevrimdışı saldırabilir, audit zincirini yeniden hesaplayabilir. Kök anahtar sürümsüzdür; değiştirmek yıkıcıdır ([key-management.md §4](key-management.md#4-hmac-kök-anahtarı-cryptohmac_root_key)):

1. `verify-audit-chain` çalıştırın, `head <seq>:<hash>`'i ve tam yedeği dışarıda saklayın (eski olayların bütünlüğünün tek kanıtı).
2. Yeni kök anahtarı dağıtın, tüm örnekleri aynı anda yeniden başlatın.
3. Kullanıcılara kurtarma kodlarını yeniden üretmelerini bildirin; `revoke-all-sessions` ile tüm oturumları kapatın (güvenilir cihaz token'ları zaten geçersizleşir).
4. Bundan sonra `verify-audit-chain` eski olaylar için bozulma raporlar; yeni bir zincir başlangıcı olarak belgelendirin.

## 5. Audit kurcalama tespiti

**Belirtiler:** `verify-audit-chain` çıkış kodu `1` / `POST /v1/admin/audit-events/verify` raporunda `broken`; günlük bakım işinin `audit retention purge refused: chain segment does not verify` hatası; beklenen olayların yokluğu.

1. **Doğrula ve çıpala:**
   ```bash
   rust-authentication --config prod.toml verify-audit-chain
   rust-authentication --config prod.toml verify-audit-chain --anchor <WORM'daki son seq:hash>
   # zamanlanmış çıpalar: log hattındaki "anchor" alanı (audit.checkpoint_interval, varsayılan günlük)
   ```
   Sorun türleri: hash uyuşmazlığı (satır değişti/silindi), `key_downgrade` (anahtarlı satırdan sonra anahtarsız veya düşük sürüm — eski bir ikili geri yüklenmiş olabilir ya da sahte satır), `unkeyed_event` (sabitlenen eski önekten sonra anahtarsız satır), `key_switch_unrecorded`, `head_mismatch`.
2. **Kapsam:** veritabanına yazabilen ama zincir anahtarını bilmeyen biri geçerli sahte olay ekleyemez/zinciri yeniden hesaplayamaz. Sondan **kesme veya geri sarma** yalnızca dış çıpayla (`--anchor`) yakalanır; sunucu çıpayı kendisi üretip loglar (K-107), log hattının onu veritabanı dışına taşıdığından emin olun ([key-management.md §5](key-management.md#5-audit-zinciri-anahtarı-k-77)). Uygulama sürecinin kendisi (anahtarı tutar) ele geçirildiyse onun yazdıkları ayırt edilemez.
3. **Hemen yap:** veritabanı yetkilerini denetleyin — uygulama rolünün `audit_events` üzerinde `UPDATE`/`DELETE` yetkisi olmamalı ([least-privilege.md](least-privilege.md#doğrulama) sorguları); anlık görüntü alın; yetkili rollerin parolalarını değiştirin.
4. Kurcalanma kökenine göre §4 (kök anahtar) veya §1–§3'ü uygulayın; bozulma noktasından sonraki olayları güvenilmez sayın ve olayı belgeleyin.

## 6. Diğer sinyaller

| Sinyal | Olası anlam | Eylem |
|--------|-------------|-------|
| `authn_passkey_clone_suspected_total` | İmza sayacı geriledi: klonlanmış doğrulayıcı | Kullanıcının passkey'lerini inceleyin; kullanıcı `DELETE /v1/me/passkeys/{id}` / admin `reset-mfa` |
| `authn_break_glass_logins_total`, `authn_admin_break_glass_used_total` | Break-glass hesabı kullanıldı (her zaman yüksek öncelikli) | Planlı değilse [admin-recovery.md §6.2](admin-recovery.md#62-ele-geçirilmiş-break-glass-hesabı) |
| `authn_admin_throttled_total`, `authn_admin_four_eyes_refused_total` | Admin hesabı limitleri zorluyor | [admin-recovery.md §6.1](admin-recovery.md#61-ele-geçirilmiş-normal-admin) |
| `authn_mfa_sms_blocked_total{limit="…"}` | SMS pompalama denemesi | `mfa.sms.global_daily_budget` ve ülke listesini gözden geçirin |
| `authn_rate_limit_triggered_total{action="login"}`, `authn_soft_lock_engaged_total` | Kimlik bilgisi doldurma | CAPTCHA politikasını (`protect.captcha.login_policy`) `always` yapın, kaynak ağları engelleyin |
