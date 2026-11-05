# Test kapsamı raporu (K-57 §6)

> **Tarih:** 2026-11-05 · **Dal:** `claude/compassionate-darwin-aa1tiy` (taban `428a267`) · **Ortam:** 4 vCPU konteyner, yerel PostgreSQL 16 + Redis.

Bu belge, `cargo llvm-cov` ile üretilen kapsam raporunun **özetidir** (HTML raporu repoya alınmaz). Amaç bir yüzde hedefi tutturmak değildir: güvenlik açısından kritik yollardaki **kapsanmayan dalları** tek tek incelemek, erişilebilir olanları testle kapatmak, erişilemeyenleri gerekçesiyle kayda geçirmektir.

## Komut

Dal (branch) kapsamı yalnızca nightly derleyicide vardır (`-Z coverage-options=branch`). CI'daki `coverage` işi kararlı 1.97 ile yalnızca satır/bölge kapsamı üretir (`--lcov`). Bu rapor için:

```bash
rustup toolchain install nightly --profile minimal
rustup component add llvm-tools-preview --toolchain nightly
cargo install cargo-llvm-cov --locked          # 0.9.1, Apache-2.0 OR MIT (yalnızca geliştirme aracı)

# Ayrı hedef dizini: ana target/ dizinine dokunmaz, iş bitince silinir (~15 GB).
export CARGO_LLVM_COV_TARGET_DIR=/tmp/authn-cov
cargo +nightly llvm-cov --workspace --all-features --branch --no-report
cargo +nightly llvm-cov report --branch --summary-only
cargo +nightly llvm-cov report --branch --json --output-path cov.json
rm -rf "$CARGO_LLVM_COV_TARGET_DIR"
```

Koşu süresi ~15 dk (derleme dahil). **Disk:** enstrümante derleme ~15 GB yer kaplar; aynı diskte eski bir `target/` varsa önce `cargo clean` gerekebilir (bu koşuda ilk deneme diski doldurdu).

## Toplam

| | Bölge | Fonksiyon | Satır | Dal |
|---|---:|---:|---:|---:|
| Önce (yeni testler yok) | 88,63 % | 89,78 % | 93,61 % | 80,28 % |
| Sonra | 88,68 % | 89,80 % | 93,66 % | 81,04 % |

`llvm-cov`'un toplam dal sayısı aynı kaynak dalını birden fazla test binary'sinde (birim testli kütüphane + her entegrasyon test binary'si) ayrı sayar. Aşağıdaki crate tablosu dalları **kaynak konumuna göre birleştirir** (bir dal herhangi bir binary'de alındıysa kapsanmış sayılır). Satır sayıları `#[cfg(test)]` birim test modüllerini de içerir.

## Crate bazında (satır / birleştirilmiş dal)

Kalın satırlar güvenlik açısından kritik crate'lerdir; yeni testler yalnızca onlara eklendi.

| Crate | Satır önce | Satır sonra | Dal önce | Dal sonra |
|---|---:|---:|---:|---:|
| authn-account | 93,58 % | 93,56 % | 78,16 % | 77,98 % |
| authn-admin | 95,02 % | 95,02 % | 86,05 % | 86,05 % |
| **authn-audit** | 94,04 % | 94,23 % | 82,54 % | **84,41 %** |
| authn-core | 96,39 % | 96,39 % | 77,38 % | 77,38 % |
| **authn-crypto** | 96,59 % | 96,76 % | 87,03 % | **91,35 %** |
| **authn-mfa** | 94,98 % | 94,98 % | 84,23 % | 84,23 % |
| authn-notify | 92,33 % | 92,33 % | 86,29 % | 86,29 % |
| authn-oidc-client | 93,82 % | 93,82 % | 81,19 % | 81,19 % |
| **authn-org** | 95,69 % | 95,73 % | 82,38 % | 82,56 % |
| **authn-password** | 94,98 % | 94,98 % | 83,50 % | 83,50 % |
| **authn-protect** | 92,10 % | 92,12 % | 84,72 % | **85,52 %** |
| authn-server | 83,50 % | 83,50 % | 71,62 % | 71,62 % |
| **authn-session** | 91,46 % | 91,64 % | 72,69 % | **74,36 %** |
| authn-store | 93,98 % | 93,98 % | 88,54 % | 88,54 % |
| authn-testkit | 91,07 % | 91,16 % | 82,86 % | 84,29 % |
| **authn-webauthn** | 91,10 % | 91,10 % | 82,69 % | 82,69 % |

authn-account'taki ±1 dal farkı zamanlamaya bağlı (arka plan işi) bir yolun koşudan koşuya değişmesidir; kod değişmedi.

## Kapatılan kapsanmayan dallar (yeni testler)

| Alan | Kapsanmayan dal | Test |
|---|---|---|
| authn-crypto JWT | 512 bayttan uzun header; boş / 16'dan uzun `aud` dizisi; `iat` gelecekte veya `exp`'ten sonra; azami ömür sınırında kabul; geçersiz `typ` ve 8 KiB'ı aşan token'ı imzalamayı reddetme; `JwtError` → `internal_error` / `unauthenticated` eşlemesi | `cry_09_oversized_header_is_rejected_before_decoding`, `cry_09_audience_arrays_must_be_non_empty_and_bounded`, `cry_09_issued_at_in_the_future_or_after_expiry_is_rejected`, `cry_09_lifetime_within_the_maximum_is_accepted`, `cry_09_signer_refuses_bad_typ_and_oversized_tokens` (`src/jwt/tests.rs`) |
| authn-crypto zarf | SQL tanımlayıcısı olmayan tablo/sütun adı; Poly1305 etiketinden kısa şifreli metin | `cry_08_*` (`tests/rejection_paths.rs`) |
| authn-crypto webhook imzası | Çözmeden önce aşırı uzun sır; boş / 256'dan uzun / geçersiz karakterli `webhook-id`; 0 veya 16'dan fazla sırla imzalama; kanonik olmayan zaman damgası (`0…`, `+`, `-`, boşluk, 13 hane) | `aud_07_webhook_*` (`tests/rejection_paths.rs`) |
| authn-crypto TOTP | `:` içeren issuer, boş/kontrol karakterli hesap adı, 256 karakteri aşan değerler (provisioning URI) | `mfa_01_totp_provisioning_uri_rejects_ambiguous_issuer_and_account` |
| authn-session çerez | 8 KiB'ı aşan veya UTF-8 olmayan `Cookie` başlığı yok sayılır; `=` içermeyen parçalar; güvensiz değerler hiç yazılmaz | `ses_03_oversized_non_utf8_and_malformed_cookie_headers_are_ignored` |
| authn-session CSRF | Doğru token'ın bir eksik / bir fazla karakterli kopyası (uzunluk uyuşmazlığı dalı) | `ses_04_state_changing_cookie_requests_need_origin_and_csrf_token` (genişletildi) |
| authn-session bearer | İki `Authorization` başlığı (aynı olsalar bile); görünür ASCII olmayan başlık değeri | `ses_08_repeated_or_non_ascii_authorization_headers_are_rejected` |
| authn-session introspection | `token_type_hint=refresh_token`, boş ve 20 000 baytlık token → `active: false` | `ses_10_empty_oversized_and_refresh_hinted_tokens_are_inactive` |
| authn-session giriş | 4096 baytı aşan şifre / çok uzun tanımlayıcı Argon2'den önce reddedilir; yanıt yanlış şifreyle aynı | `ses_01_oversized_identifier_or_password_is_refused_like_a_wrong_password` |
| authn-org API anahtarı | Askıya alınmış / silinmesi planlanmış org'un anahtarı (`org_inactive`, tek tip 401, denetim kaydı; org yeniden etkinleşince anahtar çalışır) | `org_08_keys_of_suspended_or_deleting_organizations_are_refused` |
| authn-audit zincir doğrulama | Sıra numarası doğru, hash'i sahte zincir başı (`HeadMismatch`); olay satırları tutarlıyken sahte hash'li checkpoint (`CheckpointMismatch`) | `aud_02_forged_head_hash_or_checkpoint_hash_is_detected` |
| authn-audit SSRF aralıkları | CGNAT `100.64/10`, 6to4 relay `192.88.99/24`, benchmark `198.18/15`, `192.0.0/24`, `240/4`: aralığın ilk/son adresi reddedilir, hemen dışındaki genel adres reddedilmez; IPv4-mapped IPv6 | `prt_12_special_ipv4_ranges_are_refused_exactly_at_their_boundaries` |
| authn-protect giden HTTP | `Content-Length` göndermeden chunked akıtan sunucu: sınır okuma sırasında uygulanır; kullanıcı URL'sinde kimlik bilgisi, port 0, https olmayan şema | `prt_12_streamed_response_without_length_is_capped_while_reading`, `prt_12_user_supplied_urls_with_credentials_or_port_zero_are_refused` |
| authn-protect PoW CAPTCHA | 1–64 dışındaki zorluk yapılandırması; geçersiz eylem adı | `prt_05_pow_refuses_out_of_range_difficulty_and_invalid_action_names` |
| authn-protect yönlendirme | Normalleştirilmiş biçimin 2048 bayt sınırını aşması (fuzz bulgusu, aşağıya bakın) | `prt_10_normalised_target_respects_the_length_limit_and_revalidates` |

## Bilinçli olarak kapsanmayan dallar (gerekçeli)

Kalan dalların büyük çoğunluğu şu sınıflardandır; her biri incelendi:

1. **Derinlemesine savunma: önceki bir kontrol aynı durumu zaten yakalıyor.** Örnekler:
   - `authn-session/src/service/refresh.rs`: `row.session_id != record.id`, `revoked_at`, satır süresi dolmuş, ardıl token zaten kullanılmış/iptal edilmiş/süresi dolmuş. Token önce oturumuyla eşlenir; iptal ve süre dolumu oturumu da düşürür (`lock_live` reddeder); rotasyon ebeveynin mühürlü ardılını aynı ifadede siler. Bu yüzden ardıl kontrollerine genel API'den ulaşılamaz. Davranış zaten `ses_05_*` testleriyle doğrulanıyor (yeniden kullanım, grace penceresi, kapanan pencere).
   - `authn-org/src/service/api_keys.rs:569`: veritabanı hash ile eşleştirdikten sonra sabit zamanlı ikinci karşılaştırma.
   - `authn-password/src/service/reset.rs:513`: satır kilidi altında yeniden kontrol. Durum ve adres değişikliği daha önceki bir adımda reddediliyor (`pwd_09_reset_is_refused_when_the_account_was_suspended_meanwhile`, `pwd_07_reset_secrets_die_when_the_account_changes_its_address`).
   - `authn-webauthn/src/service/authentication.rs:411/477`: kullanıcı doğrulaması (UV) `webauthn-rs` tarafından zaten zorunlu tutuluyor. Satır 483'teki "her iki sayaç da 0" alt koşulu, sayacı hep 0 bildiren bir doğrulayıcı gerektirir (yazılım doğrulayıcısı sayacı artırır; sayaç imzalı olduğu için sahtelenemez).
   - `authn-protect/src/captcha/pow.rs:139/227/297` (sürüm baytı, kanonik olmayan base64, zorluk aralığı): yük HMAC ile korunur; kanonik olmayan base64'ü çözücü zaten reddeder.
2. **Kısa devre alt koşulları.** `a || b || c` biçimindeki bir kontrolde dal sayacı her alt koşulu ayrı sayar (MC/DC benzeri). Bu yüzden ret yolu test edilse bile, testin ilk alt koşulda durduğu hallerde sonraki alt koşullar "kapsanmadı" görünür (ör. `jwt.rs` `verify_signature` uzunluk/alfabe kontrolleri).
3. **Veritabanı / altyapı hataları** (`?` ile yayılan `sqlx` hataları, `rollback` hatası, denetim kaydının başarısız olması). Bunlar fake portlarla ayrıca test edilen hata yollarıdır. Gerçek PostgreSQL'de tetiklemek için arıza enjeksiyonu gerekir.
4. **Test kodunun kendi dalları** (`assert!(a && b)` biçimindeki iddiaların başarısız tarafı) ve `Display` / `Debug` uygulamaları.

## İlgili

- Uzun fuzz koşusu ve bulgusu: [`docs/handoff/remaining-work.md`](../handoff/remaining-work.md) K-57 satırı.
- Gereksinim izlenebilirliği (her kimlik bir test adında): `scripts/check-requirement-coverage.sh`.
