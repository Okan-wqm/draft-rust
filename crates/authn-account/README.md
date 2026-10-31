# authn-account

Kayıt, e-posta doğrulama, hesap durum makinesi, profil, e-posta değişikliği, hesap silme, veri dışa aktarma (`DataExporter` toplayıcısı) ve onay kayıtları.

## Sahip olunan gereksinimler

ACC-01 … ACC-13, DOC-07

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-account/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/account.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/account.rs` |
| Uygulanan portlar | `DataExporter` toplayıcısı (`crates/authn-core/src/ports/data_exporter.rs`) |
| Sahip olunan tablolar | `user_profiles`, `terms_versions`, `consents`, `account_deletions` (+ `users` üzerinde durum geçişleri `UserRepository` ile) |
| `one_time_tokens.purpose` değerleri | `email_verification`, `email_verification_code`, `email_change`, `email_change_code`, `email_change_revert`, `account_deletion_cancel` |
| Migration aralığı | `1200–1299` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- E-posta normalizasyonunun temel hali `authn_core::domain::EmailAddress` içindedir; ACC-03 sahibi olarak sertleştirme (ör. ek kurallar) sözleşme değişikliği talebiyle yapılır.
- Durum makinesi (ACC-06) tek bir fonksiyonda tanımlanır; DB yazımı `UserRepository::update_status` (compare-and-set) ile yapılır.
- Hesap silme tamamlanınca `UserRepository::delete` ile kullanıcı satırı silinir; FK `ON DELETE CASCADE` tüm modül verilerini temizler, audit takma adları bağlantısız kalır (AUD-05).

## Komutlar

```bash
cargo test -p authn-account
cargo clippy -p authn-account --all-targets -- -D warnings
cargo fmt -p authn-account
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
