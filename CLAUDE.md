# rust-authentication — çalışma kuralları

Bu repo, B2C web, B2B SaaS ve mobil uygulamaların ortak kullanacağı, Rust ile yazılmış bir kimlik doğrulama sistemidir.
Tam gereksinimler: `docs/spec/requirements.md`. Modül sahipliği ve arayüz sözleşmeleri: `docs/architecture/contracts.md`.

> **Bu işi devralıyorsan önce `docs/HANDOFF.md`'yi, sonra `docs/handoff/remaining-work.md`'yi oku.** Projenin durumu, kalan işler, bilinen tuzaklar ve çalışma deseni orada.

## Değişmez kurallar

- **Dil:** Kod, tanımlayıcılar, kod yorumları, commit mesajları ve API hata kodları İngilizce. Tüm Markdown dokümantasyonu Türkçe.
- **Lisans:** Yalnızca izin verici lisanslı bağımlılıklar (MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2/3, ISC, Zlib, Unicode-3.0, CC0, CDLA-Permissive-2.0, 0BSD). GPL/AGPL/LGPL/SSPL/BUSL ve ticari lisans yasak. Onaylı istisnalar yalnızca şunlar: passkey için `webauthn-rs` ailesi (MPL-2.0), `deny.toml` içinde crate bazında; yalnızca geliştirme amaçlı `fuzz/` workspace'inde `libfuzzer-sys` (NCSA — BSD benzeri, ticari kullanıma izin verir), `fuzz/deny.toml` içinde crate bazında. `libfuzzer-sys` ürün workspace'inde (`deny.toml` `[bans]`) yasaktır, ürün binary'sine asla girmez. Yeni bağımlılık eklemeden önce lisansını kontrol et; `cargo deny check` geçmeli. Lisans şartları harfi harfine karşılanır: bağımlılık eklendiğinde/güncellendiğinde `python3 -I licenses/generate_notices.py` ile `THIRD_PARTY_LICENSES.txt` yeniden üretilip commit edilir (CI farkı yakalar; bkz. `licenses/README.md`).
- **Projenin kendi lisansı:** Tescilli, tüm hakları saklı (`LICENSE`, sahibi Okan-wqm, by-okan@live.com). Yazılı izin olmadan hiçbir amaçla kullanılamaz. Hiçbir dosyaya açık kaynak lisans başlığı ekleme; bağımlılıkların lisans şartları (`THIRD_PARTY_LICENSES.txt`) yine harfi harfine karşılanır.
- **Güvenlik:** `unsafe` yasak (`#![forbid(unsafe_code)]`). Sırlar `secrecy`/`zeroize` ile tutulur, `Debug` çıktısında görünmez, asla loglanmaz. Sır karşılaştırmaları sabit zamanlı (`subtle`). Rastgelelik yalnızca CSPRNG (`OsRng`/`getrandom`). Kendi kriptografik algoritmanı yazma; yalnızca denetlenmiş crate'leri birleştir.
- **Hata yönetimi:** Production kodunda `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` yok (testlerde serbest). Dış dünyaya iç hata detayı sızmaz; kararlı hata kodları kullanılır.
- **Hesap varlığını sızdırmama:** Kullanıcının var olup olmadığı yanıt içeriğinden, durum kodundan veya yanıt süresinden anlaşılmamalı.

## Kalite kapıları (her değişiklikten sonra)

Tek başına çalışırken (tüm workspace):

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

Başka agent'larla paralel çalışırken yalnızca kendi crate'in üzerinde (`--all`/`--workspace` biçimlendirmesi başkalarının yarım dosyalarını bozar):

```bash
cargo fmt -p <crate>
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
cargo test -p <crate> --all-features
```

Testler gerçek PostgreSQL kullanır (`DATABASE_URL`, varsayılanı `.cargo/config.toml` içinde). Her `#[sqlx::test]` kendi geçici veritabanını oluşturur.

## Çalışma düzeni

- Sadece sahibi olduğun crate/dosyaları değiştir (bkz. `docs/architecture/contracts.md`). Başka bir modülün arayüzünde değişiklik gerekiyorsa sözleşme belgesindeki kurala uy.
- Veritabanı sorguları çalışma zamanı sqlx sorgularıdır (`sqlx::query_as` + `FromRow`); derleme zamanı `query!` makroları kullanılmaz.
- Her gereksinimin bir kimliği vardır (ör. `PWD-07`). Test adlarında bu kimliği kullan (ör. `pwd_07_reset_token_is_single_use`).
