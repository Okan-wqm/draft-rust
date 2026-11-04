# Üçüncü taraf lisans bildirimleri

Projede kullanılan tüm bağımlılıklar izin verici lisanslı (LIC-01). Ancak bu lisanslar da şartsız değil: MIT, BSD, ISC, Zlib, Apache-2.0 vb. lisanslar, yazılım **binary olarak dağıtıldığında** telif bildiriminin ve lisans metninin de verilmesini şart koşar. Apache-2.0 §4(d) ayrıca bağımlılıktaki `NOTICE` dosyasının içeriğinin aktarılmasını ister. MPL-2.0 (`webauthn-rs` ailesi) §3.2 ise alıcıya kaynak koduna nasıl ulaşacağının bildirilmesini gerektirir. Bu klasör, bu şartları harfi harfine karşılamak içindir.

## Ürün binary'si (`rust-authentication`)

- Kökteki `THIRD_PARTY_LICENSES.txt`, binary'ye giren her crate'i (test ve derleme bağımlılıkları hariç), lisansını, crate'in kendi lisans metnini ve telif bildirimlerini, ayrıca crate'lerin `NOTICE`/`COPYRIGHT`/`AUTHORS` dosyalarını **birebir** içerir. MPL-2.0 crate'leri için kaynak kodu erişim bildirimi dosyanın başındadır.
- Docker imajında `/usr/share/doc/rust-authentication/THIRD_PARTY_LICENSES.txt` yoluna kopyalanır. Binary'yi başka bir yolla dağıtırsanız bu dosyayı da yanında verin.
- Yeniden üretmek için (çevrimdışı, tekrarlanabilir; `cargo-about` 0.9.3, `--features cli` ile kurulu olmalı):

  ```bash
  python3 -I licenses/generate_notices.py
  ```

- CI'daki `licence-notices` işi dosyayı yeniden üretir ve depodakiyle farklıysa başarısız olur. Bağımlılık eklediğinizde/güncellediğinizde dosyayı yeniden üretip commit edin.
- Yapılandırma: `about.toml` (kabul edilen lisanslar `deny.toml` ile aynı tutulmalı), şablon `licenses/about.hbs`.
- Docker taban imajı (`distroless/cc-debian12`) içindeki Debian paketlerinin lisans bildirimleri imajın kendi `/usr/share/doc/*/copyright` dosyalarındadır; bunlar Rust bağımlılığı değildir.

## Fuzz düzeneği (`fuzz/`)

- `libfuzzer-sys` için proje sahibinin onayladığı lisans istisnası yalnızca `fuzz/` workspace'inde geçerlidir; kök `deny.toml` bu crate'i ürün workspace'inde yasaklar.
- Crate'in kaydı libFuzzer kısmı için "NCSA" der; içindeki kaynak dosyaların başlıkları ise `Apache-2.0 WITH LLVM-exception` der (LLVM 2019'da lisans değiştirdi, eski katkılar NCSA altında kaldı). İkisinin de şartlarını karşılamak için `fuzz/THIRD_PARTY_LICENSES.txt`, crate'in MIT ve Apache-2.0 metinlerini ve LLVM compiler-rt'nin `LICENSE.TXT` (Apache-2.0 + LLVM istisnaları + eski Illinois/NCSA ve MIT lisansları) ile `CREDITS.TXT` dosyalarını birebir içerir.
- Fuzz binary'leri dağıtılmaz; dağıtılırsa bu dosya yanında verilmelidir. NCSA şartı gereği LLVM Ekibi'nin, Illinois Üniversitesi'nin ve katkıcıların adları bu projeyi tanıtmak/onaylatmak için kullanılmaz.
