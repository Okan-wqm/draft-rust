# En az yetkili veritabanı rolleri (OPS-10, AUD-02, K-42)

Bu belge üretim kurulumundaki üç PostgreSQL rolünü, her birinin yetkilerini ve kurulum adımlarını anlatır. Yetkiler elle yazılmaz: çalıştırılabilir yardımcı fonksiyon `authn_apply_least_privilege` (migration `2900_least_privilege.sql`, `2901_least_privilege_no_temp.sql` ve `2902_least_privilege_erasure_ledger.sql` ile güncellendi; sahibi authn-server) her seferinde aynı sonucu üretir. Testler: `crates/authn-server/tests/least_privilege.rs` (`ops_10_least_privilege_grants_are_exact`, `ops_10_the_application_runs_as_the_restricted_role`, `ops_10_roles_inheriting_owner_or_peer_privileges_are_refused`, `ops_10_least_privilege_helper_ignores_the_callers_search_path`, `ops_10_restricted_roles_cannot_create_temporary_objects`, `ops_10_temporary_privilege_through_set_role_is_refused`).

## Roller

| Rol | Ne için | Yapılandırma | Bağlantı sayısı |
|-----|---------|--------------|-----------------|
| **Şema sahibi** (ör. `authn_owner`; aynı zamanda **veritabanı sahibi** olmalı, aşağıya bakın) | yalnızca `rust-authentication migrate` ve `authn_apply_least_privilege` çağrısı | sunucu yapılandırmasında **yok**; migration'ı ayrı bir iş/CI adımı çalıştırır | — |
| **Uygulama rolü** (ör. `authn_app`) | `serve` ve CLI komutları; tüm modül tabloları | `database.url` | `database.max_connections` (varsayılan 20) |
| **Bakım rolü** (ör. `authn_maintenance`) | günlük audit saklama temizliği (`AuditService::run_maintenance`), zamanlanmış dış çıpa (`create_scheduled_checkpoint`, K-107) ve `audit-checkpoint` komutu | `database.maintenance_url` | `database.maintenance_max_connections` (varsayılan 2) |

`database.maintenance_url` verilmezse audit bakımı uygulama havuzuyla çalışır ve sunucu açılışta bir uyarı loglar. Bu yalnızca uygulama rolünün kısıtlanmadığı (ör. geliştirme) kurulumlar içindir: en az yetkili uygulama rolü `audit_events` satırı silemez, saklama temizliği ve zamanlanmış kontrol noktası da başarısız olur (`audit maintenance failed` / `audit chain checkpoint failed` loglanır, sunucu durmaz).

## Yetkiler

`authn_apply_least_privilege(app_role, maintenance_role)` önce iki rolün şemadaki **her tablo** üzerindeki tüm yetkilerini geri alır (ör. `GRANT ALL ON ALL TABLES` artığı kalmaz), sonra şunları verir:

| Tablolar | Uygulama rolü | Bakım rolü |
|----------|---------------|------------|
| Modül tabloları (aşağıdaki istisnalar dışında her tablo: `users`, `sessions`, `identities`, `oauth_states`, `oauth_token_revocations`, `admin_passkey_enrollments`, `admin_operation_leases`, `pending_registrations`, …) | `SELECT, INSERT, UPDATE, DELETE` | — |
| `admin_action_reasons`, `admin_reason_restrictions`, `admin_reason_restriction_periods` (ekleme-yalnızca; tetikleyici ayrıca `UPDATE`/`DELETE`/`TRUNCATE`'i reddeder) | `SELECT, INSERT` | — |
| `erasure_ledger` (silme defteri, K-108; 2902: uygulama yalnızca ekler, bir silmenin kaydı dışa aktarılmadan silinemez/değiştirilemez) | `SELECT, INSERT` | — |
| `admin_approvals` (K-66; değişmez kolonları tetikleyici korur, satırlar yalnızca kullanıcı silinince kaskadla gider) | `SELECT, INSERT, UPDATE` | — |
| `audit_events` | `SELECT, INSERT` | `SELECT, DELETE` (tetikleyici yalnızca `SET LOCAL authn.audit_purge_before` kaçış kapısıyla izin verir) |
| `audit_chain_checkpoints` | `SELECT` | `SELECT, INSERT` |
| `audit_chain_head` | `SELECT, UPDATE` | `SELECT` |
| `audit_subjects`, `audit_event_pii` | `SELECT, INSERT, DELETE` | `SELECT` (+ `audit_event_pii` üzerinde `DELETE`) |
| `outbox`, `webhook_endpoints`, `webhook_deliveries` | `SELECT, INSERT, UPDATE, DELETE` | `outbox`, `webhook_deliveries` üzerinde `SELECT, DELETE` |
| `audit_subject_view_holds` (K-62, migration `1701`) | authn-audit'in `authn_audit_apply_least_privilege` fonksiyonunun verdiği kadar | aynı |
| `_sqlx_migrations` | `SELECT` (hazır olma kontrolü şema sürümünü okur) | — |
| Şema | `USAGE` | `USAGE` |
| Diziler | `USAGE, SELECT` | — |
| Veritabanı: `TEMPORARY` (geçici tablo / fonksiyon, 2901) | **yok** (`PUBLIC`'ten de geri alınır) | **yok** |

Hiçbir rol `TRUNCATE`, `REFERENCES` veya `TRIGGER` almaz. Audit/outbox/webhook satırları authn-audit'in kendi fonksiyonundan gelir (`authn_audit_apply_least_privilege`, migration `1700`); `authn_apply_least_privilege` onu en sonda çağırır.

Kaskadlar (ör. bir audit olayı saklama süresiyle silinince `admin_action_reasons` gerekçesinin de silinmesi) PostgreSQL'de referans veren tablonun **sahibinin** yetkisiyle çalışır; bakım rolünün o tablolarda yetkisi gerekmez (`adm_08_retention_purge_still_removes_justifications`).

## Kurulum

```sql
-- Şema sahibi olarak, bir kez:
CREATE ROLE authn_app LOGIN PASSWORD '...';
CREATE ROLE authn_maintenance LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE authn TO authn_app, authn_maintenance;
```

```bash
# Şema sahibiyle migration (her sürümde):
AUTHN__DATABASE__URL='postgres://authn_owner:...@db/authn?sslmode=verify-full' rust-authentication migrate
```

```sql
-- Şema sahibi olarak, her migration'dan SONRA (yeni tablolar da kapsansın; idempotent):
SELECT authn_apply_least_privilege('authn_app', 'authn_maintenance');
```

```toml
# Sunucu yapılandırması:
[database]
url = "postgres://authn_app:...@db/authn?sslmode=verify-full"
maintenance_url = "postgres://authn_maintenance:...@db/authn?sslmode=verify-full"
migrate_on_start = false        # uygulama rolü DDL yapamaz
```

Kurallar:

- Uygulama ve bakım rolleri **hiçbir tablonun sahibi olmamalı ve sahibin rolüne üye olmamalıdır** (sahip her yetkiye sahiptir, üyeleri de miras alır); fonksiyon bu durumda hata verir. İki rol aynı olamaz ve birbirine üye olamaz (uygulama rolü bakım rolünün `audit_events` `DELETE` yetkisini miras alırdı). Süper kullanıcı, `BYPASSRLS` ve `pg_read_all_data` / `pg_write_all_data` üyesi roller de reddedilir: hiçbir `GRANT`/`REVOKE` onları kısıtlamaz.
- Fonksiyon `SECURITY INVOKER`'dır (çağıranın, yani şema sahibinin yetkisiyle çalışır) ve migration anındaki `search_path`'i sabitler (`SET search_path FROM CURRENT`); tüm adlar şema niteliklidir. Çağıranın `search_path`'ine yerleştirilmiş aynı adlı bir nesne kullanılmaz.
- **Geçici nesne yok (2901, wave 6B):** `pg_temp` arama yolunda şemadan önce gelebildiği için geçici tablo/fonksiyon oluşturabilen bir rol, `SECURITY DEFINER` bir fonksiyonun ya da tetikleyicinin sahibinin yetkisiyle kendi kodunu çalıştırtabilir (K-77'de `chain_key_switch` tetikleyicisinde bulundu; o fonksiyon `1703`'te düzeltildi). Bu sınıfı kapatmak için fonksiyon veritabanı düzeyindeki `TEMPORARY` yetkisini iki rolden **ve `PUBLIC`'ten** geri alır (PostgreSQL bu yetkiyi varsayılan olarak `PUBLIC`'e verir). Sonuçlar: (1) fonksiyonu **veritabanı sahibi** (veya süper kullanıcı) çalıştırmalıdır; başkası çalıştırırsa PostgreSQL `PUBLIC` yetkisini geri almaz, fonksiyon bunu denetler ve `role … can still create temporary objects` hatasıyla durur (ipucu, veritabanı sahibinin çalıştıracağı `REVOKE` komutunu verir). (2) Rollerden biri `TEMPORARY`'yi başka bir rol üyeliğiyle alıyorsa da hata verir; üyelik `WITH INHERIT FALSE` (veya rol `NOINHERIT`) olsa bile, çünkü rol `SET ROLE` ile o role geçip geçici nesne oluşturabilir ve nesne `RESET ROLE`'dan sonra da oturumun `pg_temp`'inde kalır (denetim, rolün üyesi olduğu her rolü kendisi dahil tarar). (3) Veritabanı bu servise ayrılmış olmalıdır; aynı veritabanında geçici tablo isteyen başka bir rol varsa ona açıkça `GRANT TEMPORARY ON DATABASE … TO …` verin (uygulama ve bakım rollerine asla). Uygulama geçici nesne kullanmaz.
- `migrate_on_start = true` en az yetkili kurulumda kullanılamaz (uygulama rolü şemayı değiştiremez); migration ayrı adımdır.
- Yeni bir sürüm tablo eklediyse fonksiyon yeniden çalıştırılmadıkça uygulama rolü o tabloya erişemez (güvenli taraf: hata, sessiz yetki değil). Dağıtım hattına "migrate → apply_least_privilege → serve" sırasını koyun.
- Sırlar (`database.url`, `maintenance_url`) ortam değişkeni veya secret mount ile verilir (`AUTHN__DATABASE__URL`, `AUTHN__DATABASE__MAINTENANCE_URL`); loglara ve hata mesajlarına girmez.

## Doğrulama

```sql
SELECT has_table_privilege('authn_app', 'audit_events', 'DELETE');        -- false
SELECT has_table_privilege('authn_app', 'admin_action_reasons', 'UPDATE'); -- false
SELECT has_table_privilege('authn_maintenance', 'users', 'SELECT');        -- false
SELECT has_database_privilege('authn_app', current_database(), 'TEMPORARY'); -- false
SELECT has_database_privilege('authn_maintenance', current_database(), 'TEMPORARY'); -- false
```

```sql
-- Miras alınan yetki yok (hepsi false olmalı; fonksiyon zaten reddeder):
SELECT pg_has_role('authn_app', 'authn_owner', 'MEMBER');
SELECT pg_has_role('authn_app', 'authn_maintenance', 'MEMBER');
SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = 'authn_app';
```

Otomatik doğrulama: `cargo test -p authn-server --test least_privilege` (gerçek PostgreSQL'de iki geçici rol oluşturur, yetkileri tek tek denetler, uygulamayı uygulama rolüyle — giriş, temizlik işleri, çevrimdışı admin işlemi, tam hesap silme — ve audit bakımını bakım rolüyle çalıştırır; üyelik/süper kullanıcı/`search_path` reddini ve iki rolün de `CREATE TEMP TABLE` / `pg_temp` fonksiyonu oluşturamadığını dener).
