# Sayfalama (DOC-04)

Kaynak: `crates/authn-core/src/domain/pagination.rs` (`PageRequest`, `Cursor`, `Page`). Listeleme uçları `OFFSET` kullanmaz; **keyset (imleç) sayfalaması** yapar.

## İstek

| Sorgu parametresi | Anlam |
|-------------------|-------|
| `limit` | Sayfa boyutu. Varsayılan **20**, en fazla **100**; aralık dışı değerler hata vermez, `1..=100`'e kıstırılır |
| `cursor` | Önceki sayfanın `next_cursor` değeri, olduğu gibi |

## Yanıt

```json
{ "items": [ … ], "next_cursor": "AQAAAZL…" }
```

- `next_cursor` yalnızca devamı varsa bulunur; **son sayfada alan hiç yoktur** (`null` değil, eksik).
- Sıralama uca göre değişir (aşağıdaki tablo); eşitlikte satır kimliği belirleyicidir. Keyset sayfalaması sayesinde sayfalar arasında eklenen/silinen satırlar diğer satırları kaydırmaz, yinelenme veya atlama olmaz.
- İmleç opaktır: `base64url(sürüm ‖ sıralama anahtarı ‖ satır kimliği)`, en fazla 64 karakter. Biçimi bozuk imleç `422 validation_failed`. İmleç bütünlük korumalı **değildir**; her sorgu kendi kiracı/sahip filtresini ayrıca uygular, yani başka bir kiracının imleci veri açmaz.
- Toplam sayı (`total`) döndürülmez.

## Sayfalı uçlar

| Uç | Sıra | Ek filtreler |
|----|------|--------------|
| `GET /v1/orgs` | en eski önce (oluşturma) | — |
| `GET /v1/orgs/{org_id}/members` | en eski önce (oluşturma) | — |
| `GET /v1/orgs/{org_id}/invitations` | en eski önce (oluşturma) | — |
| `GET /v1/orgs/{org_id}/api-keys` | en eski önce (oluşturma) | — |
| `GET /v1/orgs/{org_id}/service-accounts` | en eski önce (oluşturma) | — |
| `GET /v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` | en yeni önce | — |
| `GET /v1/orgs/{org_id}/audit-events` | en yeni önce | `kind`, `category`, `outcome` (`success` / `failure`), `actor_user_id`, `resource_type`, `since`, `until` (RFC 3339; `since` dahil, `until` hariç) |
| `GET /v1/me/security-events` | en yeni önce | — (pencere `audit.user_visible_window`, varsayılan 90 gün) |
| `GET /v1/admin/users` | en yeni önce | `email`, `status`, `platform_admin`, `email_verified`, `created_after`, `created_before` |
| `GET /v1/admin/audit-events` | en yeni önce | organizasyon filtrelerine ek `subject_user_id`, `org_id` |

`POST /v1/admin/audit-events/export` aynı filtreleri gövdede alır, sunucu tarafında 100'lük sayfalarla en fazla yapılandırılmış üst sınır kadar olay toplar ve kalanı için `next_cursor` döner.

Sayfasız listeler (ör. `GET /v1/me/sessions`, `GET /v1/me/passkeys`, `GET /v1/orgs/{org_id}/roles`, `GET /v1/orgs/{org_id}/domains`, `GET /v1/orgs/{org_id}/webhooks`) kullanıcı/organizasyon başına yapılandırma sınırlarıyla küçük tutulur (ör. `webauthn.max_credentials_per_user`, `org.limits.*`, `audit.webhooks.max_endpoints_per_org`).

## Örnek

```bash
curl -s "https://auth.example.com/v1/orgs/$ORG/members?limit=50" -H "Authorization: Bearer $AT"
# → {"items":[…], "next_cursor":"AQAAAZL…"}
curl -s "https://auth.example.com/v1/orgs/$ORG/members?limit=50&cursor=AQAAAZL…" -H "Authorization: Bearer $AT"
```
