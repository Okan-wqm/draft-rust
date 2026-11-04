use std::path::Path;

use authn_core::config::notify::NotifyConfig;
use authn_core::domain::{EmailAddress, Locale, PhoneNumber};
use authn_core::ports::{
    Notification, NotificationKind, Recipient, SmsNotification, SmsNotificationKind,
};
use authn_core::secret::SensitiveString;
use time::{Duration, OffsetDateTime};
use url::Url;

use super::*;

const BASE: &str = "https://auth.test.example";
const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
}

fn renderer() -> TemplateRenderer {
    TemplateRenderer::new(&NotifyConfig::default(), &Url::parse(BASE).unwrap()).unwrap()
}

fn renderer_with_overrides(dir: &Path) -> Result<TemplateRenderer, NotifyError> {
    let config = NotifyConfig {
        template_dir: Some(dir.to_path_buf()),
        ..NotifyConfig::default()
    };
    TemplateRenderer::new(&config, &Url::parse(BASE).unwrap())
}

fn notification(locale: Locale, name: Option<&str>, kind: NotificationKind) -> Notification {
    Notification {
        recipient: Recipient {
            email: EmailAddress::parse("ada@example.com").unwrap(),
            user_id: None,
            display_name: name.map(str::to_owned),
        },
        locale,
        kind,
    }
}

fn invitation(org_name: &str, inviter: &str) -> NotificationKind {
    NotificationKind::Invitation {
        org_name: org_name.to_owned(),
        inviter_name: Some(inviter.to_owned()),
        token: SensitiveString::new(TOKEN),
        expires_at: now() + Duration::days(7),
    }
}

fn write(dir: &Path, name: &str, contents: &str) {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

#[test]
fn ntf_01_every_notification_kind_renders_in_turkish_and_english() {
    let renderer = renderer();
    for locale in LOCALES {
        let samples = context::samples(locale, now());
        let names: Vec<&str> = samples.iter().map(|n| n.kind.template_name()).collect();
        assert_eq!(names, EMAIL_TEMPLATES, "a sample for every kind, in order");
        for n in &samples {
            let rendered = renderer.render_email(n, now()).unwrap();
            let label = format!("{locale}/{}", n.kind.template_name());
            assert!(!rendered.subject.is_empty(), "{label}");
            assert!(sanitize::is_header_safe(&rendered.subject), "{label}");
            assert!(rendered.text.len() > 80, "{label}: {}", rendered.text);
            assert!(
                rendered
                    .html
                    .contains(&format!("<html lang=\"{}\">", locale.as_str())),
                "{label}"
            );
            assert!(rendered.html.contains("Ada Lovelace"), "{label}: greeting");
            for output in [&rendered.subject, &rendered.text, &rendered.html] {
                assert!(
                    !output.contains("{{") && !output.contains("{%"),
                    "{label}: unrendered template syntax"
                );
            }
        }
    }
}

#[test]
fn ntf_01_turkish_and_english_texts_are_both_translated() {
    let renderer = renderer();
    let en = context::samples(Locale::En, now());
    let tr = context::samples(Locale::Tr, now());
    for (en, tr) in en.iter().zip(&tr) {
        let en = renderer.render_email(en, now()).unwrap();
        let tr = renderer.render_email(tr, now()).unwrap();
        assert_ne!(en.subject, tr.subject);
        assert_ne!(en.text, tr.text);
        assert!(en.text.starts_with("Hello Ada Lovelace,"), "{}", en.text);
        assert!(tr.text.starts_with("Merhaba Ada Lovelace,"), "{}", tr.text);
    }
}

#[test]
fn ntf_01_links_codes_and_validity_appear_in_both_bodies() {
    let renderer = renderer();
    let n = notification(
        Locale::En,
        None,
        NotificationKind::PasswordReset {
            token: SensitiveString::new(TOKEN),
            code: Some(SensitiveString::new("135790")),
            expires_at: now() + Duration::minutes(30),
        },
    );
    let rendered = renderer.render_email(&n, now()).unwrap();
    let link = format!("{BASE}/reset-password#token={TOKEN}");
    assert!(rendered.text.contains(&link), "{}", rendered.text);
    assert!(rendered.text.contains("135790"));
    assert!(rendered.text.contains("expire in 30 minutes"));
    assert!(rendered.text.starts_with("Hello,"));
    assert_eq!(rendered.subject, "Reset your password");
    // In HTML the link sits in an (escaped) href attribute.
    assert!(
        rendered
            .html
            .contains("href=\"https:&#x2f;&#x2f;auth.test.example&#x2f;reset-password#token=")
    );
    assert!(rendered.html.contains(TOKEN));
    assert!(rendered.html.contains("135790"));
    // The code never appears in the subject (lock-screen previews).
    assert!(!rendered.subject.contains("135790"));
    // Debug output never shows bodies.
    let debug = format!("{rendered:?}");
    assert!(!debug.contains(TOKEN) && !debug.contains("135790"));
}

#[test]
fn ntf_02_expiry_is_computed_at_render_time() {
    let renderer = renderer();
    let n = notification(
        Locale::Tr,
        None,
        NotificationKind::MagicLink {
            token: SensitiveString::new(TOKEN),
            expires_at: now() + Duration::minutes(15),
        },
    );
    let early = renderer.render_email(&n, now()).unwrap();
    assert!(early.text.contains("15 dakika boyunca"), "{}", early.text);
    let late = renderer
        .render_email(&n, now() + Duration::minutes(10))
        .unwrap();
    assert!(late.text.contains("5 dakika boyunca"), "{}", late.text);
}

#[test]
fn ntf_02_user_values_are_html_escaped() {
    let renderer = renderer();
    let n = notification(
        Locale::En,
        Some("<script>alert(1)</script>"),
        invitation(
            "\"><img src=x onerror=alert(1)>",
            "<b onmouseover=alert(2)>Mallory</b>",
        ),
    );
    let rendered = renderer.render_email(&n, now()).unwrap();
    for raw in ["<script", "<img", "<b onmouseover", "onerror=alert(1)>"] {
        assert!(!rendered.html.contains(raw), "{raw} must be escaped");
    }
    assert!(rendered.html.contains("&lt;script&gt;"));
    assert!(rendered.html.contains("&lt;img src=x"));
}

#[test]
fn ntf_02_values_are_data_not_template_source() {
    let renderer = renderer();
    let n = notification(
        Locale::En,
        Some("{{ 7*7 }} {% for x in range(3) %}x{% endfor %}"),
        invitation("{{ app_name }}", "{{ link }}"),
    );
    let rendered = renderer.render_email(&n, now()).unwrap();
    assert!(
        rendered
            .text
            .contains("Hello {{ 7*7 }} {% for x in range(3) %}x{% endfor %},")
    );
    assert!(!rendered.text.contains("49"));
    assert!(rendered.text.contains("“{{ app_name }}”"));
}

#[test]
fn ntf_02_links_point_only_to_the_public_base_url() {
    let renderer = renderer();
    let n = notification(
        Locale::En,
        Some("https://evil.example/login"),
        invitation("Visit https://evil.example now", "http://attacker.example"),
    );
    let rendered = renderer.render_email(&n, now()).unwrap();
    for body in [&rendered.text, &rendered.subject] {
        let body = body.replace("[://]", "[defanged]");
        for (index, part) in body.split("://").enumerate().skip(1) {
            assert!(
                part.starts_with("auth.test.example/"),
                "foreign URL #{index} in: {body}"
            );
        }
    }
    assert!(rendered.text.contains("https[://]evil.example"));
    for part in rendered.html.split("href=\"").skip(1) {
        assert!(
            part.starts_with("https:&#x2f;&#x2f;auth.test.example&#x2f;"),
            "{part}"
        );
    }
}

#[test]
fn ntf_02_subject_lines_cannot_inject_headers() {
    let renderer = renderer();
    let n = notification(
        Locale::En,
        Some("Ada\r\nBcc: victim@example.com"),
        invitation("Acme\r\nBcc: victim@example.com\u{202E}", "x"),
    );
    let rendered = renderer.render_email(&n, now()).unwrap();
    assert!(
        sanitize::is_header_safe(&rendered.subject),
        "{:?}",
        rendered.subject
    );
    assert!(!rendered.subject.contains('\n') && !rendered.subject.contains('\r'));
    assert!(rendered.subject.contains("Acme Bcc: victim@example.com"));
    // The plain-text body cannot gain extra lines either.
    assert!(rendered.text.contains("Hello Ada Bcc: victim@example.com,"));
}

#[test]
fn ntf_02_untrusted_values_are_length_capped() {
    let renderer = renderer();
    let n = notification(
        Locale::En,
        Some(&"A".repeat(5000)),
        invitation(&"O".repeat(5000), "x"),
    );
    let rendered = renderer.render_email(&n, now()).unwrap();
    assert!(rendered.subject.chars().count() <= sanitize::MAX_SUBJECT_CHARS);
    assert!(
        !rendered
            .text
            .contains(&"A".repeat(sanitize::MAX_NAME_CHARS + 1))
    );
    assert!(
        !rendered
            .text
            .contains(&"O".repeat(sanitize::MAX_ORG_NAME_CHARS + 1))
    );
}

#[test]
fn ntf_02_malformed_tokens_and_codes_are_refused() {
    let renderer = renderer();
    let bad_token = notification(
        Locale::En,
        None,
        NotificationKind::MagicLink {
            token: SensitiveString::new("abc/../../evil.example?x="),
            expires_at: now() + Duration::minutes(15),
        },
    );
    assert_eq!(
        renderer.render_email(&bad_token, now()).unwrap_err(),
        RenderError::InvalidToken
    );
    for code in ["12ab56", "12345", "12345678901", "１２３４５６"] {
        let bad_code = notification(
            Locale::En,
            None,
            NotificationKind::LoginCode {
                code: SensitiveString::new(code),
                expires_at: now() + Duration::minutes(10),
            },
        );
        assert_eq!(
            renderer.render_email(&bad_code, now()).unwrap_err(),
            RenderError::InvalidCode,
            "{code}"
        );
    }
}

#[test]
fn ntf_02_dates_are_rendered_in_utc_per_locale() {
    let renderer = renderer();
    let at = time::macros::datetime!(2026-11-01 14:05 UTC);
    for (locale, expected) in [
        (Locale::En, "1 November 2026, 14:05 UTC"),
        (Locale::Tr, "1 Kasım 2026 14:05 (UTC)"),
    ] {
        let n = notification(
            locale,
            None,
            NotificationKind::PasswordChanged {
                at,
                ip_masked: None,
                device: None,
            },
        );
        let rendered = renderer.render_email(&n, at).unwrap();
        assert!(rendered.text.contains(expected), "{}", rendered.text);
        // Optional details are omitted, not printed as "none".
        assert!(!rendered.text.to_lowercase().contains("none"));
    }
}

#[test]
fn ntf_04_sms_texts_render_in_both_locales_with_origin_bound_code() {
    let renderer = renderer();
    for locale in LOCALES {
        for kind in [
            SmsNotificationKind::MfaSmsCode {
                code: SensitiveString::new("975310"),
                expires_at: now() + Duration::minutes(10),
            },
            SmsNotificationKind::PhoneVerification {
                code: SensitiveString::new("975310"),
                expires_at: now() + Duration::minutes(10),
            },
        ] {
            let sms = SmsNotification {
                to: PhoneNumber::parse("+905551112233").unwrap(),
                user_id: None,
                locale,
                kind,
            };
            let text = renderer.render_sms(&sms, now()).unwrap();
            let text = text.expose();
            assert!(text.contains("975310"));
            assert!(text.ends_with("\n@auth.test.example #975310"), "{text}");
            assert!(text.chars().count() <= MAX_SMS_CHARS);
            assert!(text.contains(if locale == Locale::Tr {
                "10 dakika"
            } else {
                "10 minutes"
            }));
        }
    }
}

#[test]
fn ntf_02_templates_can_be_overridden_from_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "en/email/magic_link.subject.txt",
        "Sign in to {{ app_name }} now",
    );
    write(
        dir.path(),
        "tr/sms/mfa_sms_code.txt",
        "Kod: {{ code }}\n@{{ domain }} #{{ code }}",
    );
    write(dir.path(), ".DS_Store", "ignored");
    let renderer = renderer_with_overrides(dir.path()).unwrap();
    assert_eq!(renderer.overridden().len(), 2);
    let n = notification(
        Locale::En,
        None,
        NotificationKind::MagicLink {
            token: SensitiveString::new(TOKEN),
            expires_at: now() + Duration::minutes(15),
        },
    );
    assert_eq!(
        renderer.render_email(&n, now()).unwrap().subject,
        "Sign in to rust-authentication now"
    );
}

#[test]
fn ntf_02_invalid_override_directories_fail_at_startup() {
    let cases: [(&str, &str, &str); 11] = [
        (
            "en/email/invitation.html",
            "{% extends \"en/email/layout.html\" %}{% block content %}{% include \"en/email/invitation.txt\" %}{% endblock %}",
            "no include/import",
        ),
        (
            "en/email/invitation.html",
            "{% extends \"en/email/layout.txt\" %}",
            "same kind",
        ),
        (
            "en/email/invitation.html",
            "{% extends layout_name %}",
            "same kind",
        ),
        (
            "en/email/invitation.html",
            "{%- filter safe -%}{{ org_name }}{%- endfilter -%}",
            "safe",
        ),
        (
            "en/email/magic_lnk.txt",
            "typo",
            "not a known template name",
        ),
        ("de/email/magic_link.txt", "x", "not a known template name"),
        (
            "en/email/invitation.html",
            "{% extends \"en/email/layout.html\" %}{% block content %}{{ org_name|safe }}{% endblock %}",
            "safe",
        ),
        (
            "en/email/invitation.html",
            "{% autoescape false %}{{ org_name }}{% endautoescape %}",
            "auto-escaping",
        ),
        (
            "en/email/login_code.subject.txt",
            "{% if %}",
            "login_code.subject.txt",
        ),
        (
            "en/email/login_code.subject.txt",
            "Code for {{ nonexistent_variable }}",
            "login_code",
        ),
        (
            "en/email/password_reset.txt",
            "Somebody wants to reset your password.",
            "must contain the link",
        ),
    ];
    for (name, contents, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), name, contents);
        let err = renderer_with_overrides(dir.path()).unwrap_err().to_string();
        assert!(err.contains(expected), "{name}: {err}");
    }
}

#[test]
fn ntf_02_override_that_drops_the_code_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "tr/sms/phone_verification.txt",
        "Telefonunuzu doğrulayın.",
    );
    let err = renderer_with_overrides(dir.path()).unwrap_err().to_string();
    assert!(err.contains("must show the code"), "{err}");
}

#[test]
fn ntf_02_runaway_override_templates_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "en/email/mfa_reset.subject.txt",
        "{% for i in range(10000) %}{% for j in range(10000) %}x{% endfor %}{% endfor %}",
    );
    let err = renderer_with_overrides(dir.path()).unwrap_err().to_string();
    assert!(err.contains("mfa_reset"), "{err}");
}

#[test]
fn ntf_02_oversized_override_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "en/email/mfa_reset.subject.txt",
        &"x".repeat(usize::try_from(MAX_TEMPLATE_BYTES).unwrap() + 1),
    );
    let err = renderer_with_overrides(dir.path()).unwrap_err().to_string();
    assert!(err.contains("larger than 64 KiB"), "{err}");
}

#[test]
fn ntf_02_builtin_templates_never_disable_escaping() {
    for (name, source) in builtin::BUILTIN {
        check_forbidden_constructs(name, source).unwrap();
    }
    assert_eq!(
        template_names().len(),
        2 * (2 + 3 * EMAIL_TEMPLATES.len() + SMS_TEMPLATES.len())
    );
}

/// Security review: the escaping guard must not depend on whitespace or be
/// desynchronised by `{%` inside strings, and filters that emit
/// unescaped ("safe") markup must not be reachable by any spelling.
#[test]
fn ntf_02_escape_guards_cannot_be_bypassed_by_syntax_tricks() {
    let cases: [(&str, &str); 9] = [
        // No whitespace after the keyword.
        (
            "en/email/invitation.html",
            "{%autoescape(false)%}{{ org_name }} {{ link }}{%endautoescape%}",
        ),
        (
            "en/email/invitation.html",
            "{{ link }}{%include\"en/email/invitation.txt\"%}",
        ),
        (
            "en/email/invitation.html",
            "{%extends\"en/email/layout.txt\"%}",
        ),
        // `{%` inside a string literal used to hide the following tag.
        (
            "en/email/invitation.html",
            "{{ \"{%\" }}{% autoescape false %}{{ org_name }} {{ link }}{% endautoescape %}",
        ),
        // A computed `extends` target that ends in `.html` but may pick a
        // plain-text (unescaped) layout.
        (
            "en/email/invitation.html",
            "{% extends \"en/email/layout.txt\" if true else \"en/email/layout.html\" %}",
        ),
        // The `safe` filter reached by name through `map`.
        (
            "en/email/invitation.html",
            "{{ link }}{{ [org_name]|map(\"safe\")|join }}",
        ),
        // `tojson` output is marked safe but does not escape `\"`: it
        // breaks out of a double-quoted attribute.
        (
            "en/email/invitation.html",
            "<a title=\"{{ org_name|tojson }}\" href=\"{{ link }}\">x</a>",
        ),
        // `debug()` dumps the whole context (links, codes) anywhere.
        ("en/email/invitation.subject.txt", "{{ debug() }}"),
        (
            "en/email/invitation.html",
            "{% set s = \"safe\" %}{{ link }}{{ [org_name]|map(s)|join }}",
        ),
    ];
    for (name, contents) in cases {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), name, contents);
        assert!(
            renderer_with_overrides(dir.path()).is_err(),
            "{name} must be refused: {contents}"
        );
    }
}

/// Security review: subjects travel unencrypted through mail relays, show
/// on lock screens and appear in `Debug` output: an override must not be
/// able to put the link or the code there.
#[test]
fn ntf_02_subject_templates_cannot_reveal_links_or_codes() {
    for (name, contents) in [
        ("en/email/login_code.subject.txt", "Your code: {{ code }}"),
        ("tr/email/magic_link.subject.txt", "Giriş: {{ link }}"),
        (
            "en/email/password_reset.subject.txt",
            "{% if code %}Code {{ code }}{% endif %} reset",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), name, contents);
        let err = renderer_with_overrides(dir.path())
            .err()
            .unwrap_or_else(|| panic!("{name} must be refused"))
            .to_string();
        assert!(err.contains(name.trim_end_matches(".subject.txt")), "{err}");
    }
    // The built-in subjects keep rendering.
    let renderer = renderer();
    for locale in LOCALES {
        for n in context::samples(locale, now()) {
            let rendered = renderer.render_email(&n, now()).unwrap();
            let parts = context::secret_parts(&n.kind);
            for secret in parts.tokens.iter().chain(&parts.codes) {
                assert!(!rendered.subject.contains(secret.expose()));
            }
        }
    }
}

/// K-18, K-19, K-40: the new security notices render the provider (escaped)
/// and the reset link; `registration_attempt` covers sign-up and e-mail
/// change attempts in both languages.
#[test]
fn ntf_01_identity_passkey_clone_and_revert_notices() {
    let renderer = renderer();
    let linked = notification(
        Locale::En,
        None,
        NotificationKind::IdentityLinked {
            provider: "<b>Acme</b>".to_owned(),
            at: now(),
        },
    );
    let rendered = renderer.render_email(&linked, now()).unwrap();
    assert!(
        rendered.text.contains("<b>Acme</b> was linked"),
        "{}",
        rendered.text
    );
    assert!(
        !rendered.html.contains("<b>Acme</b>"),
        "provider must be escaped"
    );
    assert!(
        rendered.html.contains("&lt;b&gt;Acme&lt;&#x2f;b&gt;"),
        "{}",
        rendered.html
    );
    assert!(rendered.text.contains(&format!("{BASE}/")));

    let unlinked = notification(
        Locale::Tr,
        None,
        NotificationKind::IdentityUnlinked {
            provider: "Google".to_owned(),
            at: now(),
        },
    );
    let rendered = renderer.render_email(&unlinked, now()).unwrap();
    assert!(
        rendered.text.contains("Google kaldırıldı"),
        "{}",
        rendered.text
    );

    for (kind, en, tr) in [
        (
            NotificationKind::PasskeyCloneSuspected { at: now() },
            "may have been copied",
            "kopyalanmış olabileceğini",
        ),
        (
            NotificationKind::EmailChangeReverted { at: now() },
            "was reverted",
            "geri alındı",
        ),
    ] {
        let en_out = renderer
            .render_email(&notification(Locale::En, None, kind.clone()), now())
            .unwrap();
        let tr_out = renderer
            .render_email(&notification(Locale::Tr, None, kind), now())
            .unwrap();
        assert!(en_out.text.contains(en), "{}", en_out.text);
        assert!(tr_out.text.contains(tr), "{}", tr_out.text);
    }

    for (locale, signup, change) in [
        (
            Locale::En,
            "sign up",
            "change the address of another account",
        ),
        (Locale::Tr, "kaydolmak", "başka bir hesabın adresini"),
    ] {
        let out = renderer
            .render_email(
                &notification(locale, None, NotificationKind::RegistrationAttempt),
                now(),
            )
            .unwrap();
        assert!(out.text.contains(signup), "{}", out.text);
        assert!(out.text.contains(change), "{}", out.text);
    }
}
