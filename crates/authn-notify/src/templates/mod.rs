//! Message templates (NTF-01, NTF-02).
//!
//! * Every [`NotificationKind`](authn_core::ports::NotificationKind) has a subject, a plain-text and an HTML
//!   template in Turkish and English (`<locale>/email/<kind>.subject.txt`,
//!   `.txt`, `.html`, extending `<locale>/email/layout.{txt,html}`); every
//!   [`SmsNotificationKind`](authn_core::ports::SmsNotificationKind) has `<locale>/sms/<kind>.txt`.
//! * Templates are minijinja with **auto-escaping for `.html`** (decided by
//!   the file name, not by the template). Constructs that disable escaping
//!   (`|safe`, `{% autoescape %}`, `{% filter safe %}`) are refused, in the
//!   built-in templates and in overrides alike.
//! * Untrusted values are additionally neutralised before rendering
//!   ([`crate::sanitize`]): plain text, subjects and SMS have no escaping.
//! * Values are data, never template source: a display name of
//!   `{{ 7*7 }}` is printed literally.
//! * `notify.template_dir` may override any built-in file (same relative
//!   path). Unknown files are refused (typos would otherwise silently fall
//!   back to the built-in text). Every template is compiled and rendered
//!   with sample data at startup ([`TemplateRenderer::new`]); a template
//!   that drops the link or the code of its kind is refused.
//! * Undefined variables are errors (strict mode); rendering is bounded by
//!   minijinja fuel; debug output (which could echo values) is off and the
//!   `safe` / `tojson` filters and the `debug()` function are removed.
//! * Subject templates do not receive `link` and `code` (an override that
//!   tries to print them fails at startup).

mod builtin;
mod context;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use authn_core::config::AppConfig;
use authn_core::config::notify::NotifyConfig;
use authn_core::ports::{Notification, SmsNotification};
use authn_core::secret::SensitiveString;
use minijinja::syntax::SyntaxConfig;
use minijinja::{AutoEscape, Environment, UndefinedBehavior, Value};
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroize;

pub use self::builtin::{EMAIL_TEMPLATES, LOCALES, SMS_TEMPLATES};
use self::context::Rendered;
pub use self::context::deliver_before;
pub(crate) use self::context::{is_valid_code, secret_parts, sms_code, sms_deliver_before};
use crate::error::{NotifyError, RenderError};
use crate::links::LinkBuilder;
use crate::sanitize;

/// Largest accepted override file.
pub const MAX_TEMPLATE_BYTES: u64 = 64 * 1024;
/// Longest rendered SMS text (about three concatenated GSM segments).
pub const MAX_SMS_CHARS: usize = 480;
/// minijinja fuel per render (bounds loops in operator templates).
const FUEL_PER_RENDER: u64 = 100_000;
/// Variables withheld from subject templates: subjects travel through
/// relays unencrypted, appear on lock screens and in `Debug` output.
const SUBJECT_HIDDEN_VARIABLES: [&str; 2] = ["link", "code"];

/// A rendered e-mail. Bodies contain links and codes: they are redacted in
/// `Debug` and zeroized on drop.
pub struct RenderedEmail {
    /// Subject line (single line, sanitized, ≤ 200 characters).
    pub subject: String,
    /// Plain-text body.
    pub text: String,
    /// HTML body.
    pub html: String,
}

impl fmt::Debug for RenderedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderedEmail")
            .field("subject", &self.subject)
            .field("text_len", &self.text.len())
            .field("html_len", &self.html.len())
            .finish()
    }
}

impl Drop for RenderedEmail {
    fn drop(&mut self) {
        self.text.zeroize();
        self.html.zeroize();
    }
}

/// Renders notifications with the built-in or overridden templates.
pub struct TemplateRenderer {
    env: Environment<'static>,
    links: LinkBuilder,
    app_name: String,
    overridden: BTreeSet<String>,
}

impl fmt::Debug for TemplateRenderer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateRenderer")
            .field("links", &self.links)
            .field("app_name", &self.app_name)
            .field("overridden", &self.overridden)
            .finish_non_exhaustive()
    }
}

/// Every template file name this crate knows (built-ins and valid override
/// targets).
#[must_use]
pub fn template_names() -> Vec<&'static str> {
    builtin::BUILTIN.iter().map(|(name, _)| *name).collect()
}

fn auto_escape(name: &str) -> AutoEscape {
    if is_html(name) {
        AutoEscape::Html
    } else {
        AutoEscape::None
    }
}

/// The family of a template name: `.html` templates are HTML-escaped,
/// everything else is plain text.
fn is_html(name: &str) -> bool {
    name.ends_with(".html")
}

/// Built-in filters and functions removed from the environment: `safe` and
/// `tojson` return values marked as safe (`tojson` does not escape `"`, so
/// it breaks out of a quoted attribute), and `debug()` dumps the whole
/// context — links and codes included — into any template, subjects too.
/// Removing them is a runtime guarantee that no spelling (`|safe`,
/// `map("safe")`, a filter name held in a variable…) can reach them.
const REMOVED_FILTERS: [&str; 2] = ["safe", "tojson"];
/// See [`REMOVED_FILTERS`].
const REMOVED_GLOBALS: [&str; 1] = ["debug"];

/// The statement keyword that follows a `{%` opening (after the optional
/// whitespace-control sign and whitespace), and the rest of the source.
/// minijinja does not need whitespace between a keyword and its argument
/// (`{%include"x"%}`), so the keyword ends at the first character that
/// cannot be part of an identifier.
fn statement_keyword(after_open: &str) -> (&str, &str) {
    let rest = after_open.trim_start_matches(['-', '+']).trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    (
        rest.get(..end).unwrap_or_default(),
        rest.get(end..).unwrap_or_default(),
    )
}

/// Whether `argument` (the text between `extends` and `%}`) is exactly one
/// string literal naming a template of the same family as `name`.
fn is_same_family_literal(name: &str, argument: &str) -> bool {
    let argument = argument.trim_end_matches(['-', '+']).trim();
    let target = argument
        .strip_prefix('"')
        .and_then(|a| a.strip_suffix('"'))
        .or_else(|| {
            argument
                .strip_prefix('\'')
                .and_then(|a| a.strip_suffix('\''))
        });
    target.is_some_and(|target| {
        !target.is_empty()
            && target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
            && is_html(target) == is_html(name)
    })
}

/// Refuses constructs that could turn auto-escaping off:
///
/// * the `safe` filter (`|safe`, `{% filter safe %}`) and `{% autoescape %}`;
/// * `{% include %}`, `{% import %}`, `{% from %}` — an HTML template could
///   otherwise pull in a plain-text (unescaped) template;
/// * `{% extends %}` of a template of the other family or of a computed
///   name (only a single string literal is accepted).
///
/// **Every** `{%` of the source is inspected — also those inside comments,
/// string literals or raw blocks (false positives are acceptable, a missed
/// tag is not): a `{%` inside a string can therefore never hide the next
/// real tag. The removed filters ([`REMOVED_FILTERS`]) are the runtime
/// backstop for filter spellings this scan cannot see.
fn check_forbidden_constructs(name: &str, source: &str) -> Result<(), NotifyError> {
    let safe_rule = "the `safe` filter is not allowed (values must stay escaped)";
    let compact: String = source
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.contains("|safe") {
        return Err(NotifyError::template(name, safe_rule));
    }
    let mut rest = source;
    while let Some(open) = rest.find("{%") {
        let after = rest.get(open + 2..).unwrap_or_default();
        // Advance past this opening only, never past the closing `%}`: a
        // `%}` inside a string literal must not swallow the next tag.
        rest = after;
        let (keyword, tail) = statement_keyword(after);
        let argument = tail
            .find("%}")
            .map_or(tail, |close| tail.get(..close).unwrap_or_default().trim());
        match keyword.to_ascii_lowercase().as_str() {
            "autoescape" | "endautoescape" => {
                return Err(NotifyError::template(
                    name,
                    "changing auto-escaping is not allowed",
                ));
            }
            "include" | "import" | "from" => {
                return Err(NotifyError::template(
                    name,
                    "only `extends` may reference other templates (no include/import)",
                ));
            }
            "filter" if argument.to_ascii_lowercase().contains("safe") => {
                return Err(NotifyError::template(name, safe_rule));
            }
            "extends" if !is_same_family_literal(name, argument) => {
                return Err(NotifyError::template(
                    name,
                    "`extends` must name a literal template of the same kind (.html or .txt)",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn read_template(path: &Path, name: &str) -> Result<String, NotifyError> {
    let io_err = |source| NotifyError::Io {
        path: path.to_path_buf(),
        source,
    };
    let metadata = std::fs::metadata(path).map_err(io_err)?;
    if !metadata.is_file() {
        return Err(NotifyError::template(name, "is not a regular file"));
    }
    if metadata.len() > MAX_TEMPLATE_BYTES {
        return Err(NotifyError::template(name, "is larger than 64 KiB"));
    }
    let bytes = std::fs::read(path).map_err(io_err)?;
    String::from_utf8(bytes).map_err(|_| NotifyError::template(name, "is not valid UTF-8"))
}

/// Collects `(name, source)` for every file under `dir`, refusing names that
/// are not known templates. Hidden entries (`.…`) are ignored.
fn load_overrides(dir: &Path) -> Result<Vec<(String, String)>, NotifyError> {
    let known: BTreeSet<&str> = template_names().into_iter().collect();
    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(dir.to_path_buf(), String::new(), 0)];
    while let Some((path, prefix, depth)) = stack.pop() {
        let entries = std::fs::read_dir(&path).map_err(|source| NotifyError::Io {
            path: path.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| NotifyError::Io {
                path: path.clone(),
                source,
            })?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                return Err(NotifyError::template(
                    &prefix,
                    "contains a file name that is not valid UTF-8",
                ));
            };
            if file_name.starts_with('.') {
                continue;
            }
            let name = if prefix.is_empty() {
                file_name.to_owned()
            } else {
                format!("{prefix}/{file_name}")
            };
            let entry_path = entry.path();
            if entry_path.is_dir() {
                if depth >= 2 {
                    return Err(NotifyError::template(&name, "unexpected directory"));
                }
                stack.push((entry_path, name, depth + 1));
                continue;
            }
            if !known.contains(name.as_str()) {
                return Err(NotifyError::template(
                    &name,
                    "is not a known template name (expected <locale>/email/<kind>.{subject.txt,txt,html} or <locale>/sms/<kind>.txt)",
                ));
            }
            let source = read_template(&entry_path, &name)?;
            found.push((name, source));
        }
    }
    Ok(found)
}

impl TemplateRenderer {
    /// Builds the renderer from `[notify]` and `server.public_base_url`,
    /// loads overrides and validates every template (fail-fast).
    pub fn from_config(config: &AppConfig) -> Result<Self, NotifyError> {
        Self::new(&config.notify, &config.server.public_base_url)
    }

    /// Builds the renderer from the notify section and the public base URL.
    pub fn new(config: &NotifyConfig, public_base_url: &Url) -> Result<Self, NotifyError> {
        let links = LinkBuilder::new(public_base_url, &config.links)?;
        let mut env = Environment::new();
        env.set_debug(false);
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        env.set_auto_escape_callback(auto_escape);
        env.set_fuel(Some(FUEL_PER_RENDER));
        for filter in REMOVED_FILTERS {
            env.remove_filter(filter);
        }
        for global in REMOVED_GLOBALS {
            env.remove_global(global);
        }
        env.set_syntax(
            SyntaxConfig::builder()
                .trim_blocks(true)
                .lstrip_blocks(true)
                .build()
                .map_err(|e| NotifyError::config(format!("template syntax: {e}")))?,
        );
        let overrides = match &config.template_dir {
            Some(dir) => load_overrides(dir)?,
            None => Vec::new(),
        };
        let overridden: BTreeSet<String> = overrides.iter().map(|(n, _)| n.clone()).collect();
        for (name, source) in builtin::BUILTIN {
            if overridden.contains(*name) {
                continue;
            }
            check_forbidden_constructs(name, source)?;
            env.add_template(name, source)
                .map_err(|e| NotifyError::template(name, e.to_string()))?;
        }
        for (name, source) in overrides {
            check_forbidden_constructs(&name, &source)?;
            env.add_template_owned(name.clone(), source)
                .map_err(|e| NotifyError::template(&name, e.to_string()))?;
        }
        let renderer = Self {
            env,
            links,
            app_name: sanitize::header_value(&config.app_name, 64),
            overridden,
        };
        renderer.validate()?;
        Ok(renderer)
    }

    /// Template files replaced by the override directory.
    #[must_use]
    pub fn overridden(&self) -> &BTreeSet<String> {
        &self.overridden
    }

    /// The link builder.
    #[must_use]
    pub fn links(&self) -> &LinkBuilder {
        &self.links
    }

    /// Renders every e-mail and SMS kind in every locale with sample data
    /// and checks that links and codes survive (called by [`Self::new`]).
    pub fn validate(&self) -> Result<(), NotifyError> {
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        for locale in LOCALES {
            for notification in context::samples(locale, now) {
                let template = notification.kind.template_name();
                let name = format!("{}/email/{template}", locale.as_str());
                let rendered = self
                    .render_email(&notification, now)
                    .map_err(|e| NotifyError::template(&name, e.to_string()))?;
                let parts = context::secret_parts(&notification.kind);
                for token in &parts.tokens {
                    if !rendered.text.contains(token.expose())
                        || !rendered.html.contains(token.expose())
                    {
                        return Err(NotifyError::template(
                            &name,
                            "the text and HTML bodies must contain the link",
                        ));
                    }
                }
                for code in &parts.codes {
                    if !rendered.text.contains(code.expose())
                        || !rendered.html.contains(code.expose())
                    {
                        return Err(NotifyError::template(
                            &name,
                            "the text and HTML bodies must show the code",
                        ));
                    }
                }
            }
            for sms in context::sms_samples(locale, now) {
                let name = format!("{}/sms/{}.txt", locale.as_str(), sms.kind.template_name());
                let text = self
                    .render_sms(&sms, now)
                    .map_err(|e| NotifyError::template(&name, e.to_string()))?;
                let code = context::sms_code(&sms.kind);
                if !text.expose().contains(code.expose()) {
                    return Err(NotifyError::template(&name, "the SMS must show the code"));
                }
            }
        }
        Ok(())
    }

    fn render(&self, name: &str, ctx: &Value) -> Result<String, RenderError> {
        let template = self
            .env
            .get_template(name)
            .map_err(|e| RenderError::template(name, &e))?;
        template
            .render(ctx)
            .map_err(|e| RenderError::template(name, &e))
    }

    /// Renders an e-mail notification. `now` is the delivery time (used for
    /// "expires in …").
    pub fn render_email(
        &self,
        notification: &Notification,
        now: OffsetDateTime,
    ) -> Result<RenderedEmail, RenderError> {
        let Rendered { mut values } =
            context::email_values(notification, &self.links, &self.app_name, now)?;
        let base = format!(
            "{}/email/{}",
            notification.locale.as_str(),
            notification.kind.template_name()
        );
        // Subjects never see the secrets: with strict undefined handling an
        // override that prints the link or the code fails at startup.
        let subject_values: BTreeMap<&'static str, Value> = values
            .iter()
            .filter(|(key, _)| !SUBJECT_HIDDEN_VARIABLES.contains(*key))
            .map(|(key, value)| (*key, value.clone()))
            .collect();
        let subject_raw =
            self.render(&format!("{base}.subject.txt"), &Value::from(subject_values))?;
        let subject = sanitize::header_value(&subject_raw, sanitize::MAX_SUBJECT_CHARS);
        if subject.is_empty() {
            return Err(RenderError::EmptySubject);
        }
        values.insert("subject", Value::from(subject.clone()));
        let ctx = Value::from(values);
        let text = sanitize::text_body(&self.render(&format!("{base}.txt"), &ctx)?);
        let html = self.render(&format!("{base}.html"), &ctx)?;
        Ok(RenderedEmail {
            subject,
            text,
            html,
        })
    }

    /// Renders an SMS text (≤ [`MAX_SMS_CHARS`] characters).
    pub fn render_sms(
        &self,
        sms: &SmsNotification,
        now: OffsetDateTime,
    ) -> Result<SensitiveString, RenderError> {
        let Rendered { values } = context::sms_values(sms, self.links.host(), &self.app_name, now)?;
        let name = format!(
            "{}/sms/{}.txt",
            sms.locale.as_str(),
            sms.kind.template_name()
        );
        let text = sanitize::text_body(&self.render(&name, &Value::from(values))?);
        let length = text.chars().count();
        if length == 0 || length > MAX_SMS_CHARS {
            return Err(RenderError::SmsLength { max: MAX_SMS_CHARS });
        }
        Ok(SensitiveString::new(text))
    }
}

#[cfg(test)]
mod tests;
