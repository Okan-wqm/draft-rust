//! Human-readable device descriptions for notifications and
//! `known_devices.device_name` (RSK-04).

/// Longest description stored (`known_devices_name_check`).
pub const MAX_DEVICE_NAME_CHARS: usize = 128;

/// "Firefox on Linux", "Safari on iOS", … or "Unknown device". The input is
/// the sanitized user agent of the request context (≤ 512 bytes); the
/// output contains only characters from woothee's fixed vocabulary or the
/// fallback, never raw attacker-controlled text.
#[must_use]
pub fn describe(user_agent: Option<&str>) -> String {
    let parsed = user_agent.and_then(|ua| woothee::parser::Parser::new().parse(ua));
    let description = match parsed {
        Some(r) if r.name != "UNKNOWN" && r.os != "UNKNOWN" => format!("{} on {}", r.name, r.os),
        Some(r) if r.name != "UNKNOWN" => r.name.to_owned(),
        Some(r) if r.os != "UNKNOWN" => r.os.to_owned(),
        _ => "Unknown device".to_owned(),
    };
    description.chars().take(MAX_DEVICE_NAME_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsk_04_user_agents_are_described() {
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
        assert_eq!(describe(Some(firefox)), "Firefox on Linux");
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(describe(Some(iphone)), "Safari on iPhone");
        assert_eq!(describe(None), "Unknown device");
        assert_eq!(
            describe(Some("<script>alert(1)</script>")),
            "Unknown device"
        );
    }
}
