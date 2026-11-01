//! Localized (TR/EN) feedback for the password policy (PWD-04).
//!
//! zxcvbn only produces English text; its warnings and suggestions are
//! enums, mapped here to static Turkish and English strings so the API never
//! returns library-generated text.

use authn_core::domain::Locale;
use authn_core::ports::PasswordViolation;
use zxcvbn::feedback::{Suggestion, Warning};

/// Picks the string of `locale`.
const fn pick(locale: Locale, en: &'static str, tr: &'static str) -> &'static str {
    match locale {
        Locale::En => en,
        Locale::Tr => tr,
    }
}

/// Message explaining a policy violation.
#[must_use]
pub fn violation_message(violation: PasswordViolation, locale: Locale) -> String {
    match violation {
        PasswordViolation::TooShort { min } => match locale {
            Locale::En => format!("Use at least {min} characters."),
            Locale::Tr => format!("En az {min} karakter kullanın."),
        },
        PasswordViolation::TooLong { max } => match locale {
            Locale::En => format!("Use at most {max} characters."),
            Locale::Tr => format!("En fazla {max} karakter kullanın."),
        },
        PasswordViolation::Breached => pick(
            locale,
            "This password has appeared in a data breach and must not be used.",
            "Bu şifre bir veri ihlalinde ortaya çıkmış; kullanılmamalıdır.",
        )
        .to_owned(),
        PasswordViolation::TooWeak { .. } => pick(
            locale,
            "This password is too easy to guess.",
            "Bu şifre çok kolay tahmin edilebilir.",
        )
        .to_owned(),
    }
}

/// Message shown when the password contains the e-mail address, the
/// display name or the service name.
#[must_use]
pub fn user_input_message(locale: Locale) -> &'static str {
    pick(
        locale,
        "Avoid your e-mail address, your name and the name of this service.",
        "E-posta adresinizi, adınızı ve bu hizmetin adını kullanmaktan kaçının.",
    )
}

/// Localized zxcvbn warning.
#[must_use]
pub fn warning_message(warning: Warning, locale: Locale) -> &'static str {
    match warning {
        Warning::StraightRowsOfKeysAreEasyToGuess => pick(
            locale,
            "Straight rows of keys are easy to guess.",
            "Klavyedeki düz tuş sıraları kolay tahmin edilir.",
        ),
        Warning::ShortKeyboardPatternsAreEasyToGuess => pick(
            locale,
            "Short keyboard patterns are easy to guess.",
            "Kısa klavye desenleri kolay tahmin edilir.",
        ),
        Warning::RepeatsLikeAaaAreEasyToGuess => pick(
            locale,
            "Repeats like \"aaa\" are easy to guess.",
            "\"aaa\" gibi tekrarlar kolay tahmin edilir.",
        ),
        Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => pick(
            locale,
            "Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\".",
            "\"abcabcabc\" gibi tekrarları tahmin etmek \"abc\" kadar kolaydır.",
        ),
        Warning::ThisIsATop10Password => pick(
            locale,
            "This is a top-10 common password.",
            "Bu, en yaygın 10 şifreden biri.",
        ),
        Warning::ThisIsATop100Password => pick(
            locale,
            "This is a top-100 common password.",
            "Bu, en yaygın 100 şifreden biri.",
        ),
        Warning::ThisIsACommonPassword => pick(
            locale,
            "This is a very common password.",
            "Bu çok yaygın bir şifre.",
        ),
        Warning::ThisIsSimilarToACommonlyUsedPassword => pick(
            locale,
            "This is similar to a commonly used password.",
            "Bu, sık kullanılan bir şifreye benziyor.",
        ),
        Warning::SequencesLikeAbcAreEasyToGuess => pick(
            locale,
            "Sequences like abc or 6543 are easy to guess.",
            "abc veya 6543 gibi diziler kolay tahmin edilir.",
        ),
        Warning::RecentYearsAreEasyToGuess => pick(
            locale,
            "Recent years are easy to guess.",
            "Yakın tarihli yıllar kolay tahmin edilir.",
        ),
        Warning::AWordByItselfIsEasyToGuess => pick(
            locale,
            "A word by itself is easy to guess.",
            "Tek başına bir kelime kolay tahmin edilir.",
        ),
        Warning::DatesAreOftenEasyToGuess => pick(
            locale,
            "Dates are often easy to guess.",
            "Tarihler genellikle kolay tahmin edilir.",
        ),
        Warning::NamesAndSurnamesByThemselvesAreEasyToGuess => pick(
            locale,
            "Names and surnames by themselves are easy to guess.",
            "Tek başına ad ve soyadlar kolay tahmin edilir.",
        ),
        Warning::CommonNamesAndSurnamesAreEasyToGuess => pick(
            locale,
            "Common names and surnames are easy to guess.",
            "Yaygın ad ve soyadlar kolay tahmin edilir.",
        ),
    }
}

/// Localized zxcvbn suggestion.
#[must_use]
pub fn suggestion_message(suggestion: Suggestion, locale: Locale) -> &'static str {
    match suggestion {
        Suggestion::UseAFewWordsAvoidCommonPhrases => pick(
            locale,
            "Use a few words, avoid common phrases.",
            "Birkaç kelime kullanın, yaygın ifadelerden kaçının.",
        ),
        Suggestion::NoNeedForSymbolsDigitsOrUppercaseLetters => pick(
            locale,
            "No need for symbols, digits, or uppercase letters.",
            "Sembol, rakam veya büyük harf kullanmanız gerekmez.",
        ),
        Suggestion::AddAnotherWordOrTwo => pick(
            locale,
            "Add another word or two. Uncommon words are better.",
            "Bir iki kelime daha ekleyin. Az kullanılan kelimeler daha iyidir.",
        ),
        Suggestion::CapitalizationDoesntHelpVeryMuch => pick(
            locale,
            "Capitalization doesn't help very much.",
            "Büyük harf kullanmak pek işe yaramaz.",
        ),
        Suggestion::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase => pick(
            locale,
            "All-uppercase is almost as easy to guess as all-lowercase.",
            "Tamamı büyük harf bir şifre, tamamı küçük harf olan kadar kolay tahmin edilir.",
        ),
        Suggestion::ReversedWordsArentMuchHarderToGuess => pick(
            locale,
            "Reversed words aren't much harder to guess.",
            "Ters yazılmış kelimeleri tahmin etmek çok daha zor değildir.",
        ),
        Suggestion::PredictableSubstitutionsDontHelpVeryMuch => pick(
            locale,
            "Predictable substitutions like '@' instead of 'a' don't help very much.",
            "'a' yerine '@' gibi tahmin edilebilir değişiklikler pek işe yaramaz.",
        ),
        Suggestion::UseALongerKeyboardPatternWithMoreTurns => pick(
            locale,
            "Use a longer keyboard pattern with more turns.",
            "Daha uzun ve daha çok yön değiştiren bir klavye deseni kullanın.",
        ),
        Suggestion::AvoidRepeatedWordsAndCharacters => pick(
            locale,
            "Avoid repeated words and characters.",
            "Tekrarlanan kelime ve karakterlerden kaçının.",
        ),
        Suggestion::AvoidSequences => {
            pick(locale, "Avoid sequences.", "Ardışık dizilerden kaçının.")
        }
        Suggestion::AvoidRecentYears => pick(
            locale,
            "Avoid recent years.",
            "Yakın tarihli yıllardan kaçının.",
        ),
        Suggestion::AvoidYearsThatAreAssociatedWithYou => pick(
            locale,
            "Avoid years that are associated with you.",
            "Sizinle ilişkilendirilebilecek yıllardan kaçının.",
        ),
        Suggestion::AvoidDatesAndYearsThatAreAssociatedWithYou => pick(
            locale,
            "Avoid dates and years that are associated with you.",
            "Sizinle ilişkilendirilebilecek tarih ve yıllardan kaçının.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwd_04_feedback_exists_in_both_languages() {
        let warnings = [
            Warning::StraightRowsOfKeysAreEasyToGuess,
            Warning::ShortKeyboardPatternsAreEasyToGuess,
            Warning::RepeatsLikeAaaAreEasyToGuess,
            Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess,
            Warning::ThisIsATop10Password,
            Warning::ThisIsATop100Password,
            Warning::ThisIsACommonPassword,
            Warning::ThisIsSimilarToACommonlyUsedPassword,
            Warning::SequencesLikeAbcAreEasyToGuess,
            Warning::RecentYearsAreEasyToGuess,
            Warning::AWordByItselfIsEasyToGuess,
            Warning::DatesAreOftenEasyToGuess,
            Warning::NamesAndSurnamesByThemselvesAreEasyToGuess,
            Warning::CommonNamesAndSurnamesAreEasyToGuess,
        ];
        for w in warnings {
            let en = warning_message(w, Locale::En);
            let tr = warning_message(w, Locale::Tr);
            assert!(!en.is_empty() && !tr.is_empty() && en != tr, "{w:?}");
        }
        let suggestions = [
            Suggestion::UseAFewWordsAvoidCommonPhrases,
            Suggestion::NoNeedForSymbolsDigitsOrUppercaseLetters,
            Suggestion::AddAnotherWordOrTwo,
            Suggestion::CapitalizationDoesntHelpVeryMuch,
            Suggestion::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase,
            Suggestion::ReversedWordsArentMuchHarderToGuess,
            Suggestion::PredictableSubstitutionsDontHelpVeryMuch,
            Suggestion::UseALongerKeyboardPatternWithMoreTurns,
            Suggestion::AvoidRepeatedWordsAndCharacters,
            Suggestion::AvoidSequences,
            Suggestion::AvoidRecentYears,
            Suggestion::AvoidYearsThatAreAssociatedWithYou,
            Suggestion::AvoidDatesAndYearsThatAreAssociatedWithYou,
        ];
        for s in suggestions {
            let en = suggestion_message(s, Locale::En);
            let tr = suggestion_message(s, Locale::Tr);
            assert!(!en.is_empty() && !tr.is_empty() && en != tr, "{s:?}");
        }
        assert_eq!(
            violation_message(PasswordViolation::TooShort { min: 12 }, Locale::Tr),
            "En az 12 karakter kullanın."
        );
        assert_eq!(
            violation_message(PasswordViolation::TooLong { max: 128 }, Locale::En),
            "Use at most 128 characters."
        );
        assert_ne!(
            user_input_message(Locale::En),
            user_input_message(Locale::Tr)
        );
    }
}
