//! `text_enum!` — string-backed enums with consistent serde, `Display`,
//! `FromStr` and PostgreSQL `text` / `text[]` mapping.
//!
//! The database stores these values as `text` guarded by `CHECK` constraints
//! (see `migrations/`), never as PostgreSQL enum types, so that adding a value
//! is a plain constraint change.

macro_rules! text_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident => $text:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
            utoipa::ToSchema,
        )]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                // utoipa does not see the `$text` literal inside the
                // `serde` attribute of a `macro_rules!` expansion (it is a
                // `None`-delimited group there), so the schema name is
                // given explicitly. `tests/openapi.rs` in authn-server
                // checks that both agree (ARC-09).
                #[serde(rename = $text)]
                #[schema(rename = $text)]
                $variant,
            )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The stable wire / database representation.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)+
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::domain::UnknownVariant;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($text => Ok($name::$variant),)+
                    _ => Err($crate::domain::UnknownVariant { kind: stringify!($name) }),
                }
            }
        }

        impl sqlx::Type<sqlx::Postgres> for $name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <&str as sqlx::Type<sqlx::Postgres>>::type_info()
            }

            fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
                <&str as sqlx::Type<sqlx::Postgres>>::compatible(ty)
            }
        }

        impl sqlx::postgres::PgHasArrayType for $name {
            fn array_type_info() -> sqlx::postgres::PgTypeInfo {
                <&str as sqlx::postgres::PgHasArrayType>::array_type_info()
            }

            fn array_compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
                <&str as sqlx::postgres::PgHasArrayType>::array_compatible(ty)
            }
        }

        impl<'q> sqlx::Encode<'q, sqlx::Postgres> for $name {
            fn encode_by_ref(
                &self,
                buf: &mut sqlx::postgres::PgArgumentBuffer,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
            }
        }

        impl<'r> sqlx::Decode<'r, sqlx::Postgres> for $name {
            fn decode(
                value: sqlx::postgres::PgValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                let text = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
                Ok(text.parse::<$name>()?)
            }
        }
    };
}
