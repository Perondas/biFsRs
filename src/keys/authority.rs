use nutype::nutype;

#[nutype(
    sanitize(trim, lowercase),
    validate(not_empty, predicate = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')),
    derive(Debug, PartialEq, Clone, Display, Eq, Hash),
)]
pub struct Authority(String);
