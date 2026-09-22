//! Token lifetime duration parsing.

use std::str::FromStr;

/// A parsed duration in whole seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TtlSeconds(u64);

impl TtlSeconds {
    #[must_use]
    pub fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for TtlSeconds {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();
        if raw.is_empty() {
            anyhow::bail!("TTL duration cannot be empty");
        }
        if let Ok(secs) = raw.parse::<u64>() {
            return Ok(Self(secs));
        }

        let mut total_secs: u64 = 0;
        let mut num_buf = String::new();

        for c in raw.chars() {
            if c.is_ascii_digit() {
                num_buf.push(c);
            } else {
                if num_buf.is_empty() {
                    anyhow::bail!("invalid duration '{raw}': missing number before unit '{c}'");
                }
                let count: u64 = num_buf.parse()?;
                num_buf.clear();

                let unit_secs = match c {
                    's' | 'S' => 1,
                    'm' | 'M' => 60,
                    'h' | 'H' => 3600,
                    'd' | 'D' => 86_400,
                    'w' | 'W' => 7 * 86_400,
                    _ => anyhow::bail!(
                        "unknown time unit '{c}' in duration '{raw}' (expected s, m, h, d, or w)"
                    ),
                };

                total_secs = total_secs
                    .checked_add(
                        count
                            .checked_mul(unit_secs)
                            .ok_or_else(|| anyhow::anyhow!("duration '{raw}' overflows u64"))?,
                    )
                    .ok_or_else(|| anyhow::anyhow!("duration '{raw}' overflows u64"))?;
            }
        }

        if !num_buf.is_empty() {
            anyhow::bail!("invalid duration '{raw}': trailing number without unit");
        }

        Ok(Self(total_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compound_and_simple_durations() {
        assert_eq!("90d".parse::<TtlSeconds>().unwrap().get(), 90 * 86_400);
        assert_eq!("1h30m".parse::<TtlSeconds>().unwrap().get(), 3600 + 1800);
        assert_eq!("3600".parse::<TtlSeconds>().unwrap().get(), 3600);
        assert_eq!("45s".parse::<TtlSeconds>().unwrap().get(), 45);
        assert_eq!("2w".parse::<TtlSeconds>().unwrap().get(), 14 * 86_400);
    }

    #[test]
    fn rejects_malformed_durations() {
        assert!("".parse::<TtlSeconds>().is_err());
        assert!("d".parse::<TtlSeconds>().is_err());
        assert!("90x".parse::<TtlSeconds>().is_err());
        assert!("10d5".parse::<TtlSeconds>().is_err());
    }
}