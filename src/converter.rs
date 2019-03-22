use failure::Error;
use failure::Fail;

#[derive(Debug, Fail)]
enum ConverterError {
    #[fail(display = "unknown suffix: {}", suffix)]
    UnknownSuffix { suffix: String },
}

pub fn literal_to_bytes(input: &str) -> Result<u64, Error> {
    match input.parse::<u64>() {
        Ok(result) => Ok(result),
        Err(_) => {
            let (num_str, suffix) = input.split_at(input.len() - 1);
            let num = num_str.parse::<u64>()?;
            match suffix {
                "K" => Ok(num * 1024),
                "M" => Ok(num * 1024 * 1024),
                "G" => Ok(num * 1024 * 1024 * 1024),
                "T" => Ok(num * 1024 * 1024 * 1024 * 1024),
                _ => Err(ConverterError::UnknownSuffix {
                    suffix: suffix.to_owned(),
                }
                .into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::literal_to_bytes;

    #[test]
    fn digits() {
        assert_eq!(1234, literal_to_bytes("1234").unwrap());
    }
    #[test]
    fn kilos() {
        assert_eq!(4096, literal_to_bytes("4K").unwrap());
    }
    #[test]
    fn megas() {
        assert_eq!(36700160, literal_to_bytes("35M").unwrap());
    }
    #[test]
    fn gigas() {
        assert_eq!(119185342464, literal_to_bytes("111G").unwrap());
    }
}
