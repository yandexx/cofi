pub fn literal_to_bytes(input: &str) -> Result<u64, String> {
    match input.parse::<u64>() {
        Ok(result) => Ok(result),
        Err(why) => {
            let (num_str, suffix) = input.split_at(input.len() - 1);
            let num = match num_str.parse::<u64>() {
                Ok(num) => num,
                Err(why) => return Err(format!("Can't parse \"{}\": {}.", num_str, why)),
            };
            
            match suffix {
                "K" => Ok(num * 1024),
                "M" => Ok(num * 1024 * 1024),
                "G" => Ok(num * 1024 * 1024 * 1024),
                "T" => Ok(num * 1024 * 1024 * 1024 * 1024),
                _ => Err(format!(
                    "Cannot convert: {}, or unknown suffix. Try K, M, G or T.",
                    why
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::literal_to_bytes;

    #[test]
    fn digits() {
        assert_eq!(Ok(1234), literal_to_bytes("1234"));
    }
    #[test]
    fn kilos() {
        assert_eq!(Ok(4096), literal_to_bytes("4K"));
    }
    #[test]
    fn megas() {
        assert_eq!(Ok(36700160), literal_to_bytes("35M"));
    }
    #[test]
    fn gigas() {
        assert_eq!(Ok(119185342464), literal_to_bytes("111G"));
    }
}
