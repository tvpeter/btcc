use anyhow::{anyhow, Result};
use bdk_wallet::{
    bip39::{Language, Mnemonic},
    keys::{bip39::WordCount, GeneratableKey, GeneratedKey},
    miniscript::Tap,
};

pub fn generate_mnemonic() -> Result<Vec<&'static str>, anyhow::Error> {
    let mnemonic: GeneratedKey<_, Tap> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| anyhow!("Error generating mnemonic"))?;

    let words_array: Vec<&'static str> = mnemonic.words().collect();

    Ok(words_array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        assert!(generate_mnemonic().is_ok());
        assert_eq!(generate_mnemonic().unwrap().len(), 12);
    }
}
