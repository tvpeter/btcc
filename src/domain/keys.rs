use anyhow::{anyhow, Result};
use bdk_wallet::{
    bip39::{Language, Mnemonic},
    bitcoin::{bip32::Xpriv, Network},
    keys::{bip39::WordCount, GeneratableKey, GeneratedKey},
    miniscript::Tap,
    template::{Bip84, DescriptorTemplate},
    KeychainKind,
};

const NETWORK: Network = Network::Testnet; // move it into config file

pub fn generate_mnemonic() -> Result<Vec<&'static str>, anyhow::Error> {
    let mnemonic: GeneratedKey<_, Tap> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| anyhow!("Error generating mnemonic"))?;

    let mnemonic_array: Vec<&'static str> = mnemonic.words().collect();

    Ok(mnemonic_array)
}

pub fn restore_mnemonic(mnemonic: Vec<&'static str>) -> Result<Vec<&'static str>, anyhow::Error> {
    const VALID_MNEMONIC_LEN: &[usize] = &[12, 15, 18, 21, 24];

    if !VALID_MNEMONIC_LEN.contains(&mnemonic.len()) {
        return Err(anyhow!("Invalid mnemonic length"));
    }

    Ok(mnemonic)
}

pub fn mnemonic_to_descriptors(
    mnemonic: Vec<&'static str>,
    passphrase: Option<&str>,
) -> Result<(String, String), anyhow::Error> {
    let mut mnemonic_string = String::new();
    for word in mnemonic {
        mnemonic_string.push_str(word);
        mnemonic_string.push(' ');
    }

    let restored_mnemonic = Mnemonic::parse(mnemonic_string)?;
    let seed = restored_mnemonic.to_seed(passphrase.unwrap_or(""));

    let xpriv = Xpriv::new_master(NETWORK, &seed)?;

    let (external_descriptor, external_key_map, _) =
        Bip84(xpriv, KeychainKind::External).build(NETWORK)?;
    let (internal_descriptor, internal_key_map, _) =
        Bip84(xpriv, KeychainKind::Internal).build(NETWORK)?;

    let external_desc_priv = external_descriptor.to_string_with_secret(&external_key_map);
    let internal_desc_priv = internal_descriptor.to_string_with_secret(&internal_key_map);

    Ok((external_desc_priv, internal_desc_priv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        assert!(generate_mnemonic().is_ok());
        assert_eq!(generate_mnemonic().unwrap().len(), 12);
    }

    #[test]
    fn test_restore_mnemonic() {
        let mnemonic: Vec<&str> = generate_mnemonic().unwrap();
        assert!(restore_mnemonic(mnemonic.clone()).is_ok());
        let restored_mnemonic = restore_mnemonic(mnemonic.clone()).unwrap();
        assert_eq!(restored_mnemonic.len(), 12);
        assert_eq!(restored_mnemonic, mnemonic)
    }

    #[test]
    fn test_mnemonic_to_descriptors() {
        let mnemonic: Vec<&str> = generate_mnemonic().unwrap();
        let passphrase = "passphrase";
        let (external_desc_priv, internal_desc_priv) =
            mnemonic_to_descriptors(mnemonic.clone(), Some(passphrase)).unwrap();
        assert!(external_desc_priv.contains("wpkh"));
        assert!(internal_desc_priv.contains("wpkh"));
    }
}
