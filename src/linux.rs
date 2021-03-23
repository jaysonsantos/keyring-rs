use std::collections::HashMap;

use secret_service::{EncryptionType, SecretService};

use crate::error::{KeyringError, ParseError, Result};

pub struct Keyring<'a> {
    service: &'a str,
    username: &'a str,
}

// Eventually try to get collection into the Keyring struct?
impl<'a> Keyring<'a> {
    pub const fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring { service, username }
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        let ss = SecretService::new(EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        let mut attrs = self.default_attributes();
        attrs.insert("application", "rust-keyring");
        let label = &format!("Password for {} on {}", self.username, self.service)[..];
        collection.create_item(
            label,
            attrs,
            password.as_bytes(),
            true, // replace
            "text/plain",
        )?;
        Ok(())
    }

    pub fn get_password(&self) -> Result<String> {
        let ss = SecretService::new(EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        let search = collection.search_items(self.default_attributes())?;
        let item = search.get(0).ok_or(KeyringError::NoPasswordFound)?;
        let secret_bytes = item.get_secret()?;
        let secret = String::from_utf8(secret_bytes).map_err(ParseError::Utf8)?;
        Ok(secret)
    }

    pub fn delete_password(&self) -> Result<()> {
        let ss = SecretService::new(EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        let search = collection.search_items(self.default_attributes())?;
        let item = search.get(0).ok_or(KeyringError::NoPasswordFound)?;
        Ok(item.delete()?)
    }

    fn default_attributes(&self) -> HashMap<&'a str, &'a str> {
        let mut attributes = HashMap::new();
        attributes.insert("service", self.service);
        attributes.insert("username", self.username);
        attributes
    }
}
