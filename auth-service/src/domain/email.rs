use std::hash::Hash;

use regex::Regex;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)] 
pub struct Email(Secret<String>); 

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Email> {
        let re = Regex::new(r"\S+@\S+\.\S+").unwrap();
        if re.is_match(s.expose_secret()) {
            Ok(Self(s))
        }
        else {
            Err(eyre!(format!(
                "{} is not a valid email.",
                s.expose_secret()
            )))
        }
    }
}


impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    use secrecy::Secret; 

    #[test]
    fn good_emails_should_be_parsed() {

        let raw_emails = [
            "guillem@letsgetrusty.com", 
            "other@letsgetrusty.com", 
            "person@gmail.com"
        ];

        for raw_email in raw_emails {
            assert!(Email::parse(Secret::new(raw_email.to_string())).is_ok());
        }
        
    }

    #[test]
    fn bad_email_should_be_parsed() {

        let raw_emails = [
            "space_in_user_name @domain", 
            "@only_domain", 
            "only_user_name@", 
            "person@ space_in_domain", 
            "no_separation"
        ];

        for raw_email in raw_emails {
            assert!(Email::parse(Secret::new(raw_email.to_string())).is_err());
        }
        
    }
}