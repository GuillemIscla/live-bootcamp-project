use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct Password(Secret<String>);

impl PartialEq for Password { 
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Password {
    pub fn parse(s:Secret<String>) -> Result<Password> {
        if  validate_password(&s) {
            Ok(Self(s))
        }
        else {
            Err(eyre!("Password chosen do not pass the validation"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool { // Updated!
    s.expose_secret().len() >= 8 && 
        s.expose_secret().chars().any(|c| c.is_uppercase()) && 
        s.expose_secret().chars().any(|c| c.is_lowercase())
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}


#[cfg(test)]
mod tests {

    use super::Password;
    use secrecy::Secret;

    #[test]
    fn good_passwords_should_be_parsed() {

        let raw_passwords = [
            "gotSomeUpperAndLower", 
            "GotSpecial!Char", 
            "Exactly8"
        ];

        for raw_password in raw_passwords {
            assert!(Password::parse(Secret::new(raw_password.to_string())).is_ok());
        }
        
    }

    #[test]
    fn bad_passwords_should_be_parsed() {

        let raw_passwords = [
            "short", 
            "LOWERCASE", 
            "UPPERCASE", 
            "****", 
            "123"
        ];

        for raw_password in raw_passwords {
            assert!(Password::parse(Secret::new(raw_password.to_string())).is_err());
        }
        
    }
}