
#[derive(PartialEq, Debug, Clone)]
pub struct Password {
    value: String,
}

impl Password {
    pub fn parse(raw_password:&str) -> Result<Password, ()> {
        if raw_password.len() >= 8 && 
            raw_password.chars().any(|c| c.is_uppercase())&& 
            raw_password.chars().any(|c| c.is_lowercase())
        {
            Ok(Password { value: raw_password.to_string() })
        }
        else {
            Err(())
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.value
    }
}


#[test]
fn good_passwords_should_be_parsed() {

    let raw_passwords = [
        "gotSomeUpperAndLower", 
        "GotSpecial!Char", 
        "Exactly8"
    ];

    for raw_password in raw_passwords {
        assert!(Password::parse(raw_password).is_ok());
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
        assert!(Password::parse(raw_password).is_err());
    }
    
}