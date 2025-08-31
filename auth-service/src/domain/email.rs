use regex::Regex;

#[derive(PartialEq, Debug, Clone, Hash, Eq)]
pub struct Email {
    value: String,
}

impl Email {
    pub fn parse(raw_email:String) -> Result<Email, ()> {
        let re = Regex::new(r"\S+@\S+\.\S+").unwrap();
        if re.is_match(&raw_email) {
            Ok(Email { value: raw_email })
        }
        else {
            Err(())
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.value
    }
}


#[test]
fn good_emails_should_be_parsed() {

    let raw_emails = [
        "guillem@letsgetrusty.com", 
        "other@letsgetrusty.com", 
        "person@gmail.com"
    ];

    for raw_email in raw_emails {
        assert!(Email::parse(raw_email.to_string()).is_ok());
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
        assert!(Email::parse(raw_email.to_string()).is_err());
    }
    
}