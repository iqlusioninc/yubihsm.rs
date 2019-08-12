//! Certificate templates.
//!
//! These are presently used for SSH certificates only.

mod algorithm;
pub(crate) mod commands;

pub use self::algorithm::Algorithm;
use crate::ssh;

/// Template types
#[derive(Debug)]
pub enum Template {
    /// SSH CA certificate templates
    Ssh(ssh::Template),
}

impl Template {
    /// Get the template algorithm for this template type
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Template::Ssh(_) => Algorithm::Ssh,
        }
    }

    /// Get an SSH template, if this template is one
    pub fn ssh(&self) -> Option<&ssh::Template> {
        match self {
            Template::Ssh(ssh) => Some(ssh),
        }
    }
}

impl From<ssh::Template> for Template {
    fn from(template: ssh::Template) -> Template {
        Template::Ssh(template)
    }
}

impl AsRef<[u8]> for Template {
    fn as_ref(&self) -> &[u8] {
        match self {
            Template::Ssh(ssh) => ssh.as_ref(),
        }
    }
}
