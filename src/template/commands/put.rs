//! Put a certificate template into the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Template.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_template`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutTemplateCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Template data
    pub data: Vec<u8>,
}

impl Command for PutTemplateCommand {
    type ResponseType = PutTemplateResponse;
}

/// Response from `command::put_template`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutTemplateResponse {
    /// ID of the template
    pub object_id: object::Id,
}

impl Response for PutTemplateResponse {
    const COMMAND_CODE: command::Code = command::Code::PutTemplate;
}
