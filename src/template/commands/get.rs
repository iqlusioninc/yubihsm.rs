//! Get a certificate template stored on the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Template.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::get_template`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetTemplateCommand {
    /// Object ID of the certificate template
    pub object_id: object::Id,
}

impl Command for GetTemplateCommand {
    type ResponseType = GetTemplateResponse;
}

/// Response from `command::get_template`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetTemplateResponse(pub(crate) Vec<u8>);

impl Response for GetTemplateResponse {
    const COMMAND_CODE: command::Code = command::Code::GetTemplate;
}
