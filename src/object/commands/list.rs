//! List objects visible from the current session
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::list_objects`
#[derive(Serialize, Deserialize, Debug)]
// TODO: use serde to serialize filters
pub(crate) struct ListObjectsCommand(pub(crate) Vec<u8>);

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Response from `command::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListObjectsResponse(pub(crate) Vec<object::Entry>);

impl Response for ListObjectsResponse {
    const COMMAND_CODE: command::Code = command::Code::ListObjects;
}
