//! Get Pseudo Random Bytes
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Pseudo_Random.html>

use crate::{
    command::{self, Command, MAX_MSG_SIZE},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Max message size - tag byte - 16-bit response length field
pub(crate) const MAX_RAND_BYTES: usize = MAX_MSG_SIZE - 1 - 2;

/// Request parameters for `command::get_pseudo_random`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetPseudoRandomCommand {
    /// Number of random bytes to return
    pub bytes: u16,
}

impl Command for GetPseudoRandomCommand {
    type ResponseType = GetPseudoRandomResponse;
}

/// Response from `command::get_pseudo_random`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetPseudoRandomResponse {
    /// Bytes of pseudo random data returned from the YubiHSM
    pub bytes: Vec<u8>,
}

impl Response for GetPseudoRandomResponse {
    const COMMAND_CODE: command::Code = command::Code::GetPseudoRandom;
}
