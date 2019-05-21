//! Information about device storage

use serde::{Deserialize, Serialize};

/// Response from the [Get Storage Info] command.
///
/// [Get Storage Info]: https://developers.yubico.com/YubiHSM2/Commands/Get_Storage_Info.html
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Info {
    /// Total number of storage records
    pub total_records: u16,

    /// Storage records which are currently free
    pub free_records: u16,

    /// Total number of storage pages
    pub total_pages: u16,

    /// Storage pages which are currently free
    pub free_pages: u16,

    /// Page size in bytes
    pub page_size: u16,
}
