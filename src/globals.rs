use serde::{Deserialize, Serialize};
pub const PIPE_NAME: &str = r"\\.\pipe\rtti_pipe";

#[derive(Serialize, Deserialize, Debug)]
pub struct Parameters {
    pub threads: u16,
    pub use_json: bool,
    pub proc_target: Option<String>
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            threads: 4,
            use_json: false,
            proc_target: None
        }
    }
}
