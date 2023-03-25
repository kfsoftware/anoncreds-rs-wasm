use wasm_bindgen::prelude::*;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize)]
#[repr(usize)]
#[wasm_bindgen]
pub enum ErrorCode {
    Success = 0,
    Input = 1,
    IOError = 2,
    InvalidState = 3,
    Unexpected = 4,
    CredentialRevoked = 5,
    InvalidUserRevocId = 6,
    ProofRejected = 7,
    RevocationRegistryFull = 8,
}
