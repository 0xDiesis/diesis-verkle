pub mod committer;
pub mod crs;
mod default_crs;
pub mod ipa; // follows the BCMS20 scheme
pub mod math_utils;
pub mod multiproof;
mod streaming;
pub mod transcript;

pub mod lagrange_basis;

/// Failures at checked prover boundaries. Legacy wrappers require trusted inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    InvalidDomain,
    InvalidParameters,
    InvalidQuery,
    EmptyQueries,
    DegenerateChallenge,
    ReplayMismatch,
}
impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProofError {}
pub(crate) type IOResult<T> = std::io::Result<T>;
pub(crate) type IOError = std::io::Error;
pub(crate) type IOErrorKind = std::io::ErrorKind;
