use std::borrow::Cow;

use compact_str::CompactString;
use httpsig::prelude::HttpSigError;
use thiserror::Error;

/// Result type for http signature
pub type HyperSigResult<T> = std::result::Result<T, HyperSigError>;

/// Error type for http signature for hyper
#[derive(Clone, Error, Debug)]
pub enum HyperSigError {
  /// No signature headers found
  #[error("No signature headers found: {0}")]
  NoSignatureHeaders(&'static str),

  /// Failed to parse signature headers
  #[error("Failed to stringify signature headers")]
  FailedToStrSignatureHeaders,

  /// Failed to parse header value
  #[error("Failed to parse header value")]
  InvalidHeaderValue,

  /// Invalid component name
  #[error("Invalid component name: {0}")]
  InvalidComponentName(Cow<'static, str>),

  /// Invalid component param
  #[error("Invalid component param: {0}")]
  InvalidComponentParam(String),

  /// Invalid signature
  #[error("Invalid signature: {0}")]
  InvalidSignature(&'static str),

  /// Inherited from HttpSigError
  #[error("HttpSigError: {0}")]
  HttpSigError(#[from] HttpSigError),
}

impl From<http::header::InvalidHeaderValue> for HyperSigError {
  fn from(_err: http::header::InvalidHeaderValue) -> Self {
    Self::InvalidHeaderValue
  }
}

impl From<http::header::ToStrError> for HyperSigError {
  fn from(_err: http::header::ToStrError) -> Self {
    Self::FailedToStrSignatureHeaders
  }
}

/// Result type for http signature
pub type HyperDigestResult<T> = std::result::Result<T, HyperDigestError>;

/// Error type for http signature for hyper
#[derive(Clone, Error, Debug)]
pub enum HyperDigestError {
  /// Http body error
  #[error("Http body error: {0}")]
  HttpBodyError(&'static str),

  /// No content-digest header found
  #[error("No content-digest header found: {0}")]
  NoDigestHeader(&'static str),

  /// Failed to parse header value
  #[error("Failed to parse header value: {0}")]
  InvalidHeaderValue(Cow<'static, str>),

  /// Failed to parse content digest headers
  #[error("Failed to stringify content-digest header")]
  FailedToStrDigestHeader,

  /// Invalid content-digest
  #[error("Invalid content-digest: {0}")]
  InvalidContentDigest(&'static str),

  /// Invalid content-digest type
  #[error("Invalid content-digest type: {0}")]
  InvalidContentDigestType(CompactString),
}

impl From<http::header::ToStrError> for HyperDigestError {
  fn from(_err: http::header::ToStrError) -> Self {
    Self::FailedToStrDigestHeader
  }
}
