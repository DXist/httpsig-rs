use std::fmt::{self, Write as _};
use std::io::Write as _;

use base64::{Engine as _, engine::general_purpose};
use compact_str::{CompactString, ToCompactString};
use indexmap::IndexMap;
use rustc_hash::FxBuildHasher;
use sfv::{BareItem, Item, ListEntry, Parser};

use crate::{
  crypto::SigningKey,
  error::{HttpSigError, HttpSigResult},
  message_component::HttpMessageComponent,
  prelude::{VerifyingKey, message_component::HttpMessageComponentId},
  signature_params::HttpSignatureParams,
};

/// IndexMap of signature name and HttpSignatureHeaders
pub type HttpSignatureHeadersMap = IndexMap<CompactString, HttpSignatureHeaders, FxBuildHasher>;

#[derive(Debug, Clone)]
/// Signature Headers derived from HttpSignatureBase
pub struct HttpSignatureHeaders {
  /// Signature value of "Signature" http header in the form of "<signature_name>=:<base64_signature>:"
  signature: HttpSignature,
  /// signature-params value of "Signature-Input" http header in the form of "<signature_name>=:<signature_params>:"
  signature_params: HttpSignatureParams,
}

impl HttpSignatureHeaders {
  /// Generates (possibly multiple) HttpSignatureHeaders from signature and signature-input header values
  pub fn try_parse(signature_header: &str, signature_input_header: &str) -> HttpSigResult<HttpSignatureHeadersMap> {
    let signature_input: sfv::Dictionary = Parser::new(signature_input_header).parse()?;
    let mut signature: sfv::Dictionary = Parser::new(signature_header).parse()?;
    // let signature_input =
    //   Parser::parse_dictionary(signature_input_header.as_bytes()).map_err(|e| HttpSigError::ParseSFVError(e.to_string()))?;
    // let signature =
    //   Parser::parse_dictionary(signature_header.as_bytes()).map_err(|e| HttpSigError::ParseSFVError(e.to_string()))?;

    if signature.len() != signature_input.len() {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The number of signature and signature-input headers are not the same",
      ));
    }

    if !signature.keys().all(|k| signature_input.contains_key(k)) {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The signature and signature-input headers are not the same",
      ));
    }
    if !signature.values().all(|v| {
      matches!(
        v,
        ListEntry::Item(Item {
          bare_item: BareItem::ByteSequence(_),
          ..
        })
      )
    }) {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The signature header is not a dictionary",
      ));
    }
    if !signature_input.values().all(|v| matches!(v, ListEntry::InnerList(_))) {
      return Err(HttpSigError::BuildSignatureHeaderError(
        "The signature-input header is not a dictionary",
      ));
    }

    let res = signature_input
      .iter()
      .map(|(k, v)| {
        let signature_name = k.as_str().to_compact_string();
        let signature_params = HttpSignatureParams::try_from(v)?;

        let signature_bytes = match signature.swap_remove(k) {
          Some(ListEntry::Item(Item {
            bare_item: BareItem::ByteSequence(v),
            ..
          })) => v,
          _ => unreachable!(),
        };
        let signature = HttpSignature(signature_bytes);

        Ok((
          signature_name,
          Self {
            signature,
            signature_params,
          },
        )) as HttpSigResult<(CompactString, Self)>
      })
      .collect::<Result<HttpSignatureHeadersMap, _>>()?;
    Ok(res)
  }

  /// Returns the signature value without name
  pub fn signature(&self) -> &HttpSignature {
    &self.signature
  }

  /// Returns the signature params value without name for signature-input header
  pub fn signature_params(&self) -> &HttpSignatureParams {
    &self.signature_params
  }

  /// Converts into the (signature, signature params value pair) without name for signature-input header
  pub fn into_signature_and_params(self) -> (HttpSignature, HttpSignatureParams) {
    (self.signature, self.signature_params)
  }

  /// Returns the signature value of "Signature" http header in the form of "<signature_name>=:<base64_signature>:"
  pub fn signature_header_value(&self, signature_name: &str) -> String {
    const NON_RSA_SIGNATURE_BUFFER_SIZE: usize = 128;
    let mut buf = String::with_capacity(NON_RSA_SIGNATURE_BUFFER_SIZE);
    write!(buf, "{}=:{}:", signature_name, self.signature).expect("fmt::Write is infallible for String");
    buf
  }
  /// Returns the signature input value of "Signature-Input" http header in the form of "<signature_name>=<signature_params>"
  pub fn signature_input_header_value(&self, signature_name: &str) -> String {
    const TYPICAL_SIGNATURE_INPUT_BUFFER_SIZE: usize = 256;
    let mut buf = String::with_capacity(TYPICAL_SIGNATURE_INPUT_BUFFER_SIZE);
    write!(buf, "{}={}", signature_name, self.signature_params).expect("fmt::Write is infallible for String");
    buf
  }
}

#[derive(Debug, Clone)]
/// Wrapper struct of raw signature bytes
pub struct HttpSignature(Vec<u8>);

impl fmt::Display for HttpSignature {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let signature_value = general_purpose::STANDARD.encode(&self.0);
    write!(f, "{}", signature_value)
  }
}

impl AsRef<HttpSignature> for HttpSignature {
  fn as_ref(&self) -> &HttpSignature {
    self
  }
}

/// Signature Base
/// https://datatracker.ietf.org/doc/html/rfc9421#section-2.5
pub struct HttpSignatureBase {
  /// HTTP message field and derived components ordered as in the vector in signature params
  component_lines: Vec<HttpMessageComponent>,
  /// signature params
  signature_params: HttpSignatureParams,
}

const TYPICAL_SIGNATURE_BASE_UPPER_BOUND_SIZE: usize = 512;

impl HttpSignatureBase {
  /// Creates a new signature base from component lines and signature params
  /// This should not be exposed to user and not used directly.
  /// Use wrapper functions generating SignatureBase from base HTTP request and Signer itself instead when newly generating signature
  /// When verifying signature, use wrapper functions generating SignatureBase from HTTP request containing signature params itself instead.
  pub fn try_new(component_lines: Vec<HttpMessageComponent>, signature_params: HttpSignatureParams) -> HttpSigResult<Self> {
    // check if the order of component lines is the same as the order of covered message component ids
    if component_lines.len() != signature_params.covered_components.len() {
      return Err(HttpSigError::BuildSignatureBaseError(
        "The number of component lines is not the same as the number of covered message component ids",
      ));
    }

    let assertion = component_lines
      .iter()
      .zip(signature_params.covered_components.iter())
      .all(|(component_line, covered_component_id)| component_line.id == *covered_component_id);
    if !assertion {
      return Err(HttpSigError::BuildSignatureBaseError(
        "The order of component lines is not the same as the order of covered message component ids",
      ));
    }

    Ok(Self {
      component_lines,
      signature_params,
    })
  }

  /// Returns the signature base string as vector of bytes to be signed.
  pub fn to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TYPICAL_SIGNATURE_BASE_UPPER_BOUND_SIZE);
    write!(buf, "{}", self).expect("std::io::Write is infallible for Vec");
    buf
  }

  /// Build signature from given signing key
  pub fn build_raw_signature(&self, signing_key: &impl SigningKey) -> HttpSigResult<Vec<u8>> {
    let bytes = self.to_vec();
    signing_key.sign(&bytes)
  }

  /// Build the signature and signature-input headers structs
  pub fn build_signature_headers(self, signing_key: &impl SigningKey) -> HttpSigResult<HttpSignatureHeaders> {
    let signature = self.build_raw_signature(signing_key)?;
    Ok(HttpSignatureHeaders {
      signature: HttpSignature(signature),
      signature_params: self.signature_params,
    })
  }

  /// Verify the signature using the given verifying key
  pub fn verify_signature(&self, verifying_key: &impl VerifyingKey, signature: &HttpSignature) -> HttpSigResult<()> {
    if self.signature_params.is_expired() {
      return Err(HttpSigError::ExpiredSignatureParams("Signature params is expired"));
    }
    let signature_bytes = signature.0.as_slice();
    verifying_key.verify(&self.to_vec(), signature_bytes)
  }

  /// Get key id from signature params
  pub fn keyid(&self) -> Option<&str> {
    self.signature_params.keyid.as_deref()
  }

  /// Get algorithm from signature params
  pub fn alg(&self) -> Option<&str> {
    self.signature_params.alg.as_deref()
  }

  /// Get nonce from signature params
  pub fn nonce(&self) -> Option<&str> {
    self.signature_params.nonce.as_deref()
  }

  /// Get covered components from signature params
  pub fn covered_components(&self) -> &[HttpMessageComponentId] {
    &self.signature_params.covered_components
  }
}

impl fmt::Display for HttpSignatureBase {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for component in &self.component_lines {
      // writeln appends `\n` on all platforms
      writeln!(f, "{}", component)?;
    }
    // no final newline according to the [Signature Base algorithm](https://www.rfc-editor.org/rfc/rfc9421#section-2.5)
    write!(f, "\"@signature-params\": {}", self.signature_params)
  }
}

impl AsRef<HttpSignatureBase> for HttpSignatureBase {
  fn as_ref(&self) -> &HttpSignatureBase {
    self
  }
}

/// Signer and verifier of signature bases.
pub struct HttpSignatureBaseOperator {
  buf: Vec<u8>,
}

impl Default for HttpSignatureBaseOperator {
  fn default() -> Self {
    Self {
      buf: Vec::with_capacity(TYPICAL_SIGNATURE_BASE_UPPER_BOUND_SIZE),
    }
  }
}

impl HttpSignatureBaseOperator {
  /// Sign the provided signature bases by the corresponding signing key for each pair.
  ///
  /// Output raw signature results into the `output` collection.
  pub fn sign_bases<I, B, S, K, O>(&mut self, signature_base_keys: I, output: &mut O)
  where
    I: IntoIterator<Item = (B, S)>,
    B: AsRef<HttpSignatureBase>,
    S: AsRef<K>,
    K: SigningKey,
    O: Extend<HttpSigResult<Vec<u8>>>,
  {
    output.extend(signature_base_keys.into_iter().map(|(base, signing_key)| {
      self.buf.clear();
      write!(self.buf, "{}", base.as_ref()).expect("std::io::Write is infallible for Vec");
      signing_key.as_ref().sign(&self.buf)
    }))
  }

  /// Sign the provided signature bases by the corresponding signing key for each pair.
  ///
  /// Build [`HttpSignatureHeaders`] for each signature into the `output` collection.
  pub fn build_signature_headers<I, S, K, O>(&mut self, signature_base_keys: I, output: &mut O)
  where
    I: IntoIterator<Item = (HttpSignatureBase, S)>,
    S: AsRef<K>,
    K: SigningKey,
    O: Extend<HttpSigResult<HttpSignatureHeaders>>,
  {
    output.extend(signature_base_keys.into_iter().map(|(base, signing_key)| {
      self.buf.clear();
      write!(self.buf, "{}", base).expect("std::io::Write is infallible for Vec");
      signing_key.as_ref().sign(&self.buf).map(|signature| HttpSignatureHeaders {
        signature: HttpSignature(signature),
        signature_params: base.signature_params,
      })
    }))
  }

  /// Verify the provided signature bases with the corresponding verifying key and signature for each tuple.
  ///
  /// Returns input identifier `N` of the first valid signature or None if no signatures are valid.
  pub fn verify_signatures<I, N, B, V, K, S>(&mut self, id_base_key_signatures: I) -> Option<N>
  where
    I: IntoIterator<Item = (N, B, V, S)>,
    B: AsRef<HttpSignatureBase>,
    V: AsRef<K>,
    K: VerifyingKey,
    S: AsRef<HttpSignature>,
  {
    id_base_key_signatures
      .into_iter()
      .find_map(|(id, base, verifying_key, signature)| {
        let base = base.as_ref();
        if base.signature_params.is_expired() {
          None
        } else {
          self.buf.clear();
          write!(self.buf, "{}", base).expect("std::io::Write is infallible for Vec");
          let signature_bytes = signature.as_ref().0.as_slice();
          verifying_key.as_ref().verify(&self.buf, signature_bytes).ok().map(|_| id)
        }
      })
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::signature_params::HttpSignatureParams;

  const COMPONENT_LINES: &[&str] = &[
    r##""@method": GET"##,
    r##""@path": /"##,
    r##""date": Tue, 07 Jun 2014 20:51:35 GMT"##,
    r##""content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"##,
  ];

  /// こんな感じでSignatureBaseをParamsとかComponentLinesから直接作るのは避ける。
  #[test]
  fn test_signature_base_directly_instantiated() {
    const SIGPARA: &str = r##";created=1704972031;alg="ed25519";keyid="gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is=""##;
    let values = (r##""@method" "@path" "date" "content-digest""##, SIGPARA);
    let signature_params = HttpSignatureParams::try_from(format!("({}){}", values.0, values.1).as_str()).unwrap();

    let component_lines = COMPONENT_LINES
      .iter()
      .map(|&s| HttpMessageComponent::try_from(s))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let signature_base = HttpSignatureBase::try_new(component_lines, signature_params).unwrap();
    let test_string = r##""@method": GET
"@path": /
"date": Tue, 07 Jun 2014 20:51:35 GMT
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@signature-params": "##;
    assert_eq!(
      signature_base.to_string(),
      format!("{}({}){}", test_string, values.0, values.1)
    );
  }

  #[test]
  fn test_signature_values() {
    const SIGNATURE_INPUT: &str = r##"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519", sig-b27=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519-alt""##;
    const SIGNATURE: &str = r##"sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:, sig-b27=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"##;

    let mut header_map = HttpSignatureHeaders::try_parse(SIGNATURE, SIGNATURE_INPUT).unwrap();
    assert!(header_map.len() == 2);
    let http_signature_headers = header_map.swap_remove("sig-b26").unwrap();
    assert_eq!(
      http_signature_headers.signature_header_value("sig-b26"),
      SIGNATURE.split(',').next().unwrap()
    );
    assert_eq!(
      http_signature_headers.signature_input_header_value("sig-b26"),
      SIGNATURE_INPUT.split(',').next().unwrap()
    );
  }
}
