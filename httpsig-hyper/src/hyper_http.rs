use crate::error::{HyperSigError, HyperSigResult};

use compact_str::{CompactString, ToCompactString, format_compact};
use http::{HeaderMap, Request, Response};
use http_body::Body;
use httpsig::prelude::{
  AlgorithmName, HttpSignature, HttpSignatureBase, HttpSignatureBaseOperator, HttpSignatureHeaders, HttpSignatureHeadersMap,
  HttpSignatureParams, SigningKey, VerifyingKey,
  message_component::{
    DerivedComponentName, HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName, HttpMessageComponentParam,
  },
};
use indexmap::IndexMap;
use std::str::FromStr;

/// A type alias for the signature name
type SignatureName = CompactString;
/// A type alias for the key id in base 64
type KeyId = CompactString;

/* --------------------------------------- */
/// A trait about the http message signature common to both request and response
pub trait MessageSignature {
  type Error: From<http::header::InvalidHeaderValue>;

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool;

  /// Extract all key ids for signature bases contained in the request headers
  fn get_alg_key_ids(&self) -> Result<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>, Self::Error>;

  /// Extract all signature params used to generate signature bases contained in the request headers
  fn get_signature_params(&self) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error>;

  fn message_headers_mut(&mut self) -> &mut HeaderMap;

  /// Set the http message signatures from given pairs of (http signature headers, name)
  fn set_message_signature_headers<I, N>(&mut self, headers_name: I) -> Result<(), Self::Error>
  where
    I: IntoIterator<Item = (HttpSignatureHeaders, N)>,
    N: AsRef<str>,
  {
    for (headers, name) in headers_name {
      let name = name.as_ref();
      self
        .message_headers_mut()
        .append("signature-input", headers.signature_input_header_value(name).try_into()?);
      self
        .message_headers_mut()
        .append("signature", headers.signature_header_value(name).try_into()?);
    }
    Ok(())
  }
}

/// A trait about http message signature for request
pub trait MessageSignatureReq {
  type Error;
  /// Set the http message signature from given http signature params and signing key.
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Consider constructing signature bases for each signature via [`Self::build_signature_base`] and using [`httpsig::prelude::HttpSignatureBaseOperator`]
  /// in a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  /// Then call [`MessageSignature::set_message_signature_headers`].
  fn set_message_signature<T>(
    &mut self,
    signature_params: HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> Result<(), Self::Error>
  where
    T: SigningKey;

  /// Set the http message signatures from given tuples of (http signature params, signing key, name)
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Consider constructing signature bases for each signature via [`Self::build_signature_base`] and using [`httpsig::prelude::HttpSignatureBaseOperator`]
  /// in a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  /// Then call [`MessageSignature::set_message_signature_headers`].
  fn set_message_signatures<'a, T, I>(&mut self, params_key_name: I) -> Result<(), Self::Error>
  where
    T: SigningKey + 'a,
    I: IntoIterator<Item = (HttpSignatureParams, &'a T, &'a str)>;

  /// Build signature base from hyper http request and signature params.
  ///
  /// # Arguments:
  ///
  /// - signature_params: the http signature params
  fn build_signature_base(&self, signature_params: HttpSignatureParams) -> HyperSigResult<HttpSignatureBase>;

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Consider extracting signature bases and signatures via [`Self::extract_signatures`] and using [`httpsig::prelude::HttpSignatureBaseOperator`]
  /// in a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  fn verify_message_signature<V, K>(&self, verifying_key: V, key_id: Option<&str>) -> Result<SignatureName, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey;

  /// Verify multiple signatures at once
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Consider extracting signature bases and signatures via [`Self::extract_signatures`] and using [`httpsig::prelude::HttpSignatureBaseOperator`]
  /// in a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  fn verify_message_signatures<V, K>(
    &self,
    key_and_id: &[(V, Option<&str>)],
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey;

  /// Extract all signature bases and signatures contained in the request headers
  fn extract_signatures(&self) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignature)>, Self::Error>;
}

/// A trait about http message signature for response
pub trait MessageSignatureRes {
  type Error;
  /// Set the http message signature from given http signature params and signing key
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Consider using [`httpsig::prelude::HttpSignatureBaseOperator`]
  /// in a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  /// Then call [`MessageSignature::set_message_signature_headers`].
  fn set_message_signature<'a, T, B>(
    &mut self,
    signature_params: HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    T: SigningKey + 'a;

  /// Set the http message signatures from given tuples of (http signature params, signing key, name)
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Consider using [`httpsig::prelude::HttpSignatureBaseOperator`]
  /// in a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  /// Then call [`MessageSignature::set_message_signature_headers`].
  fn set_message_signatures<'a, T, I, B>(
    &mut self,
    params_key_name: I,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    T: SigningKey + 'a,
    I: IntoIterator<Item = (HttpSignatureParams, &'a T, &'a str)>;

  /// Build signature base from hyper http request and signature params.
  ///
  /// # Arguments:
  ///
  /// - signature_params: the http signature params
  /// - req_for_param: optional request, related to the response signature base
  fn build_signature_base<B>(
    &self,
    signature_params: HttpSignatureParams,
    req_for_param: Option<&Request<B>>,
  ) -> HyperSigResult<HttpSignatureBase>;

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  ///
  /// Note: This is a synchronous, CPU-intensive operation. Callers
  /// should execute this on a dedicated thread pool (e.g, via [rayon::spawn_fifo](https://docs.rs/rayon/latest/rayon/fn.spawn_fifo.html), gated by concurrency limit semaphore).
  fn verify_message_signature<V, K, B>(
    &self,
    verifying_key: V,
    key_id: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<SignatureName, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey;

  /// Verify multiple signatures at once
  fn verify_message_signatures<V, K, B>(
    &self,
    key_and_id: &[(V, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey;

  /// Extract all signature bases and signatures contained in the request headers
  fn extract_signatures<B>(
    &self,
    req_for_param: Option<&Request<B>>,
  ) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignature)>, Self::Error>;
}

/* --------------------------------------- */
impl<D> MessageSignature for Request<D>
where
  D: Body,
{
  type Error = HyperSigError;

  /// Check if the request has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    has_message_signature_inner(self.headers())
  }

  /// Extract all signature bases contained in the request headers
  fn get_alg_key_ids(&self) -> HyperSigResult<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>> {
    get_alg_key_ids_inner(self)
  }

  /// Extract all signature params used to generate signature bases contained in the request headers
  fn get_signature_params(&self) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error> {
    get_signature_params_inner(self)
  }

  fn message_headers_mut(&mut self) -> &mut HeaderMap {
    self.headers_mut()
  }
}

/// Default signature name used to indicate signature in http header (`signature` and `signature-input`)
const DEFAULT_SIGNATURE_NAME: &str = "sig";

// No reference to the covered request if response signature base is not intended to cover request.
const NO_REQ_FOR_PARAM: Option<&Request<()>> = None;

impl<D> MessageSignatureReq for Request<D>
where
  D: Body,
{
  type Error = HyperSigError;

  /// Set the http message signature from given http signature params and signing key
  fn set_message_signature<T>(
    &mut self,
    signature_params: HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
  ) -> HyperSigResult<()>
  where
    T: SigningKey,
  {
    self.set_message_signatures([(
      signature_params,
      signing_key,
      signature_name.unwrap_or(DEFAULT_SIGNATURE_NAME),
    )])
  }

  fn set_message_signatures<'a, T, I>(&mut self, params_key_name: I) -> Result<(), Self::Error>
  where
    T: SigningKey + 'a,
    I: IntoIterator<Item = (HttpSignatureParams, &'a T, &'a str)>,
  {
    for (params, key, name) in params_key_name {
      let base = build_signature_base(self, params, NO_REQ_FOR_PARAM)?;
      let headers = base.build_signature_headers(key)?;
      self.set_message_signature_headers([(headers, name)])?;
    }
    Ok(())
  }

  fn build_signature_base(&self, signature_params: HttpSignatureParams) -> HyperSigResult<HttpSignatureBase> {
    build_signature_base(self, signature_params, NO_REQ_FOR_PARAM)
  }

  /// Verify the http message signature with given verifying key if the request has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  fn verify_message_signature<V, K>(&self, verifying_key: V, key_id: Option<&str>) -> HyperSigResult<SignatureName>
  where
    V: AsRef<K>,
    K: VerifyingKey,
  {
    self.verify_message_signatures(&[(verifying_key, key_id)])?.pop().unwrap()
  }

  fn verify_message_signatures<V, K>(
    &self,
    key_and_id: &[(V, Option<&str>)],
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey,
  {
    if !self.has_message_signature() {
      return Err(HyperSigError::NoSignatureHeaders(
        "The request does not have signature and signature-input headers",
      ));
    }
    let map_signature_with_base = self.extract_signatures()?;
    Ok(verify_message_signatures_inner(&map_signature_with_base, key_and_id))
  }

  /// Extract all signature bases and signatures contained in the request headers
  fn extract_signatures(&self) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignature)>, Self::Error> {
    extract_signatures_inner(self, NO_REQ_FOR_PARAM)
  }
}

/* --------------------------------------- */
impl<D> MessageSignature for Response<D>
where
  D: Body,
{
  type Error = HyperSigError;

  /// Check if the response has signature and signature-input headers
  fn has_message_signature(&self) -> bool {
    has_message_signature_inner(self.headers())
  }

  /// Extract all key ids for signature bases contained in the response headers
  fn get_alg_key_ids(&self) -> Result<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>, Self::Error> {
    get_alg_key_ids_inner(self)
  }

  /// Extract all signature params used to generate signature bases contained in the response headers
  fn get_signature_params(&self) -> Result<IndexMap<SignatureName, HttpSignatureParams>, Self::Error> {
    get_signature_params_inner(self)
  }

  fn message_headers_mut(&mut self) -> &mut HeaderMap {
    self.headers_mut()
  }
}

impl<D> MessageSignatureRes for Response<D>
where
  D: Body,
{
  type Error = HyperSigError;

  /// Set the http message signature from given http signature params and signing key
  fn set_message_signature<'a, T, B>(
    &mut self,
    signature_params: HttpSignatureParams,
    signing_key: &T,
    signature_name: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    T: SigningKey + 'a,
  {
    self.set_message_signatures(
      [(
        signature_params,
        signing_key,
        signature_name.unwrap_or(DEFAULT_SIGNATURE_NAME),
      )],
      req_for_param,
    )
  }

  fn set_message_signatures<'a, T, I, B>(
    &mut self,
    params_key_name: I,
    req_for_param: Option<&Request<B>>,
  ) -> Result<(), Self::Error>
  where
    T: SigningKey + 'a,
    I: IntoIterator<Item = (HttpSignatureParams, &'a T, &'a str)>,
  {
    for (params, key, name) in params_key_name {
      let base = build_signature_base(self, params, req_for_param)?;
      let headers = base.build_signature_headers(key)?;
      self.set_message_signature_headers([(headers, name)])?;
    }

    Ok(())
  }

  fn build_signature_base<B>(
    &self,
    signature_params: HttpSignatureParams,
    req_for_param: Option<&Request<B>>,
  ) -> HyperSigResult<HttpSignatureBase> {
    build_signature_base(self, signature_params, req_for_param)
  }

  /// Verify the http message signature with given verifying key if the response has signature and signature-input headers
  /// Return Ok(()) if the signature is valid.
  /// If invalid for the given key or error occurs (like the case where the request does not have signature and/or signature-input headers), return Err.
  /// If key_id is given, it is used to match the key id in signature params
  fn verify_message_signature<V, K, B>(
    &self,
    verifying_key: V,
    key_id: Option<&str>,
    req_for_param: Option<&Request<B>>,
  ) -> Result<SignatureName, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey,
  {
    self
      .verify_message_signatures(&[(verifying_key, key_id)], req_for_param)?
      .pop()
      .unwrap()
  }

  fn verify_message_signatures<V, K, B>(
    &self,
    key_and_id: &[(V, Option<&str>)],
    req_for_param: Option<&Request<B>>,
  ) -> Result<Vec<Result<SignatureName, Self::Error>>, Self::Error>
  where
    V: AsRef<K>,
    K: VerifyingKey,
  {
    if !self.has_message_signature() {
      return Err(HyperSigError::NoSignatureHeaders(
        "The response does not have signature and signature-input headers",
      ));
    }
    let map_signature_with_base = self.extract_signatures(req_for_param)?;
    Ok(verify_message_signatures_inner(&map_signature_with_base, key_and_id))
  }

  /// Extract all signature bases and signatures contained in the response headers
  fn extract_signatures<B>(
    &self,
    req_for_param: Option<&Request<B>>,
  ) -> Result<IndexMap<SignatureName, (HttpSignatureBase, HttpSignature)>, Self::Error> {
    extract_signatures_inner(self, req_for_param)
  }
}

/* --------------------------------------- */
// inner functions
/// has message signature inner function
fn has_message_signature_inner(headers: &HeaderMap) -> bool {
  headers.contains_key("signature") && headers.contains_key("signature-input")
}

/// get key ids inner function
fn get_alg_key_ids_inner<M: HttpMessage>(
  req_or_res: &M,
) -> HyperSigResult<IndexMap<SignatureName, (Option<AlgorithmName>, Option<KeyId>)>> {
  let signature_headers_map = extract_signature_headers_with_name(req_or_res)?;
  let res = signature_headers_map
    .into_iter()
    .map(|(name, headers)| {
      // Unknown or unsupported algorithm strings are mapped to None
      let (_, params) = headers.into_signature_and_params();
      let alg = params
        .alg
        .as_ref()
        .map(|a| AlgorithmName::from_str(a))
        .transpose()
        .ok()
        .flatten();
      let key_id = params.keyid;
      (name, (alg, key_id))
    })
    .collect();
  Ok(res)
}

/// get signature params inner function
fn get_signature_params_inner<M: HttpMessage>(req_or_res: &M) -> HyperSigResult<IndexMap<SignatureName, HttpSignatureParams>> {
  let signature_headers_map = extract_signature_headers_with_name(req_or_res)?;
  let res = signature_headers_map
    .into_iter()
    .map(|(name, headers)| (name, headers.into_signature_and_params().1))
    .collect();
  Ok(res)
}

/// extract signatures inner function
fn extract_signatures_inner<M: HttpMessage, B>(
  req_or_res: &M,
  req_for_param: Option<&Request<B>>,
) -> HyperSigResult<IndexMap<SignatureName, (HttpSignatureBase, HttpSignature)>> {
  let signature_headers_map = extract_signature_headers_with_name(req_or_res)?;
  let extracted = signature_headers_map
    .into_iter()
    .filter_map(|(name, headers)| {
      let (signature, params) = headers.into_signature_and_params();
      build_signature_base(req_or_res, params, req_for_param)
        .ok()
        .map(|base| (name, (base, signature)))
    })
    .collect();
  Ok(extracted)
}

/// Verify multiple signatures inner function
fn verify_message_signatures_inner<V, K>(
  map_signature_with_base: &IndexMap<SignatureName, (HttpSignatureBase, HttpSignature)>,
  key_and_id: &[(V, Option<&str>)],
) -> Vec<HyperSigResult<SignatureName>>
where
  V: AsRef<K>,
  K: VerifyingKey,
{
  let mut operator = HttpSignatureBaseOperator::default();
  // verify for each key_and_id tuple
  key_and_id
    .iter()
    .map(|(key, key_id)| {
      let mut signature_is_present = false;
      // check if any one of the signature headers is valid
      let id_base_key_signatures = map_signature_with_base.iter().filter_map(|(name, (base, signature))| {
        if key_id.is_none() || base.keyid() == *key_id {
          signature_is_present = true;
          Some((name, base, key, signature))
        } else {
          None
        }
      });
      let first_successful = operator.verify_signatures(id_base_key_signatures);
      if !signature_is_present {
        return Err(HyperSigError::NoSignatureHeaders(
          "No signature as appropriate target for verification",
        ));
      }
      if let Some(first_successful) = first_successful {
        Ok(first_successful.clone())
      } else {
        Err(HyperSigError::InvalidSignature("Invalid signature for the verifying key"))
      }
    })
    .collect()
}

/* --------------------------------------- */

/// [`HttpMessage`] represents http request or response message we sign or verify.
trait HttpMessage {
  fn message_method(&self) -> HyperSigResult<&http::Method>;
  fn message_uri(&self) -> HyperSigResult<&http::Uri>;
  fn message_headers(&self) -> &HeaderMap;
  fn message_status(&self) -> HyperSigResult<http::StatusCode>;
  /// Validation callback for HTTP Message, containing a component with `req` param.
  fn on_message_component_req_param(&self, caller_provided_request: bool) -> HyperSigResult<()>;
  /// Validation callback for HTTP Message, containing a derived component with `req` param.
  fn on_message_derived_component_req_param(&self) -> HyperSigResult<()>;
  /// Validation callback for HTTP Message, containing a derived component.
  fn on_message_derived_component(
    &self,
    derived_name: &DerivedComponentName,
    component_id: &HttpMessageComponentId,
  ) -> HyperSigResult<()>;
}

impl<B> HttpMessage for Request<B> {
  fn message_method(&self) -> HyperSigResult<&http::Method> {
    Ok(self.method())
  }

  fn message_uri(&self) -> HyperSigResult<&http::Uri> {
    Ok(self.uri())
  }

  fn message_headers(&self) -> &HeaderMap {
    self.headers()
  }

  fn message_status(&self) -> HyperSigResult<http::StatusCode> {
    Err(HyperSigError::InvalidComponentName("`status` is only for response".into()))
  }

  fn on_message_component_req_param(&self, _caller_provided_request: bool) -> HyperSigResult<()> {
    Err(HyperSigError::InvalidComponentParam("`req` is not allowed in request".into()))
  }

  fn on_message_derived_component_req_param(&self) -> HyperSigResult<()> {
    Ok(())
  }

  fn on_message_derived_component(
    &self,
    derived_name: &DerivedComponentName,
    _component_id: &HttpMessageComponentId,
  ) -> HyperSigResult<()> {
    if matches!(derived_name, DerivedComponentName::Status) {
      Err(HyperSigError::InvalidComponentName("`status` is only for response".into()))
    } else {
      Ok(())
    }
  }
}

impl<B> HttpMessage for Response<B> {
  fn message_method(&self) -> HyperSigResult<&http::Method> {
    Err(HyperSigError::InvalidComponentName("`method` is only for request".into()))
  }

  fn message_uri(&self) -> HyperSigResult<&http::Uri> {
    Err(HyperSigError::InvalidComponentName("`uri` is only for request".into()))
  }

  fn message_headers(&self) -> &HeaderMap {
    self.headers()
  }

  fn message_status(&self) -> HyperSigResult<http::StatusCode> {
    Ok(self.status())
  }

  fn on_message_component_req_param(&self, caller_provided_request: bool) -> HyperSigResult<()> {
    if caller_provided_request {
      Ok(())
    } else {
      Err(HyperSigError::InvalidComponentParam(
        "`req` is required for the param but no request is provided".into(),
      ))
    }
  }

  fn on_message_derived_component_req_param(&self) -> HyperSigResult<()> {
    Err(HyperSigError::InvalidComponentParam(
      "`req`-tagged component must be extracted from the source request".into(),
    ))
  }

  fn on_message_derived_component(
    &self,
    derived_name: &DerivedComponentName,
    component_id: &HttpMessageComponentId,
  ) -> HyperSigResult<()> {
    let has_req = component_id.params.0.contains(&HttpMessageComponentParam::Req);
    if has_req {
      // `@status` must not have `req` parameter
      if matches!(derived_name, DerivedComponentName::Status) {
        Err(HyperSigError::InvalidComponentParam(
          "`@status` does not accept `req` parameter".to_string(),
        ))
      } else {
        Ok(())
      }
    } else {
      // Response messages can use `@status` and `@signature-params` directly,
      // or any request-derived component with the `req` parameter (RFC 9421 §2.4).
      if !matches!(
        derived_name,
        DerivedComponentName::Status | DerivedComponentName::SignatureParams
      ) {
        Err(HyperSigError::InvalidComponentName(
          "derived components other than `@status` and `@signature-params` require `req` parameter for response".into(),
        ))
      } else {
        Ok(())
      }
    }
  }
}

/// Extract signature and signature-input with signature-name indication from http request and response
fn extract_signature_headers_with_name<M: HttpMessage>(req_or_res: &M) -> HyperSigResult<HttpSignatureHeadersMap> {
  let headers = req_or_res.message_headers();
  if !(headers.contains_key("signature-input") && headers.contains_key("signature")) {
    return Err(HyperSigError::NoSignatureHeaders(
      "The request does not have signature and signature-input headers",
    ));
  };

  let signature_input_strings = headers
    .get_all("signature-input")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()?
    .join(", ");
  let signature_strings = headers
    .get_all("signature")
    .iter()
    .map(|v| v.to_str())
    .collect::<Result<Vec<_>, _>>()?
    .join(", ");

  let signature_headers = HttpSignatureHeaders::try_parse(&signature_strings, &signature_input_strings)?;
  Ok(signature_headers)
}

/// Build signature base from hyper http request/response and signature params
/// - req_or_res: the hyper http request or response
/// - signature_params: the http signature params
/// - req_for_param: corresponding request to be considered in the signature base in response
fn build_signature_base<M: HttpMessage, B>(
  req_or_res: &M,
  signature_params: HttpSignatureParams,
  req_for_param: Option<&Request<B>>,
) -> HyperSigResult<HttpSignatureBase> {
  let caller_provided_request = req_for_param.is_some();
  let component_lines = signature_params
    .covered_components
    .iter()
    .map(|component_id| {
      if component_id.params.0.contains(&HttpMessageComponentParam::Req) {
        req_or_res.on_message_component_req_param(caller_provided_request)?;
        let req = req_for_param.expect("None case handled above");
        extract_http_message_component(req, component_id)
      } else {
        extract_http_message_component(req_or_res, component_id)
      }
    })
    .collect::<Result<Vec<_>, _>>()?;

  HttpSignatureBase::try_new(component_lines, signature_params).map_err(|e| e.into())
}

/// Extract http field from hyper http request/response
fn extract_http_field<M: HttpMessage>(req_or_res: &M, id: &HttpMessageComponentId) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::HttpField(header_name) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as http field".into(),
    ));
  };
  let headers = req_or_res.message_headers();

  let field_values = headers
    .get_all(header_name.as_str())
    .iter()
    .map(|v| v.to_str().map(|s| s.to_compact_string()))
    .collect::<Result<Vec<_>, _>>()?;

  HttpMessageComponent::try_from((id, field_values)).map_err(|e| e.into())
}

/// Extract derived component from hyper http request/response
fn extract_derived_component<M: HttpMessage>(
  req_or_res: &M,
  id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  let HttpMessageComponentName::Derived(derived_name) = &id.name else {
    return Err(HyperSigError::InvalidComponentName(
      "invalid http message component name as derived component".into(),
    ));
  };
  // Validate parameters allowed on derived components (RFC 9421).
  // - `name`: only valid on `@query-param`
  // - `req`: only valid on response messages (to reference request-derived components, §2.4)
  // - `sf`, `key`, `bs`, `tr`: only valid on HTTP field components, not derived components
  id.params.0.iter().try_for_each(|param| match param {
    HttpMessageComponentParam::Name(_) if matches!(derived_name, DerivedComponentName::QueryParam) => Ok(()),
    HttpMessageComponentParam::Name(_) => Err(HyperSigError::InvalidComponentParam(
      "`name` parameter is only allowed for `@query-param`".to_string(),
    )),
    // `req` is only meaningful in response signatures (RFC 9421 §2.4).
    // `build_signature_base` already validates this and re-dispatches extraction against the
    // original request, so `req_or_res` here should always be `Request`.
    // Guard against misuse by callers that bypass `build_signature_base`.
    HttpMessageComponentParam::Req => req_or_res.on_message_derived_component_req_param(),
    _ => Err(HyperSigError::InvalidComponentParam(format!(
      "parameter `{param}` is not allowed on derived components",
    ))),
  })?;

  req_or_res.on_message_derived_component(derived_name, id)?;

  let field_values: Vec<CompactString> = match derived_name {
    DerivedComponentName::Method => vec![req_or_res.message_method()?.as_str().to_compact_string()],
    DerivedComponentName::TargetUri => vec![req_or_res.message_uri()?.to_compact_string()],
    DerivedComponentName::Authority => vec![
      req_or_res
        .message_uri()?
        .authority()
        .map(|s| s.to_compact_string())
        .unwrap_or("".to_compact_string()),
    ],
    DerivedComponentName::Scheme => vec![req_or_res.message_uri()?.scheme_str().unwrap_or("").to_compact_string()],
    DerivedComponentName::RequestTarget => match *req_or_res.message_method()? {
      http::Method::CONNECT => vec![
        req_or_res
          .message_uri()?
          .authority()
          .map(|s| s.to_compact_string())
          .unwrap_or("".to_compact_string()),
      ],
      http::Method::OPTIONS => vec!["*".to_compact_string()],
      _ => vec![
        req_or_res
          .message_uri()?
          .path_and_query()
          .map(|s| s.to_compact_string())
          .unwrap_or("".to_compact_string()),
      ],
    },
    DerivedComponentName::Path => vec![{
      let p = req_or_res.message_uri()?.path();
      if p.is_empty() {
        "/".to_compact_string()
      } else {
        p.to_compact_string()
      }
    }],
    DerivedComponentName::Query => vec![
      req_or_res
        .message_uri()?
        .query()
        .map(|v| format_compact!("?{v}"))
        .unwrap_or("?".to_compact_string()),
    ],
    DerivedComponentName::QueryParam => {
      let query = req_or_res.message_uri()?.query().unwrap_or("");
      query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_compact_string())
        .collect::<Vec<_>>()
    }
    DerivedComponentName::Status => vec![req_or_res.message_status()?.as_str().to_compact_string()],
    DerivedComponentName::SignatureParams => req_or_res
      .message_headers()
      .get_all("signature-input")
      .iter()
      .map(|v| v.to_str().unwrap_or("").to_compact_string())
      .collect::<Vec<_>>(),
  };

  HttpMessageComponent::try_from((id, field_values)).map_err(|e| e.into())
}

/* --------------------------------------- */
/// Extract http message component from hyper http request
fn extract_http_message_component<M: HttpMessage>(
  req_or_res: &M,
  target_component_id: &HttpMessageComponentId,
) -> HyperSigResult<HttpMessageComponent> {
  match &target_component_id.name {
    HttpMessageComponentName::HttpField(_) => extract_http_field(req_or_res, target_component_id),
    HttpMessageComponentName::Derived(_) => extract_derived_component(req_or_res, target_component_id),
  }
}

/* --------------------------------------- */
#[cfg(all(test, feature = "digest-sha256"))]
#[path = "hyper_http_tests.rs"]
mod tests;
