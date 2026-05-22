//! Benches of httpsig-hyper interface.

use criterion::{Criterion, criterion_group, criterion_main};
use http::Request;
use http_body_util::Full;
use httpsig_hyper::{
  ContentDigestType, HyperDigestError, MessageSignatureReq, RequestContentDigest,
  prelude::{SharedKey, message_component::HttpMessageComponentId},
};

use httpsig::prelude::{AlgorithmName, HttpSignatureParams};

const HMACSHA256_SECRET_KEY: &str =
  r##"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="##;

const COVERED_COMPONENTS_REQ: &[&str] = &["@method", "date", "content-type", "content-digest"];

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, HyperDigestError>;

async fn build_request() -> Request<BoxBody> {
  let body = Full::new(&b"{\"hello\": \"world\"}"[..]);
  let req = Request::builder()
    .method("GET")
    .uri("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
    .header("date", "Sun, 09 May 2021 18:30:00 GMT")
    .header("content-type", "application/json")
    .header("content-type", "application/json-patch+json")
    .body(body)
    .unwrap();
  req.set_content_digest(&ContentDigestType::Sha256).await.unwrap()
}

fn build_covered_components_req() -> Vec<HttpMessageComponentId> {
  COVERED_COMPONENTS_REQ
    .iter()
    .map(|&s| HttpMessageComponentId::try_from(s).unwrap())
    .collect()
}

fn setup_sign_verify() -> (Request<BoxBody>, SharedKey, HttpSignatureParams) {
  let req = futures::executor::block_on(build_request());
  let shared_key = SharedKey::from_base64(&AlgorithmName::HmacSha256, HMACSHA256_SECRET_KEY).unwrap();
  let mut signature_params = HttpSignatureParams::try_new(&build_covered_components_req()).unwrap();
  signature_params.set_key_info(&shared_key);
  // Random nonce is highly recommended for HMAC
  signature_params.set_random_nonce();
  (req, shared_key, signature_params)
}

fn sign_verify(req: &mut Request<BoxBody>, shared_key: &SharedKey, signature_params: HttpSignatureParams) {
  futures::executor::block_on(req.set_message_signature(signature_params, shared_key, None)).unwrap();
  futures::executor::block_on(req.verify_message_signature(shared_key, None)).unwrap();
}

fn bench_sign_verify(c: &mut Criterion) {
  c.bench_function("hmac-sha256 sign-verify", |b| {
    b.iter_batched(
      || setup_sign_verify(),
      |(mut req, shared_key, signature_params)| sign_verify(&mut req, &shared_key, signature_params),
      criterion::BatchSize::SmallInput,
    )
  });
}

criterion_group!(benches, bench_sign_verify);
criterion_main!(benches);
