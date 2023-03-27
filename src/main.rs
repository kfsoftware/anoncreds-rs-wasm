use anoncreds::issuer;
use anoncreds::types::CredentialDefinitionConfig;
use anoncreds::data_types::cred_def::SignatureType;
use anoncreds::ffi::anoncreds_set_default_logger;

pub fn main() {
    anoncreds_set_default_logger();
    let schema = issuer::create_schema(
        "name",
        "1.0",
        "did:example",
        vec!["name".to_owned(), "age".to_owned()].into(),
    )
    .expect("Unable to create Schema");

    let result = issuer::create_credential_definition(
        "did:example/schema",
        &schema,
        "did:exampple",
        "default-tag",
        SignatureType::CL,
        CredentialDefinitionConfig::default(),
    );

    assert!(result.is_ok());
}
