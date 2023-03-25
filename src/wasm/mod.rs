extern crate console_error_panic_hook;

use std::str::FromStr;

use wasm_bindgen::prelude::*;
use wasm_logger;

use crate::utils::validation::Validatable;
use crate::data_types::cred_def::SignatureType;
use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::schema::Schema;
use crate::services::issuer;
use crate::types::CredentialDefinitionConfig;

mod error;
use self::error::ErrorCode;

#[wasm_bindgen(js_name = anoncredsSetDefaultLogger)]
pub fn anoncreds_set_default_logger() -> ErrorCode {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Trace));
    debug!("Initialized default logger");

    ErrorCode::Success
}

#[wasm_bindgen(js_name = anoncredsCreateSchema)]
pub fn anoncreds_create_schema(
    name: &str,
    version: &str,
    issuer_id: &str,
    attribute_names: Vec<JsValue>,
) -> JsValue {
    let mut attribute_names_vec: Vec<String> = vec![];

    for name in &attribute_names {
        let name = name.as_string();
        if let Some(name) = name {
            attribute_names_vec.push(name.to_owned());
        }
    }

    let schema =
        issuer::create_schema(name, version, issuer_id, attribute_names_vec.into()).unwrap();

    serde_wasm_bindgen::to_value(&schema).unwrap()
}

#[wasm_bindgen(js_name = anoncredsCreateCredentialDefinition)]
pub fn anoncreds_create_credential_definition(
    schema_id: &str,
    schema: JsValue,
    tag: &str,
    issuer_id: &str,
    signature_type: &str,
    support_revocation: bool,
) -> Vec<JsValue> {
    let schema: Schema = serde_wasm_bindgen::from_value(schema).unwrap();
    let signature_type = SignatureType::from_str(signature_type)
        .map_err(err_map!(Input))
        .unwrap();
    let (cred_def, cred_def_pvt, key_proof) = issuer::create_credential_definition(
        schema_id,
        &schema,
        issuer_id,
        tag,
        signature_type,
        CredentialDefinitionConfig { support_revocation },
    )
    .unwrap();

    let cred_def = serde_wasm_bindgen::to_value(&cred_def).unwrap();
    let cred_def_pvt = serde_wasm_bindgen::to_value(&cred_def_pvt).unwrap();
    let key_proof = serde_wasm_bindgen::to_value(&key_proof).unwrap();

    vec![cred_def, cred_def_pvt, key_proof]
}

#[wasm_bindgen(js_name = anoncredsValidateCredentialDefinitionFromJson)]
pub fn anoncreds_validate_credential_definition_from_json(
    json: JsValue
) -> Result<bool, JsValue> {
    let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(json).map_err(|e| <serde_wasm_bindgen::Error as Into<JsValue>>::into(e))?;
    cred_def.validate().map(|_| true).map_err(|e| JsValue::from_str(&e.to_string()))
}
