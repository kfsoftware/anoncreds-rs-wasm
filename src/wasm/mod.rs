extern crate console_error_panic_hook;

use std::collections::HashMap;
use std::ptr;
use std::str;
use std::str::FromStr;
use bitvec::macros::internal::funty::Fundamental;
use serde_json::Value::Object;

use wasm_bindgen::prelude::*;

use wasm_logger;
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};

use crate::utils::validation::Validatable;
use crate::data_types::cred_def::{CredentialDefinitionId, SignatureType};
use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::schema::{Schema, SchemaId};
use crate::services::issuer;
use crate::types::{CredentialDefinitionConfig, CredentialDefinitionPrivate, PresentationRequest, Presentation, CredentialOffer, CredentialRequest, CredentialRequestMetadata, LinkSecret, CredentialKeyCorrectnessProof as KeyCorrectnessProof, Credential, RevocationRegistryDefinition, PresentCredentials};
use crate::prover::{create_credential_request, create_link_secret, create_presentation, process_credential};
use crate::wasm::object::{AnoncredsObject, AnoncredsObjectList, AnyAnoncredsObject, ObjectHandle, ToJson};
use js_sys::{Array, ArrayBuffer, Uint8Array};


mod error;
#[macro_use]
mod object;
#[macro_use]
mod macros;

use self::error::ErrorCode;
impl_anoncreds_object!(Credential, "Credential");
impl_anoncreds_object_from_json!(Credential, anoncreds_credential_from_json);

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
    let schema = issuer::create_schema(name, version, issuer_id, attribute_names_vec.into()).unwrap();
    serde_wasm_bindgen::to_value(&schema).unwrap()
}

#[wasm_bindgen(js_name = anoncredsCreateLinkSecret)]
pub fn anoncreds_create_link_secret() -> JsValue {
    let secret = create_link_secret().unwrap();
    let dec_secret: String = secret.try_into().unwrap();

    serde_wasm_bindgen::to_value(&dec_secret).unwrap()
}

// #[wasm_bindgen(js_name = anoncredsCredentialRequestFromJson)]
// pub fn test(
//
// ) -> JsValue {
//     let res = create_credential_request(
//         ENTROPY,
//         None,
//         &cred_def,
//         &link_secret,
//         LINK_SECRET_ID,
//         &credential_offer,
//     );
// }
#[derive(Serialize, Deserialize)]
pub struct CredentialRequestResponse {
    pub cred_req: u8,
    pub cred_req_metadata: u8,
}

// convert &str to option
fn str_to_option(str: &str) -> Option<&str> {
    if str.is_empty() {
        None
    } else {
        Some(str)
    }
}

#[wasm_bindgen(js_name = anoncredsCreateCredentialRequest)]
pub fn anoncreds_create_credential_request(
    entropy: &str,
    prover_did: &str,
    cred_def_p: usize,
    link_secret: &str,
    link_secret_id: &str,
    cred_offer_p: usize,
) -> Result<JsValue, JsValue> {
    let link_secret = link_secret;
    let link_secret = LinkSecret::try_from(link_secret).unwrap();

    let cred_def_anoncreds = ObjectHandle(cred_def_p).load().unwrap();
    let cred_def = cred_def_anoncreds.cast_ref::<CredentialDefinition>().unwrap();


    let cred_offer_anoncreds = ObjectHandle(cred_offer_p).load().unwrap();
    let cred_offer = cred_offer_anoncreds.cast_ref::<CredentialOffer>().unwrap();

    log("pre cred_req created");
    let (cred_req, cred_req_metadata) = create_credential_request(
        str_to_option(entropy),
        str_to_option(prover_did),
        &cred_def,
        &link_secret,
        link_secret_id,
        &cred_offer,
    ).map_err(|err| JsValue::from_str(&err.to_string()))?;
    log("cred_req created");
    let cred_req_object = ObjectHandle::create(cred_req).unwrap();
    let cred_req_metadata_object = ObjectHandle::create(cred_req_metadata).unwrap();
    let cred_req_res = CredentialRequestResponse {
        cred_req: cred_req_object.as_u8(),
        cred_req_metadata: cred_req_metadata_object.as_u8(),
    };
    Ok(serde_wasm_bindgen::to_value(&cred_req_res)?)
}


#[wasm_bindgen(js_name = anoncreds_credential_get_attribute)]
pub fn anoncreds_credential_get_attribute(
    handle: usize,
    name: &str,
) -> Result<JsValue, JsValue> {
    let cred_anoncreds = ObjectHandle(handle).load().unwrap();
    let mut cred = cred_anoncreds.cast_ref::<Credential>().unwrap();

    let val: String = match name {
        "schema_id" => cred.schema_id.clone().to_string(),
        "cred_def_id" => cred.cred_def_id.to_string(),
        "rev_reg_id" => cred
            .rev_reg_id
            .as_ref()
            .map_or("".to_string(), |s| s.to_string()),
        "rev_reg_index" => cred
            .signature
            .extract_index()
            .map_or("".to_string(), |s| s.to_string()),
        s => return Err(JsValue::from_str(format!("Unsupported attribute: {}", s).as_str())),
    };
    Ok(serde_wasm_bindgen::to_value(&val)?)
}


impl_anoncreds_object!(Schema, "Schema");
impl_anoncreds_object_from_json!(Schema, anoncreds_schema_from_json);

impl_anoncreds_object!(CredentialRequest, "CredentialRequest");
impl_anoncreds_object_from_json!(CredentialRequest, anoncreds_credential_request_from_json);

impl_anoncreds_object!(CredentialRequestMetadata, "CredentialRequestMetadata");
impl_anoncreds_object_from_json!(
    CredentialRequestMetadata,
    anoncreds_credential_request_metadata_from_json
);

impl_anoncreds_object!(Presentation, "Presentation");
impl_anoncreds_object_from_json!(Presentation, anoncreds_presentation_from_json);

impl_anoncreds_object!(PresentationRequest, "PresentationRequest");
impl_anoncreds_object_from_json!(
    PresentationRequest,
    anoncreds_presentation_request_from_json
);

impl_anoncreds_object!(CredentialOffer, "CredentialOffer");
impl_anoncreds_object_from_json!(CredentialOffer, anoncreds_credential_offer_from_json);

impl_anoncreds_object!(CredentialDefinition, "CredentialDefinition");
impl_anoncreds_object_from_json!(
    CredentialDefinition,
    anoncreds_credential_definition_from_json
);

impl_anoncreds_object!(CredentialDefinitionPrivate, "CredentialDefinitionPrivate");
impl_anoncreds_object_from_json!(
    CredentialDefinitionPrivate,
    anoncreds_credential_definition_private_from_json
);

impl_anoncreds_object!(KeyCorrectnessProof, "KeyCorrectnessProof");
impl_anoncreds_object_from_json!(
    KeyCorrectnessProof,
    anoncreds_key_correctness_proof_from_json
);

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}


#[wasm_bindgen]
pub fn anoncreds_object_get_json(
    p: usize,
) -> Result<JsValue, JsValue> {
    // check_useful_c_ptr!(result_p);
    let mut handle: ObjectHandle = ObjectHandle(p);
    let obj = handle.load().unwrap().to_json().unwrap();
    let s = str::from_utf8(&obj).unwrap();
    Ok(serde_wasm_bindgen::to_value(s)?)
}


#[derive(Serialize, Deserialize)]
pub struct ProcessCredentialResponse {
    pub cred: u8,
}

#[wasm_bindgen(js_name = anoncreds_process_credential)]
pub fn anoncreds_process_credential(
    cred_p: usize,
    cred_req_metadata_p: usize,
    link_secret: &str,
    cred_def_p: usize,
    rev_reg_def_p: usize,
) -> Result<JsValue, JsValue> {
    // let link_secret = link_secret;
    let link_secret = LinkSecret::try_from(link_secret).unwrap();


    let cred_anoncreds = ObjectHandle(cred_p).load().unwrap();
    let mut cred = cred_anoncreds.cast_ref::<Credential>().unwrap().try_clone().unwrap();

    let cred_def_anoncreds = ObjectHandle(cred_def_p).load().unwrap();
    let cred_def = cred_def_anoncreds.cast_ref::<CredentialDefinition>().unwrap();


    let cred_req_metadata_anoncreds = ObjectHandle(cred_req_metadata_p).load().unwrap();
    let cred_req_metadata = cred_req_metadata_anoncreds.cast_ref::<CredentialRequestMetadata>().unwrap();

    let rev_reg_def_anoncreds = ObjectHandle(rev_reg_def_p);
    // .load().unwrap();
    // let rev_reg_def = rev_reg_def_anoncreds.cast_ref::<RevocationRegistryDefinition>().unwrap();

    // let mut cred = cred
    //     .load()?
    //     .cast_ref::<Credential>()?
    //     .try_clone()
    //     .map_err(err_map!(Unexpected, "Error copying credential"))?;
    process_credential(
        &mut cred,
        cred_req_metadata,
        &link_secret,
        cred_def,
        None,
        // rev_reg_def_anoncreds
        //     .opt_load()
        //     .unwrap()
        //     .as_ref()
        //     .map(AnoncredsObject::cast_ref)
        //     .transpose().unwrap(),
    ).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let cred_handle = ObjectHandle::create(cred).unwrap();
    let cred_res = ProcessCredentialResponse {
        cred: cred_handle.as_u8(),
    };
    Ok(serde_wasm_bindgen::to_value(&cred_res)?)
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

#[wasm_bindgen(js_name = anoncredsCreateCredentialDefinitionFromJson)]
pub fn anoncreds_create_credential_definition_from_json(
    json: JsValue
) -> JsValue {
    let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(json).map_err(|e| <serde_wasm_bindgen::Error as Into<JsValue>>::into(e)).unwrap();
    serde_wasm_bindgen::to_value(&cred_def).unwrap()
}

#[wasm_bindgen(js_name = anoncredsCreateCredentialOfferFromJson)]
pub fn anoncreds_create_credential_offer_from_json(
    json: JsValue
) -> JsValue {
    let cred_offer: CredentialOffer = serde_wasm_bindgen::from_value(json).map_err(|e| <serde_wasm_bindgen::Error as Into<JsValue>>::into(e)).unwrap();

    serde_wasm_bindgen::to_value(&cred_offer).unwrap()
}

#[wasm_bindgen(js_name = anoncredsValidateCredentialDefinitionFromJson)]
pub fn anoncreds_validate_credential_definition_from_json(
    json: JsValue
) -> Result<bool, JsValue> {
    let cred_def: CredentialDefinition = serde_wasm_bindgen::from_value(json).map_err(|e| <serde_wasm_bindgen::Error as Into<JsValue>>::into(e))?;
    cred_def.validate().map(|_| true).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct WASMCredentialEntry {
    credential: usize,
    timestamp: i32,
    rev_state: usize,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct WasmCredentialProve {
    entry_idx: i64,
    referent: String,
    is_predicate: bool,
    reveal: bool,
}

struct CredentialEntry {
    credential: AnoncredsObject,
    timestamp: Option<u64>,
    rev_state: Option<AnoncredsObject>,
}

#[wasm_bindgen(js_name = anoncredsCreatePresentation)]
pub fn anoncreds_create_presentation(
    pres_req_p: usize,
    credentials: JsValue,
    credentials_prove: JsValue,
    self_attest_names: Vec<JsValue>,
    self_attest_values: Vec<JsValue>,
    link_secret: &str,
    schemas: Vec<usize>,
    schema_ids: Vec<JsValue>,
    cred_defs: Vec<usize>,
    cred_def_ids: Vec<JsValue>,
    // presentation_p: *mut usize,
) -> Result<JsValue, JsValue> {
    let link_secret = LinkSecret::try_from(link_secret).unwrap();

    if schemas.len() != schema_ids.len() {
        return Err(JsValue::from_str(err_msg!("Inconsistent lengths for schemas and schemas ids").to_string().as_str()));
    }

    if cred_defs.len() != cred_def_ids.len() {
        return Err(JsValue::from_str(err_msg!(
                "Inconsistent lengths for cred defs and cred def ids"
            ).to_string().as_str()));
    }

    log("before credentials");
    let credentials: Vec<WASMCredentialEntry> = serde_wasm_bindgen::from_value(credentials)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let credentials_prove: Vec<WasmCredentialProve> = serde_wasm_bindgen::from_value(credentials_prove)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;


    log("after credentials");
    if self_attest_names.len() != self_attest_values.len() {
        return Err(JsValue::from_str(err_msg!(
            "Inconsistent lengths for self-attested value parameters"
        ).to_string().as_str()));
    }


    log("before entries");
    let entries = {
        let credentials = credentials.as_slice();
        credentials.iter().try_fold(
            Vec::with_capacity(credentials.len()),
            |mut r, wasm_entry| {
                let cred_anoncreds = ObjectHandle(wasm_entry.credential).load().unwrap();

                // let credential = self.credential.load()?;
                let timestamp = if wasm_entry.timestamp < 0 {
                    None
                } else {
                    Some(wasm_entry.timestamp as u64)
                };
                let rev_state = None;
                r.push(CredentialEntry {
                    credential: cred_anoncreds,
                    timestamp,
                    rev_state,
                });
                Result::<Vec<CredentialEntry>, &str>::Ok(r)
            },
        )?
    };
    log("after entries");
    log("before self_attested");

    let self_attested = if self_attest_names.is_empty() {
        None
    } else {
        let mut self_attested = HashMap::new();
        for (name, raw) in self_attest_names
            .as_slice()
            .iter()
            .zip(self_attest_values.as_slice())
        {
            let name = name.as_string()
                .ok_or_else(|| JsValue::from_str(err_msg!("Missing attribute name").to_string().as_str()))?
                .to_string();
            let raw = raw.as_string()
                .ok_or_else(|| JsValue::from_str(err_msg!("Missing attribute raw value").to_string().as_str()))?
                .to_string();
            self_attested.insert(name, raw);
        }
        Some(self_attested)
    };
    log("after self_attested");

    let mut schema_identifiers: Vec<SchemaId> = vec![];
    for schema_id in schema_ids.as_slice()
        .iter() {
        let s = SchemaId::new(schema_id.as_string()
            .ok_or_else(|| JsValue::from_str("Schema ID not a string"))?)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;
        schema_identifiers.push(s);
    }

    log(format!("schema identifiers {:?}", schema_identifiers).as_str());
    let schema_object_handles: Vec<ObjectHandle> = schemas.iter().map(|u| ObjectHandle(*u)).collect();
    let schemas = AnoncredsObjectList::load(schema_object_handles.as_slice())
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let mut cred_def_identifiers: Vec<CredentialDefinitionId> = vec![];
    for cred_def_id in cred_def_ids.as_slice()
        .iter() {
        let cred_def_id = CredentialDefinitionId::new(
            cred_def_id.as_string()
                .ok_or_else(|| JsValue::from_str("Schema ID not a string"))?
        ).map_err(|err| JsValue::from_str(&err.to_string()))?;
        cred_def_identifiers.push(cred_def_id);
    }
    log(format!("cred def identifiers {:?}", cred_def_identifiers).as_str());

    let cred_def_object_handles: Vec<ObjectHandle> = cred_defs.iter().map(|u| ObjectHandle(*u)).collect();
    let cred_defs = AnoncredsObjectList::load(cred_def_object_handles.as_slice())
        .map_err(|err| JsValue::from_str(&err.to_string()))
        .unwrap();
    log("after cred defs ");

    let schemas = schemas.refs_map::<SchemaId, Schema>(&schema_identifiers)
        .map_err(|err| JsValue::from_str(&err.to_string())).unwrap();
    let cred_defs = cred_defs
        .refs_map::<CredentialDefinitionId, CredentialDefinition>(&cred_def_identifiers)
        .map_err(|err| JsValue::from_str(&err.to_string())).unwrap();

    let pres_req_anoncreds = ObjectHandle(pres_req_p).load()
        .map_err(|err| JsValue::from_str(&err.to_string()))
        .unwrap();
    let pres_req = pres_req_anoncreds.cast_ref::<PresentationRequest>()
        .map_err(|err| JsValue::from_str(&err.to_string()))
        .unwrap();


    let mut present_creds = PresentCredentials::default();
    log(format!("entries {:?}", entries.len()).as_str());
    for (entry_idx, entry) in entries.iter().enumerate() {
        let mut add_cred = present_creds.add_credential(
            entry.credential.cast_ref::<Credential>()
                .map_err(|err| JsValue::from_str(&err.to_string()))?,
            entry.timestamp,
            None,
        );

        for prove in credentials_prove.as_slice() {
            if prove.entry_idx < 0 {
                return Err(JsValue::from_str(err_msg!("Invalid credential index").to_string().as_str()));
            }
            if prove.entry_idx as usize != entry_idx {
                continue;
            }

            let referent = prove
                .referent
                .to_string();
            log(format!("Referent {} isPredicate: {}", prove.referent.as_str(), prove.is_predicate).as_str());
            if !prove.is_predicate {
                add_cred.add_requested_attribute(referent, prove.reveal);
            } else {
                add_cred.add_requested_predicate(referent);
            }
        }
    }

    log(format!("pres_req {}", str::from_utf8(
        pres_req_anoncreds.to_json()
            .map_err(|err| JsValue::from_str(&err.to_string()))?.as_slice()
    ).unwrap()
    ).as_str());
    log("before create presentation");
    let presentation = create_presentation(
        &pres_req,
        present_creds,
        self_attested,
        &link_secret,
        &schemas,
        &cred_defs,
    )
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    log("after create presentation");
    let presentation_object = ObjectHandle::create(presentation).unwrap();
    Ok(JsValue::from_str(presentation_object.as_u8().to_string().as_str()))
}
