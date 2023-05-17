use std::any::TypeId;
use std::cmp::Eq;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use bitvec::macros::internal::funty::Fundamental;
use wasm_bindgen::prelude::*;
use wasm_logger;

use ffi_support::{rust_string_to_c, ByteBuffer};
use once_cell::sync::Lazy;
use serde::Serialize;
use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, WasmAbi};
use wasm_bindgen::describe::WasmDescribe;

use super::error::{catch_error, ErrorCode};
use crate::error::Result;
use crate::new_handle_type;

pub static FFI_OBJECTS: Lazy<Mutex<BTreeMap<ObjectHandle, AnoncredsObject>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

new_handle_type!(ObjectHandle, FFI_OBJECT_COUNTER);
unsafe impl WasmAbi for ObjectHandle {}

impl WasmDescribe for ObjectHandle {
    fn describe() {
        JsValue::describe();
    }
}

impl IntoWasmAbi for ObjectHandle {
    type Abi = ObjectHandle;
    fn into_abi(self) -> ObjectHandle { self }
}

impl FromWasmAbi for ObjectHandle {
    type Abi = ObjectHandle;
    unsafe fn from_abi(js: ObjectHandle) -> ObjectHandle { js }
}


impl ObjectHandle {
    pub(crate) fn create<O: AnyAnoncredsObject + 'static>(value: O) -> Result<Self> {
        let handle = Self::next();
        FFI_OBJECTS
            .lock()
            .map_err(|_| err_msg!("Error locking object store"))?
            .insert(handle, AnoncredsObject::new(value));
        Ok(handle)
    }

    pub(crate) fn load(self) -> Result<AnoncredsObject> {
        FFI_OBJECTS
            .lock()
            .map_err(|_| err_msg!("Error locking object store"))?
            .get(&self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid object handle"))
    }

    pub(crate) fn opt_load(self) -> Result<Option<AnoncredsObject>> {
        if self.0 == 0 {
            Ok(None)
        } else {
            Some(
                FFI_OBJECTS
                    .lock()
                    .map_err(|_| err_msg!("Error locking object store"))?
                    .get(&self)
                    .cloned()
                    .ok_or_else(|| err_msg!("Invalid object handle")),
            )
                .transpose()
        }
    }

    pub(crate) fn remove(self) -> Result<AnoncredsObject> {
        FFI_OBJECTS
            .lock()
            .map_err(|_| err_msg!("Error locking object store"))?
            .remove(&self)
            .ok_or_else(|| err_msg!("Invalid object handle"))
    }
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct AnoncredsObject(Arc<dyn AnyAnoncredsObject>);

impl AnoncredsObject {
    pub fn new<O: AnyAnoncredsObject + 'static>(value: O) -> Self {
        Self(Arc::new(value))
    }

    pub fn cast_ref<O: AnyAnoncredsObject + 'static>(&self) -> Result<&O> {
        let result = unsafe { &*(&*self.0 as *const _ as *const O) };
        if self.0.type_id() == TypeId::of::<O>() {
            Ok(result)
        } else {
            Err(err_msg!(
                "Expected {} instance, received {}",
                result.type_name(),
                self.0.type_name()
            ))
        }
    }

    pub fn type_name(&self) -> &'static str {
        self.0.type_name()
    }
}

impl Hash for AnoncredsObject {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(&*self.0, state);
    }
}

pub trait ToJson {
    fn to_json(&self) -> Result<Vec<u8>>;
}

impl ToJson for AnoncredsObject {
    #[inline]
    fn to_json(&self) -> Result<Vec<u8>> {
        self.0.to_json()
    }
}

impl<T> ToJson for T
    where
        T: Serialize,
{
    fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(err_map!("Error serializing object"))
    }
}

pub trait AnyAnoncredsObject: Debug + ToJson + Send + Sync {
    fn type_name(&self) -> &'static str;

    #[doc(hidden)]
    fn type_id(&self) -> TypeId
        where
            Self: 'static,
    {
        TypeId::of::<Self>()
    }
}

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
macro_rules! impl_anoncreds_object {
    ($ident:path, $name:expr) => {
        impl $crate::wasm::object::AnyAnoncredsObject for $ident {
            fn type_name(&self) -> &'static str {
                $name
            }
        }
    };
}

macro_rules! impl_anoncreds_object_from_json {
    ($ident:path, $method:ident) => {
        #[wasm_bindgen(js_name = $method)]
        pub fn $method(
            json: JsValue,
        ) -> u8 {
            // $crate::wasm::error::catch_error(|| {
                // check_useful_c_ptr!(result_p);
            log(&format!("anoncreds_object_from_json: {:?}", json));
                let obj: $ident = serde_wasm_bindgen::from_value(json).unwrap();
                log(&format!("anoncreds_object_from_json: {:?}", obj));
                let handle = $crate::wasm::object::ObjectHandle::create(obj).unwrap();
                return handle.as_u8();

            // })
        }
    };
}


#[wasm_bindgen(js_name = anoncredsObjectGetTypeName)]
pub fn anoncreds_object_get_type_name(
    p: usize,
) -> JsValue {
    let mut handle: ObjectHandle = ObjectHandle(p);

    let obj = handle.load().unwrap();

    serde_wasm_bindgen::to_value(obj.type_name()).unwrap()
}

#[no_mangle]
pub extern "C" fn anoncreds_object_free(handle: ObjectHandle) {
    handle.remove().ok();
}

#[repr(transparent)]
pub struct AnoncredsObjectList(Vec<AnoncredsObject>);

impl AnoncredsObjectList {
    pub fn load(handles: &[ObjectHandle]) -> Result<Self> {
        let loaded = handles
            .iter()
            .map(|h| ObjectHandle::load(*h))
            .collect::<Result<_>>()?;
        Ok(Self(loaded))
    }

    #[allow(unused)]
    pub fn refs<T>(&self) -> Result<Vec<&T>>
        where
            T: AnyAnoncredsObject + 'static,
    {
        let mut refs = Vec::with_capacity(self.0.len());
        for inst in &self.0 {
            let inst = inst.cast_ref::<T>()?;
            refs.push(inst);
        }
        Ok(refs)
    }

    pub fn refs_map<'a, I, T>(&'a self, ids: &'a [I]) -> Result<HashMap<&I, &T>>
        where
            T: AnyAnoncredsObject + 'static,
            I: Eq + Hash,
    {
        let mut refs = HashMap::with_capacity(self.0.len());
        for (inst, id) in self.0.iter().zip(ids) {
            let inst = inst.cast_ref::<T>()?;
            refs.insert(id, inst);
        }
        Ok(refs)
    }
}

impl Deref for AnoncredsObjectList {
    type Target = Vec<AnoncredsObject>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AnoncredsObjectList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
