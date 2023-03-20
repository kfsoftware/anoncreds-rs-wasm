import type {
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeCredentialRevocationConfig,
  NativeNonRevokedIntervalOverride,
  ObjectHandle,
} from '..'
import type { TypedArray } from 'ref-array-di'
import type { StructObject } from 'ref-struct-di'

import RefArray from 'ref-array-di'
import * as ref from 'ref-napi'
import RefStruct from 'ref-struct-di'

import { FFI_INT64, FFI_INT8, FFI_ISIZE, FFI_OBJECT_HANDLE, FFI_STRING, FFI_INT32 } from './primitives'
import { serializeArguments } from './serialize'

const CStruct = RefStruct(ref)
const CArray = RefArray(ref)

export const StringArray = CArray('string')

const FFI_INT32_ARRAY = CArray('int32')
const FFI_INT32_ARRAY_PTR = ref.refType(FFI_INT32_ARRAY)

const FFI_INT64_ARRAY = CArray('int64')
const FFI_INT64_ARRAY_PTR = ref.refType(FFI_INT64_ARRAY)

export const ByteBufferArray = CArray('uint8')
export const ByteBufferArrayPtr = ref.refType(FFI_STRING)

export const Int64Array = FFI_INT64_ARRAY
export const Int32Array = FFI_INT32_ARRAY

export const StringArrayPtr = ref.refType(StringArray)

export const ByteBufferStruct = CStruct({
  len: FFI_INT64,
  data: ByteBufferArrayPtr,
})

export const ByteBufferStructPtr = ref.refType(ByteBufferStruct)

export const StringListStruct = CStruct({
  count: ref.types.size_t,
  data: StringArray,
})
export const createStringListStruct = (arr?: Array<string>): Buffer =>
  StringListStruct({
    count: arr?.length,
    data: (arr as unknown as TypedArray<string>) ?? null,
  }) as unknown as Buffer

export const StringListStructPtr = ref.refType(StringListStruct)

export const I64ListStruct = CStruct({
  count: FFI_ISIZE,
  data: FFI_INT64_ARRAY_PTR,
})

export const I32ListStruct = CStruct({
  count: FFI_ISIZE,
  data: FFI_INT32_ARRAY_PTR,
})
export const createI32ListStruct = (arr?: Array<number>) =>
  I32ListStruct({
    count: arr?.length,
    data: (arr ? Int32Array(arr) : ref.NULL) as unknown as ref.Pointer<TypedArray<number>>,
  }) as unknown as Buffer

export const CredRevInfoStruct = CStruct({
  reg_def: FFI_OBJECT_HANDLE,
  reg_def_private: FFI_OBJECT_HANDLE,
  reg_idx: FFI_INT64,
  tails_path: FFI_STRING,
})
export const createRevocationConfiguration = (config?: NativeCredentialRevocationConfig): Buffer => {
  if (!config) return ref.NULL

  const { registryIndex, tailsPath, revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
    serializeArguments(config)

  return CredRevInfoStruct({
    reg_def: revocationRegistryDefinition,
    reg_def_private: revocationRegistryDefinitionPrivate,
    reg_idx: registryIndex,
    tails_path: tailsPath,
  }) as unknown as Buffer
}

export const CredentialEntryStruct = CStruct({
  credential: FFI_ISIZE,
  timestamp: FFI_INT64,
  rev_state: FFI_ISIZE,
})

export const CredentialEntryArray = CArray(CredentialEntryStruct)

export const CredentialEntryListStruct = CStruct({
  count: FFI_ISIZE,
  data: CredentialEntryArray,
})
export const createCredentialEntryListStruct = (arr?: Array<NativeCredentialEntry>): Buffer => {
  const credentialEntries = arr?.map((value) =>
    CredentialEntryStruct({
      credential: value.credential.handle,
      timestamp: value.timestamp ?? -1,
      rev_state: value.revocationState?.handle ?? 0,
    })
  )
  return CredentialEntryListStruct({
    count: credentialEntries?.length,
    data:
      (credentialEntries as unknown as TypedArray<
        StructObject<{ credential: number; timestamp: number; rev_state: number }>
      >) ?? null,
  }) as unknown as Buffer
}

export const CredentialProveStruct = CStruct({
  entry_idx: FFI_INT64,
  referent: FFI_STRING,
  is_predicate: FFI_INT8,
  reveal: FFI_INT8,
})

export const CredentialProveArray = CArray(CredentialProveStruct)

export const CredentialProveListStruct = CStruct({
  count: FFI_ISIZE,
  data: CredentialProveArray,
})
export const createCredentialProveListStruct = (arr?: Array<NativeCredentialProve>): Buffer => {
  const credentialProves = arr?.map(serializeArguments).map(({ reveal, referent, entryIndex, isPredicate }) => ({
    entry_idx: entryIndex,
    is_predicate: isPredicate,
    reveal,
    referent,
  }))

  return CredentialProveListStruct({
    count: credentialProves?.length,
    data:
      (credentialProves as unknown as TypedArray<
        StructObject<{
          entry_idx: number
          referent: string
          is_predicate: number
          reveal: number
        }>
      >) ?? null,
  }) as unknown as Buffer
}

export const ObjectHandleArray = CArray('size_t')

export const ObjectHandleListStruct = CStruct({
  count: FFI_ISIZE,
  data: ObjectHandleArray,
})
export const createObjectHandleListStruct = (arr?: Array<ObjectHandle>): Buffer =>
  ObjectHandleListStruct({
    count: arr?.length,
    data: (arr?.map((o) => o.handle) as unknown as TypedArray<string>) ?? null,
  }) as unknown as Buffer

export const RevocationEntryStruct = CStruct({
  def_entry_idx: FFI_INT64,
  entry: FFI_ISIZE,
  timestamp: FFI_INT64,
})

export const RevocationEntryArray = CArray(RevocationEntryStruct)

export const RevocationEntryListStruct = CStruct({
  count: FFI_ISIZE,
  data: RevocationEntryArray,
})

export const NonRevokedIntervalOverrideStruct = CStruct({
  rev_reg_def_id: FFI_STRING,
  requested_from_ts: FFI_INT32,
  override_rev_status_list_ts: FFI_INT32,
})

export const NonRevokedIntervalOverrideArray = CArray(NonRevokedIntervalOverrideStruct)

export const NonRevokedIntervalOverrideListStruct = CStruct({
  count: FFI_ISIZE,
  data: NonRevokedIntervalOverrideArray,
})
export const createNonRevokedIntervalOverrideList = (arr?: Array<NativeNonRevokedIntervalOverride>): Buffer => {
  const nonRevokedIntervalOverrides = arr?.map(serializeArguments).map((value) =>
    NonRevokedIntervalOverrideStruct({
      rev_reg_def_id: value.revocationRegistryDefinitionId,
      requested_from_ts: value.requestedFromTimestamp,
      override_rev_status_list_ts: value.overrideRevocationStatusListTimestamp,
    })
  )
  return NonRevokedIntervalOverrideListStruct({
    count: arr?.length,
    data:
      (nonRevokedIntervalOverrides as unknown as TypedArray<
        StructObject<{ rev_reg_def_id: string; requested_from_ts: number; override_rev_status_list_ts: number }>
      >) ?? null,
  }) as unknown as Buffer
}
