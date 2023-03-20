import type { NonRevokedIntervalOverride } from '@hyperledger/anoncreds-shared'

import * as ref from 'ref-napi'
import RefStruct from 'ref-struct-di'

import { FFI_INT32, FFI_STRING } from './primitives'

const CStruct = RefStruct(ref)

export class NonRevokedIntervalOverrideStruct {
  public static serialize(options: NonRevokedIntervalOverride): Buffer {
    const { revocationRegistryDefinitionId, requestedFromTimestamp, overrideRevocationStatusListTimestamp } = options

    const structCtor = CStruct({
      rev_reg_def_id: FFI_STRING,
      requested_from_ts: FFI_INT32,
      override_rev_status_list_ts: FFI_INT32,
    })

    return structCtor({
      rev_reg_def_id: revocationRegistryDefinitionId,
      requested_from_ts: requestedFromTimestamp,
      override_rev_status_list_ts: overrideRevocationStatusListTimestamp,
    }) as unknown as Buffer
  }
}
