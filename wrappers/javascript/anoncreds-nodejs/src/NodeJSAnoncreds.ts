import type {
  NativeCredentialEntry,
  NativeCredentialProve,
  Anoncreds,
  NativeCredentialRevocationConfig,
  NativeNonRevokedIntervalOverride,
  AnoncredsErrorObject,
} from '@hyperledger/anoncreds-shared'

import { AnoncredsError, ByteBuffer, ObjectHandle } from '@hyperledger/anoncreds-shared'
import { TextDecoder, TextEncoder } from 'util'

import { byteBufferToBuffer } from './ffi'
import { allocateByteBuffer, allocateInt8Buffer, allocatePointer, allocateStringBuffer } from './ffi/alloc'
import { serializeArguments, serializer } from './ffi/serialize/primitives'
import {
  createCredentialEntryListStruct,
  createCredentialProveListStruct,
  createNonRevokedIntervalOverrideList,
  createRevocationConfiguration,
  createStringListStruct,
} from './ffi/structures'
import { getNativeAnoncreds } from './library'

function handleReturnPointer<Return>(returnValue: Buffer): Return {
  if (returnValue.address() === 0) {
    throw AnoncredsError.customError({ message: 'Unexpected null pointer' })
  }

  return returnValue.deref() as Return
}

export class NodeJSAnoncreds implements Anoncreds {
  private handleError() {
    const nativeError = allocateStringBuffer()
    getNativeAnoncreds().anoncreds_get_current_error(nativeError)
    const anoncredsErrorObject = JSON.parse(nativeError.deref() as string) as AnoncredsErrorObject

    if (anoncredsErrorObject.code === 0) return

    throw new AnoncredsError(anoncredsErrorObject)
  }

  public get nativeAnoncreds() {
    return getNativeAnoncreds()
  }

  public generateNonce(): string {
    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_generate_nonce(ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public createSchema(options: {
    name: string
    version: string
    issuerId: string
    attributeNames: string[]
  }): ObjectHandle {
    const { name, version, issuerId, attributeNames } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_schema(name, version, issuerId, attributeNames, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_revocation_registry_definition_get_attribute(objectHandle, name, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_credential_get_attribute(objectHandle, name, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    issuerId: string
    tag: string
    signatureType: string
    supportRevocation: boolean
  }): {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    keyCorrectnessProof: ObjectHandle
  } {
    const { schemaId, issuerId, schema, tag, signatureType, supportRevocation } = serializeArguments(options)

    const credentialDefinitionPtr = allocatePointer()
    const credentialDefinitionPrivatePtr = allocatePointer()
    const keyCorrectnessProofPtr = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_credential_definition(
      schemaId,
      schema,
      tag,
      issuerId,
      signatureType,
      supportRevocation,
      credentialDefinitionPtr,
      credentialDefinitionPrivatePtr,
      keyCorrectnessProofPtr
    )
    this.handleError()

    return {
      credentialDefinition: new ObjectHandle(handleReturnPointer<number>(credentialDefinitionPtr)),
      credentialDefinitionPrivate: new ObjectHandle(handleReturnPointer<number>(credentialDefinitionPrivatePtr)),
      keyCorrectnessProof: new ObjectHandle(handleReturnPointer<number>(keyCorrectnessProofPtr)),
    }
  }

  public createCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    attributeEncodedValues?: Record<string, string>
    revocationRegistryId?: string
    revocationStatusList?: ObjectHandle
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ObjectHandle {
    const {
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      revocationRegistryId,
    } = serializeArguments(options)

    const attributeNames = createStringListStruct(Object.keys(options.attributeRawValues))
    const attributeRawValues = createStringListStruct(Object.values(options.attributeRawValues))
    const attributeEncodedValues = createStringListStruct(Object.values(options.attributeEncodedValues ?? {}))

    const revocationConfiguration = createRevocationConfiguration(options.revocationConfiguration)

    const credentialPtr = allocatePointer()
    this.nativeAnoncreds.anoncreds_create_credential(
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeNames,
      attributeRawValues,
      attributeEncodedValues,
      revocationRegistryId,
      options.revocationStatusList?.handle ?? 0,
      revocationConfiguration?.ref().address(),
      credentialPtr
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(credentialPtr))
  }

  public encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): Array<string> {
    const { attributeRawValues } = serializeArguments(options)

    const ret = allocateStringBuffer()

    this.nativeAnoncreds.anoncreds_encode_credential_attributes(attributeRawValues, ret)
    this.handleError()

    const result = handleReturnPointer<string>(ret)

    return result.split(',')
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle | undefined
  }): ObjectHandle {
    const { credential, credentialRequestMetadata, linkSecret, credentialDefinition } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_process_credential(
      credential,
      credentialRequestMetadata,
      linkSecret,
      credentialDefinition,
      options.revocationRegistryDefinition?.handle ?? 0,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle {
    const { schemaId, credentialDefinitionId, keyCorrectnessProof } = serializeArguments(options)

    const ret = allocatePointer()
    this.nativeAnoncreds.anoncreds_create_credential_offer(schemaId, credentialDefinitionId, keyCorrectnessProof, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    const { entropy, proverDid, credentialDefinition, linkSecret, linkSecretId, credentialOffer } =
      serializeArguments(options)

    const credentialRequestPtr = allocatePointer()
    const credentialRequestMetadataPtr = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_credential_request(
      entropy,
      proverDid,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
      credentialRequestPtr,
      credentialRequestMetadataPtr
    )
    this.handleError()

    return {
      credentialRequest: new ObjectHandle(handleReturnPointer<number>(credentialRequestPtr)),
      credentialRequestMetadata: new ObjectHandle(handleReturnPointer<number>(credentialRequestMetadataPtr)),
    }
  }

  public createLinkSecret(): string {
    const ret = allocateStringBuffer()

    this.nativeAnoncreds.anoncreds_create_link_secret(ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public createPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: Record<string, string>
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle {
    const { presentationRequest, linkSecret } = serializeArguments(options)

    const credentialEntryList = createCredentialEntryListStruct(options.credentials)
    const credentialProveList = createCredentialProveListStruct(options.credentialsProve)

    const selfAttestNames = createStringListStruct(Object.keys(options.selfAttest))
    const selfAttestValues = createStringListStruct(Object.values(options.selfAttest))

    const { ids: schemaIds, values: schemaValues } = serializer.objectHandleMap(options.schemas)
    const { ids: credentialDefinitionIds, values: credentialDefinitionValues } = serializer.objectHandleMap(
      options.credentialDefinitions
    )

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_presentation(
      presentationRequest,
      credentialEntryList,
      credentialProveList,
      selfAttestNames,
      selfAttestValues,
      linkSecret,
      schemaValues,
      schemaIds,
      credentialDefinitionValues,
      credentialDefinitionIds,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }
  public verifyPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    schemaIds: string[]
    credentialDefinitions: ObjectHandle[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: ObjectHandle[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean {
    const {
      presentation,
      presentationRequest,
      schemas,
      credentialDefinitions,
      revocationRegistryDefinitions,
      revocationStatusLists,
      revocationRegistryDefinitionIds,
      schemaIds,
      credentialDefinitionIds,
    } = serializeArguments(options)

    const nonRevokedIntervalOverrideList = createNonRevokedIntervalOverrideList(options.nonRevokedIntervalOverrides)

    const ret = allocateInt8Buffer()

    this.nativeAnoncreds.anoncreds_verify_presentation(
      presentation,
      presentationRequest,
      schemas,
      schemaIds,
      credentialDefinitions,
      credentialDefinitionIds,
      revocationRegistryDefinitions,
      revocationRegistryDefinitionIds,
      revocationStatusLists,
      nonRevokedIntervalOverrideList,
      ret
    )
    this.handleError()

    return Boolean(handleReturnPointer<number>(ret))
  }

  public createRevocationStatusList(options: {
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    issuerId: string
    timestamp?: number
    issuanceByDefault: boolean
  }): ObjectHandle {
    const { timestamp, issuanceByDefault, revocationRegistryDefinition, revocationRegistryDefinitionId, issuerId } =
      serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_revocation_status_list(
      revocationRegistryDefinitionId,
      revocationRegistryDefinition,
      issuerId,
      timestamp,
      issuanceByDefault,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const { currentRevocationStatusList, timestamp } = serializeArguments(options)
    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_update_revocation_status_list_timestamp_only(
      timestamp,
      currentRevocationStatusList,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public updateRevocationStatusList(options: {
    timestamp?: number
    issued?: number[]
    revoked?: number[]
    revocationRegistryDefinition: ObjectHandle
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const { currentRevocationStatusList, timestamp, revocationRegistryDefinition, revoked, issued } =
      serializeArguments(options)
    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_update_revocation_status_list(
      timestamp,
      issued,
      revoked,
      revocationRegistryDefinition,
      currentRevocationStatusList,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createRevocationRegistryDefinition(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionId: string
    issuerId: string
    tag: string
    revocationRegistryType: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }) {
    const {
      credentialDefinition,
      credentialDefinitionId,
      tag,
      revocationRegistryType,
      issuerId,
      maximumCredentialNumber,
      tailsDirectoryPath,
    } = serializeArguments(options)

    const revocationRegistryDefinitionPtr = allocatePointer()
    const revocationRegistryDefinitionPrivate = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_revocation_registry_def(
      credentialDefinition,
      credentialDefinitionId,
      issuerId,
      tag,
      revocationRegistryType,
      maximumCredentialNumber,
      tailsDirectoryPath,
      revocationRegistryDefinitionPtr,
      revocationRegistryDefinitionPrivate
    )
    this.handleError()

    return {
      revocationRegistryDefinition: new ObjectHandle(handleReturnPointer<number>(revocationRegistryDefinitionPtr)),
      revocationRegistryDefinitionPrivate: new ObjectHandle(
        handleReturnPointer<number>(revocationRegistryDefinitionPrivate)
      ),
    }
  }

  public createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: ObjectHandle
    revocationStatusList: ObjectHandle
    revocationRegistryIndex: number
    tailsPath: string
    previousRevocationStatusList?: ObjectHandle
    previousRevocationState?: ObjectHandle
  }): ObjectHandle {
    const { revocationRegistryDefinition, revocationStatusList, revocationRegistryIndex, tailsPath } =
      serializeArguments(options)

    const previousRevocationState = options.previousRevocationState ?? new ObjectHandle(0)
    const previousRevocationStatusList = options.previousRevocationStatusList ?? new ObjectHandle(0)
    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_or_update_revocation_state(
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
      previousRevocationStatusList.handle,
      previousRevocationState.handle,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }
  public version(): string {
    return this.nativeAnoncreds.anoncreds_version()
  }

  public setDefaultLogger(): void {
    this.nativeAnoncreds.anoncreds_set_default_logger()
    this.handleError()
  }

  // This should be called when a function returns a non-zero code
  public getCurrentError(): string {
    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_get_current_error(ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  private objectFromJson(method: (byteBuffer: Buffer, ret: Buffer) => unknown, options: { json: string }) {
    const ret = allocatePointer()

    const byteBuffer = ByteBuffer.fromUint8Array(new TextEncoder().encode(options.json))
    this.handleError()

    method(byteBuffer.toBuffer(), ret)

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public presentationRequestFromJson(options: { json: string }) {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_presentation_request_from_json, options)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_request_from_json, options)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_request_metadata_from_json, options)
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_definition_from_json, options)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_from_json, options)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_state_from_json, options)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_presentation_from_json, options)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_offer_from_json, options)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_schema_from_json, options)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_from_json, options)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_definition_private_from_json, options)
  }

  public revocationRegistryDeltaFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_delta_from_json, options)
  }

  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_definition_from_json, options)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_definition_private_from_json, options)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_key_correctness_proof_from_json, options)
  }

  public getJson(options: { objectHandle: ObjectHandle }) {
    const ret = allocateByteBuffer()

    const { objectHandle } = serializeArguments(options)
    this.nativeAnoncreds.anoncreds_object_get_json(objectHandle, ret)
    this.handleError()

    const returnValue = handleReturnPointer<{ data: Buffer; len: number }>(ret)
    const output = new Uint8Array(byteBufferToBuffer(returnValue))

    return new TextDecoder().decode(output)
  }

  public getTypeName(options: { objectHandle: ObjectHandle }) {
    const { objectHandle } = serializeArguments(options)

    const ret = allocateStringBuffer()

    this.nativeAnoncreds.anoncreds_object_get_type_name(objectHandle, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public objectFree(options: { objectHandle: ObjectHandle }) {
    this.nativeAnoncreds.anoncreds_object_free(options.objectHandle.handle)
    this.handleError()
  }
}
