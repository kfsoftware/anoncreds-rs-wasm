import { NonRevokedIntervalOverride, ObjectHandle } from '@hyperledger/anoncreds-shared'
import { TypedArray } from 'ref-array-di'
import { NULL, Pointer } from 'ref-napi'
import { StructObject } from 'ref-struct-di'
import { NonRevokedIntervalOverrideListStruct, NonRevokedIntervalOverrideStruct } from '..'
import { I32ListStruct, Int32Array, ObjectHandleListStruct, StringListStruct } from '../structures'

export const serializer = {
  // Primitives
  string: (input: string) => input,
  null: (_: undefined | null) => NULL,
  boolean: (input: boolean) => Number(input),
  number: (input: number) => input,
  function: (input: (...args: Array<unknown>) => unknown | Promise<unknown>) => input,
  object: (input: Record<string, unknown>) => JSON.stringify(input),

  // Primitive Arrays
  stringArray: (input?: Array<string>) => {
    const data = input?.map(serializer.string)

    return StringListStruct({
      count: data?.length,
      data: (data as unknown as TypedArray<string>) ?? null,
    }) as unknown as Buffer
  },

  i32Array: (input?: Array<number>) => {
    const data = input?.map(serializer.number)

    return I32ListStruct({
      count: data?.length,
      data: (data ? Int32Array(data) : NULL) as unknown as Pointer<TypedArray<number>>,
    }) as unknown as Buffer
  },

  // ObjectHandle
  objectHandle: (input: ObjectHandle) => input.handle,

  objectHandleArray: (input?: Array<ObjectHandle>) => {
    const data = input?.map(serializer.objectHandle)

    return ObjectHandleListStruct({
      count: data?.length,
      data: (data as unknown as TypedArray<string>) ?? null,
    }) as unknown as Buffer
  },

  objectHandleMap: (input?: Record<string, ObjectHandle>) => {
    const ids = serializer.stringArray(Object.keys(input ?? {}))
    const values = serializer.objectHandleArray(Object.values(input ?? {}))

    return { ids, values }
  },

  nonRevokedIntervalOverride: (input?: NonRevokedIntervalOverride) => {
    const { overrideRevocationStatusListTimestamp, requestedFromTimestamp, revocationRegistryDefinitionId } =
      serializeArguments(input)

    return NonRevokedIntervalOverrideStruct({
      override_rev_status_list_ts: overrideRevocationStatusListTimestamp,
      rev_reg_def_id: revocationRegistryDefinitionId,
      requested_from_ts: requestedFromTimestamp,
    }) as unknown as Buffer
  },

  nonRevokedIntervalOverrideList: (input?: Array<NonRevokedIntervalOverride>) => {
    const data = input?.map(serializer.nonRevokedIntervalOverride)

    return NonRevokedIntervalOverrideListStruct({
      count: data?.length,
      data: data as unknown as TypedArray<
        StructObject<{ rev_reg_def_id: string; requested_from_ts: number; override_rev_status_list_ts: number }>
      >,
    }) as unknown as Buffer
  },
} as const

export const serialize = (input: unknown) => {
  let serializeFn: (...args: any[]) => unknown = () => {
    throw new Error(`Could not serialize value: ${input}`)
  }

  switch (typeof input) {
    case 'undefined':
      serializeFn = serializer.null
      break
    case 'string':
      serializeFn = serializer.string
      break
    case 'number':
      serializeFn = serializer.number
      break
    case 'function':
      serializeFn = serializer.function
      break
    case 'boolean':
      serializeFn = serializer.boolean
      break
    case 'object':
      if (input instanceof ObjectHandle) {
        serializeFn = serializer.objectHandle
      } else if (Array.isArray(input)) {
        if (input.every((t) => typeof t === 'string')) {
          serializeFn = serializer.stringArray
        } else if (input.every((t) => typeof t === 'number')) {
          serializeFn = serializer.i32Array
        }
      } else {
        serializeFn = serializer.object
      }
      break
  }

  return serializeFn(input) as SerializedArgument
}

type Argument =
  | Record<string, unknown>
  | Array<unknown>
  | Date
  | Uint8Array
  | SerializedArgument
  | boolean
  | ObjectHandle

type SerializedArgument = string | number | Buffer

type SerializedArguments = Record<string, SerializedArgument>

type SerializedOptions<Type> = Required<{
  [Property in keyof Type]: Type[Property] extends undefined | null
    ? null
    : Type[Property] extends string | Record<string, unknown> | (string | undefined)
    ? string
    : Type[Property] extends number | boolean | Date | ObjectHandle | (number | undefined)
    ? number
    : Type[Property] extends
        | Array<string>
        | Uint8Array
        | Array<ObjectHandle>
        | Buffer
        | (Array<ObjectHandle> | undefined)
        | (Array<number> | undefined)
    ? Buffer
    : unknown
}>

export const serializeArguments = <T extends Record<string, Argument> = Record<string, Argument>>(args?: T) => {
  const retVal: SerializedArguments = {}
  Object.entries(args ?? {}).forEach(([key, val]) => (retVal[key] = serialize(val)))
  return retVal as SerializedOptions<T>
}
