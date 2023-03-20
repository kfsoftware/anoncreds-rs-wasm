type ByteBufferOptions = {
  length: number
  data: Uint8Array
}

export class ByteBuffer {
  public length: number
  public data: Uint8Array

  public constructor({ data, length: len }: ByteBufferOptions) {
    this.data = data
    this.length = len
  }

  public static fromUint8Array(data: Uint8Array): ByteBuffer {
    return new ByteBuffer({ data, length: data.length })
  }

  public toBuffer(): Buffer {
    return Buffer.from(this.data, this.length)
  }
}

export type JsonObject = Record<string, unknown>
