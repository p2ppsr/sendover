/**
 * Coerce a value to number[]
 * @param val Buffer or string or number[]. If string, encoding param applies.
 * @param encoding defaults to 'hex'
 * @returns input val if it is a number[]; if string converts to Buffer using encoding; uses Array.from to convert buffer to number[]
 * @publicbody
 */
export function asArray(val: Buffer | string | number[], encoding?: BufferEncoding): number[] {
  let a: number[]
  if (Array.isArray(val)) a = val
  else if (Buffer.isBuffer(val)) a = Array.from(val)
  else a = Array.from(Buffer.from(val, encoding || 'hex'))
  return a
}

