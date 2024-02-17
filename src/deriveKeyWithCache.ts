import { deriveKey, SendOverDeriveKeyParams } from './deriveKey'

// Global cache object to store the results of deriveKey function invocations
const deriveKeyCache = {}

/**
 * Generates a unique cache key based on the input parameters of the deriveKey function.
 * This function serializes the parameters into a string that can be used as a key in the cache object.
 *
 * @param {SendOverDeriveKeyParams} params - The input parameters to the deriveKey function.
 * @return {string} A unique string identifier based on the input parameters.
 */
function generateCacheKey (params: SendOverDeriveKeyParams): string {
  const key = JSON.stringify(params, (key, value) =>
    value instanceof Uint8Array ? Array.from(value) : value,
  4
  )
  return key
}

/**
 * Modified deriveKey function that utilizes a caching mechanism.
 * This function first checks if the result for the given parameters is already in the cache.
 * If so, it returns the cached result. Otherwise, it proceeds with the derivation and stores the result in the cache.
 *
 * @param {SendOverDeriveKeyParams} params - The input parameters for the key derivation.
 * @return {string} Hex string of the derived key.
 */
export function deriveKeyWithCache (params: SendOverDeriveKeyParams): string {
  // Generate a unique cache key for the current invocation parameters
  const cacheKey = generateCacheKey(params)

  // Check if the result is already cached
  if (cacheKey in deriveKeyCache) {
    return deriveKeyCache[cacheKey]
  }

  // Proceed with the original deriveKey logic to derive the key
  const result = deriveKey(params)

  // Store the result in the cache with the generated cache key
  deriveKeyCache[cacheKey] = result

  return result
}
