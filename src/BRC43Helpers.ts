/**
 * Protocol IDs are two element arrays: [level, name]
 *
 * level is an integer value of 0, 1, or 2 specifying the protocol's counterparty permissions policy.
 *
 * name is a string which must uniquely identify the protocol.
 *
 * Level 0: Open. Any app can use it to talk to anyone without permission.
 * Level 1: App-bound. Only apps with permission can use the protocol. They can use it in conjunction with any counterparty.
 * Level 2: Countarparty-bound: Only apps with permission can use the protocol. When permission is granted, it only applies to the specific counterparty being authorized. Other counterparties, even under the same protocol ID, will trigger new permission requests.
 *
 * For historical and convenience purposes, a protocol ID may be specified as just a name string
 * in which case it is promoted to the array [2, name].
 *
 * Protocol names are normalized by the following rules.
 * All strings that normalize to the same value identify the same protocol.
 *
 * Protocol name normalization rules:
 * - only letters, numbers and spaces
 * - no multiple space "  "
 * - all lower case when used
 * - maximum 280 characters
 * - must be at least 5 characters
 * - must not end with " protocol"
 * - leading and trailing spaces are removed
 *
 * @param {String} input The protocol to normalize
 *
 * @returns {String} The normalized protocol
 * @private
 */
export function normalizeProtocol (input): [number, string] {
  if (typeof input === 'undefined') {
    throw new Error('A protocol ID is required')
  }
  if (typeof input === 'string') {
    return [2, normalizeProtocolName(input)]
  }
  if (!Array.isArray(input) || input.length !== 2) {
    throw new Error('Protocol IDs must be strings or two element arrays')
  }
  const level = input[0]
  if (typeof level !== 'number' || !Number.isInteger(level) || level < 0 || level > 2) {
    throw new Error('Protocol level must be 0, 1, or 2')
  }
  return [level, normalizeProtocolName(input[1])]
}

const normalizeProtocolName = (input?: string): string => {
  if (typeof input === 'undefined') {
    throw new Error('A protocol name is required')
  }
  if (typeof input !== 'string') {
    throw new Error('Protocol names must be strings')
  }
  input = input.toLowerCase().trim()
  if (input.includes('  ')) {
    throw new Error(
      'Protocol names cannot contain multiple consecutive spaces ("  ")'
    )
  }
  if (!/^[a-z0-9 ]+$/g.test(input)) {
    throw new Error(
      'Protocol names can only contain letters, numbers and spaces'
    )
  }
  if (input.endsWith(' protocol')) {
    throw new Error(
      'No need to end your protocol name with " protocol"'
    )
  }
  if (input.length > 280) {
    throw new Error('Protocol names must be 280 characters or less')
  }
  if (input.length < 5) {
    throw new Error('Protocol names must be 5 characters or more')
  }
  return input
}

export function getProtocolInvoiceNumber (params: { protocolID: string | [number, string], keyID: number | string }): string {
  const npID = normalizeProtocol(params.protocolID)
  return `${npID[0]}-${npID[1]}-${params.keyID}`
}
