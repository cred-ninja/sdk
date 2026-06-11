/**
 * Cred wire-protocol constants.
 *
 * The protocol version advertised by SDK clients and selected by servers.
 * The pre-submission draft defines 0.1.0 as the canonical initial wire version.
 */

/** Current Cred Protocol wire version. */
export const CRED_PROTOCOL_VERSION = '0.1.0';

/** HTTP header used to advertise/echo the Cred protocol version. */
export const CRED_PROTOCOL_VERSION_HEADER = 'Cred-Protocol-Version';

/** Lowest Cred Protocol wire version this package will accept. */
export const CRED_PROTOCOL_VERSION_MINIMUM = '0.1.0';

/** Protocol versions this package can speak, newest first. */
export const CRED_PROTOCOL_SUPPORTED_VERSIONS = [CRED_PROTOCOL_VERSION] as const;

/** Structured error code returned when a peer advertises an unsupported version. */
export const CRED_PROTOCOL_VERSION_UNSUPPORTED_ERROR = 'protocol_version_unsupported';

export function isCredProtocolVersionSupported(version: string): boolean {
  return (CRED_PROTOCOL_SUPPORTED_VERSIONS as readonly string[]).includes(version);
}
