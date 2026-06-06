/**
 * Cred wire-protocol constants.
 *
 * The protocol version advertised by SDK clients and echoed by the server.
 * In v0 the handshake is advisory only — peers advertise and echo the version
 * but never reject on mismatch.
 */

/** @provisional pre-submission */
export const CRED_PROTOCOL_VERSION = '0.1.0';

/** HTTP header used to advertise/echo the Cred protocol version. */
export const CRED_PROTOCOL_VERSION_HEADER = 'Cred-Protocol-Version';
