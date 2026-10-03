/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * M17 AES stream encryption for OpenRTX.
 *
 * This module owns the encryption configuration (mode, behaviour flags and the
 * three AES keys) and implements the M17 AES-CTR payload cipher on top of the
 * vendored AES block cipher in lib/crypto.
 *
 * The configuration is held in the MCU's battery-backed (VBAT) backup memory
 * where the hardware provides it, so keys survive power cycles without ever
 * being written to the codeplug flash. The block is protected by a magic value
 * and a CRC: if it is missing or corrupt the module starts with encryption off
 * and no keys, and never operates on undefined data.
 *
 * Per the M17 specification the AES-CTR counter block is the 112-bit LSF META
 * nonce followed by the 16-bit frame number (big-endian); one stream payload is
 * exactly one 16-byte AES block. Encrypt and decrypt are the same operation.
 */

/**
 * Encryption mode. The value doubles as the M17 LSF encryption subtype
 * selector (0 = clear, otherwise the AES key length).
 */
enum cryptoMode
{
    CRYPTO_OFF    = 0,   /**< Clear (no encryption)   */
    CRYPTO_AES128 = 1,   /**< AES-128                 */
    CRYPTO_AES192 = 2,   /**< AES-192                 */
    CRYPTO_AES256 = 3    /**< AES-256                 */
};

/**
 * Adaptive RX key behaviour. On an incoming encrypted call we can adjust the
 * reply key length. It never falls back to clear in any mode.
 */
enum cryptoAdaptive
{
    CRYPTO_ADAPT_OFF   = 0,  /**< Always use the configured mode.            */
    CRYPTO_ADAPT_UP    = 1,  /**< Escalate only: adopt a stronger incoming
                                  key, never a weaker one (secure default).  */
    CRYPTO_ADAPT_MATCH = 2   /**< Match the incoming key length exactly, up
                                  or down (max reach in a mixed-key net).    */
};

/** Length in bytes of the SHA-256 key fingerprint shown on screen. */
#define CRYPTO_FINGERPRINT_LEN 3

/**
 * Initialise the crypto store. Brings up the battery-backed memory, validates
 * the stored configuration (magic + CRC) and falls back to safe defaults
 * (encryption off, no keys) when it is missing or corrupt. Must be called once
 * at start-up before any other function here.
 */
void crypto_init(void);

/** @return the current encryption mode (one of enum cryptoMode). */
uint8_t crypto_getMode(void);

/** Set the persistent encryption mode (one of enum cryptoMode). */
void crypto_setMode(uint8_t mode);

/** @return the AES key length in bits for a mode (128/192/256), or 0. */
int crypto_keyBits(uint8_t mode);

/**
 * @return true if the key slot for the given mode (1..3) holds a non-zero key.
 * An all-zero slot counts as absent: encrypted TX must not proceed with one.
 */
bool crypto_keyPresent(uint8_t mode);

/**
 * Store a key into the slot for the given mode (1..3) and persist it. @p len
 * must match the mode's key length; a shorter buffer is zero-padded, a longer
 * one is truncated.
 */
void crypto_setKey(uint8_t mode, const uint8_t *key, size_t len);

/**
 * Write the SHA-256 fingerprint (first CRYPTO_FINGERPRINT_LEN bytes of the
 * digest) of the slot's key into @p out, for on-screen verification. @p out is
 * zeroed when the slot is empty. The key itself is never exposed.
 */
void crypto_fingerprint(uint8_t mode, uint8_t out[CRYPTO_FINGERPRINT_LEN]);

/** Wipe all three key slots (zeroize) and persist. Behaviour flags are kept. */
void crypto_zeroize(void);

/* --- Behaviour flags (persistent) --------------------------------------- */

/** Adaptive RX key behaviour (one of enum cryptoAdaptive). */
uint8_t crypto_getAdaptiveMode(void);
void    crypto_setAdaptiveMode(uint8_t mode);

/**
 * Adaptive RX reply window, in seconds (0..255): how long after an incoming
 * encrypted call the adopted key length is used for replies.
 */
uint8_t crypto_getAdaptiveSecs(void);
void    crypto_setAdaptiveSecs(uint8_t secs);

/** Convenience: true when adaptive RX is not OFF. */
bool crypto_getAdaptiveRx(void);
bool crypto_getHearClear(void);        /**< In crypto mode, also play clear.  */
void crypto_setHearClear(bool on);
bool crypto_getHearEncrypted(void);    /**< In clear mode, decode encrypted.  */
void crypto_setHearEncrypted(bool on);
bool crypto_getClearTxWarn(void);      /**< Warn before a clear transmission. */
void crypto_setClearTxWarn(bool on);

/* --- Stream cipher ------------------------------------------------------- */

/**
 * Prepare the cipher for a stream using the key for @p mode (1..3): expands the
 * AES key schedule from the stored key.
 *
 * @return true on success; false if the slot is empty, in which case the caller
 * must fall back to clear or refuse to transmit (never send with a zero key).
 */
bool crypto_streamStart(uint8_t mode);

/**
 * Encrypt or decrypt one 16-byte M17 stream payload in place, using the key
 * schedule from the last crypto_streamStart() and the given LSF META nonce and
 * frame number. No-op if no stream was started.
 *
 * @param payload: 16-byte voice payload, XORed with the keystream in place.
 * @param meta: 14-byte LSF META nonce (timestamp + random).
 * @param fn: 16-bit frame number for this payload.
 */
void crypto_apply(uint8_t payload[16], const uint8_t meta[14], uint16_t fn);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
