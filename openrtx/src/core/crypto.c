/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "core/crypto.h"
#include "core/crc.h"
#include "peripherals/rng.h"
#include <stddef.h>
#include <string.h>
#include "aes.h"
#include "sha256.h"

/*
 * Persistent configuration block. On targets with battery-backed memory it
 * lives there (see storePtr()); elsewhere it is a plain RAM copy. The layout is
 * fixed and guarded by a magic value and a CRC so a corrupt or uninitialised
 * block is detected and reset to safe defaults.
 */
#define CRYPTO_MAGIC 0x52435431UL   /* "RCT1" */

typedef struct
{
    uint32_t magic;
    uint8_t  mode;             /* enum cryptoMode */
    uint8_t  adaptive_mode;    /* enum cryptoAdaptive */
    uint8_t  adaptive_secs;    /* adaptive RX reply window, seconds */
    uint8_t  hear_clear;
    uint8_t  hear_encrypted;
    uint8_t  clear_tx_warn;
    uint8_t  reserved[3];      /* padding / future use */
    uint8_t  key128[16];
    uint8_t  key192[24];
    uint8_t  key256[32];
    uint16_t crc;              /* crc_ccitt over every preceding byte */
    uint16_t pad;
}
crypto_store_t;

/* AES key schedule for the active stream (4*(Nr+1) words, 60 for AES-256). */
static WORD g_schedule[60];
static int  g_activeBits = 0;

/*
 * ---------------------------------------------------------------------------
 * Battery-backed storage
 * ---------------------------------------------------------------------------
 */
#if defined(STM32F405xx)
#include "stm32f4xx.h"

static crypto_store_t *storePtr(void)
{
    static bool ready = false;

    if(!ready)
    {
        // Unlock the backup domain and clock the backup SRAM.
        RCC->APB1ENR  |= RCC_APB1ENR_PWREN;
        __DSB();
        PWR->CR       |= PWR_CR_DBP;
        RCC->AHB1ENR  |= RCC_AHB1ENR_BKPSRAMEN;
        __DSB();

        // Enable the backup regulator so the backup SRAM is retained from VBAT
        // across a power cycle. Bounded wait: proceed even if it never asserts
        // (e.g. no VBAT cell) rather than hang at boot.
        PWR->CSR |= PWR_CSR_BRE;
        for(volatile uint32_t t = 0;
            (t < 1000000u) && ((PWR->CSR & PWR_CSR_BRR) == 0); t++)
            ;

        ready = true;
    }

    return (crypto_store_t *)BKPSRAM_BASE;
}
#else
static crypto_store_t g_ramStore;

static crypto_store_t *storePtr(void)
{
    return &g_ramStore;
}
#endif

/*
 * ---------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------------
 */

static uint16_t calcCrc(const crypto_store_t *s)
{
    return crc_ccitt(s, offsetof(crypto_store_t, crc));
}

static void persist(crypto_store_t *s)
{
    s->crc = calcCrc(s);
}

static void resetDefaults(crypto_store_t *s)
{
    memset(s, 0, sizeof(*s));
    s->magic          = CRYPTO_MAGIC;
    s->mode           = CRYPTO_OFF;
    s->adaptive_mode  = CRYPTO_ADAPT_UP; /* escalate-only by default (secure)   */
    s->adaptive_secs  = 10;  /* default 10 s adaptive-RX reply window           */
    s->hear_clear     = 1;   /* in crypto mode, clear traffic stays audible     */
    s->hear_encrypted = 0;
    s->clear_tx_warn  = 0;
    persist(s);
}

static uint8_t *keySlot(crypto_store_t *s, uint8_t mode, size_t *len)
{
    switch(mode)
    {
        case CRYPTO_AES128: *len = 16; return s->key128;
        case CRYPTO_AES192: *len = 24; return s->key192;
        case CRYPTO_AES256: *len = 32; return s->key256;
        default:            *len = 0;  return NULL;
    }
}

/*
 * ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------
 */

void crypto_init(void)
{
    // The AES-CTR nonce needs randomness; bring up the RNG once here.
    rng_init();

    crypto_store_t *s = storePtr();

    if((s->magic != CRYPTO_MAGIC) || (s->crc != calcCrc(s)))
        resetDefaults(s);

    g_activeBits = 0;
}

uint8_t crypto_getMode(void)
{
    return storePtr()->mode;
}

void crypto_setMode(uint8_t mode)
{
    if(mode > CRYPTO_AES256)
        return;

    crypto_store_t *s = storePtr();
    s->mode = mode;
    persist(s);
}

int crypto_keyBits(uint8_t mode)
{
    switch(mode)
    {
        case CRYPTO_AES128: return 128;
        case CRYPTO_AES192: return 192;
        case CRYPTO_AES256: return 256;
        default:            return 0;
    }
}

bool crypto_keyPresent(uint8_t mode)
{
    crypto_store_t *s = storePtr();
    size_t len;
    const uint8_t *k = keySlot(s, mode, &len);

    if(k == NULL)
        return false;

    for(size_t i = 0; i < len; i++)
    {
        if(k[i] != 0)
            return true;
    }

    return false;
}

void crypto_setKey(uint8_t mode, const uint8_t *key, size_t len)
{
    crypto_store_t *s = storePtr();
    size_t slotLen;
    uint8_t *slot = keySlot(s, mode, &slotLen);

    if(slot == NULL)
        return;

    memset(slot, 0, slotLen);
    if(len > slotLen)
        len = slotLen;
    memcpy(slot, key, len);

    persist(s);
}

void crypto_fingerprint(uint8_t mode, uint8_t out[CRYPTO_FINGERPRINT_LEN])
{
    memset(out, 0, CRYPTO_FINGERPRINT_LEN);

    if(!crypto_keyPresent(mode))
        return;

    crypto_store_t *s = storePtr();
    size_t len;
    const uint8_t *k = keySlot(s, mode, &len);

    SHA256_CTX ctx;
    uint8_t    digest[SHA256_BLOCK_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, k, len);
    sha256_final(&ctx, digest);

    memcpy(out, digest, CRYPTO_FINGERPRINT_LEN);
}

void crypto_zeroize(void)
{
    crypto_store_t *s = storePtr();

    memset(s->key128, 0, sizeof(s->key128));
    memset(s->key192, 0, sizeof(s->key192));
    memset(s->key256, 0, sizeof(s->key256));
    g_activeBits = 0;

    persist(s);
}

/* --- Behaviour flags ---------------------------------------------------- */

#define FLAG_GETSET(getter, setter, field)       \
    bool getter(void)                            \
    {                                            \
        return storePtr()->field != 0;           \
    }                                            \
    void setter(bool on)                         \
    {                                            \
        crypto_store_t *s = storePtr();          \
        s->field = on ? 1 : 0;                   \
        persist(s);                              \
    }

FLAG_GETSET(crypto_getHearClear,    crypto_setHearClear,    hear_clear)
FLAG_GETSET(crypto_getHearEncrypted,crypto_setHearEncrypted,hear_encrypted)
FLAG_GETSET(crypto_getClearTxWarn,  crypto_setClearTxWarn,  clear_tx_warn)

uint8_t crypto_getAdaptiveMode(void)
{
    return storePtr()->adaptive_mode;
}

void crypto_setAdaptiveMode(uint8_t mode)
{
    if(mode > CRYPTO_ADAPT_MATCH)
        return;

    crypto_store_t *s = storePtr();
    s->adaptive_mode = mode;
    persist(s);
}

uint8_t crypto_getAdaptiveSecs(void)
{
    return storePtr()->adaptive_secs;
}

void crypto_setAdaptiveSecs(uint8_t secs)
{
    crypto_store_t *s = storePtr();
    s->adaptive_secs = secs;
    persist(s);
}

bool crypto_getAdaptiveRx(void)
{
    return storePtr()->adaptive_mode != CRYPTO_ADAPT_OFF;
}

/* --- Stream cipher ------------------------------------------------------- */

bool crypto_streamStart(uint8_t mode)
{
    int bits = crypto_keyBits(mode);
    if((bits == 0) || !crypto_keyPresent(mode))
    {
        g_activeBits = 0;
        return false;
    }

    crypto_store_t *s = storePtr();
    size_t len;
    const uint8_t *k = keySlot(s, mode, &len);

    aes_key_setup(k, g_schedule, bits);
    g_activeBits = bits;
    return true;
}

void crypto_apply(uint8_t payload[16], const uint8_t meta[14], uint16_t fn)
{
    if(g_activeBits == 0)
        return;

    uint8_t ctr[16];
    uint8_t keystream[16];

    // M17 AES-CTR counter block: 112-bit META nonce + 16-bit big-endian FN.
    memcpy(ctr, meta, 14);
    ctr[14] = (uint8_t)(fn >> 8);
    ctr[15] = (uint8_t)(fn & 0xFF);

    aes_encrypt(ctr, keystream, g_schedule, g_activeBits);

    for(int i = 0; i < 16; i++)
        payload[i] ^= keystream[i];
}
