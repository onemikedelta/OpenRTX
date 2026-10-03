/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 * 
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "interfaces/platform.h"
#include "interfaces/delays.h"
#include "interfaces/audio.h"
#include "interfaces/radio.h"
#include "protocols/M17/Datatypes.hpp"
#include "rtx/OpMode_M17.hpp"
#include "core/audio_codec.h"
#include <errno.h>
#include <string.h>
#include "core/gps.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/crypto.h"
#include "core/voicePrompts.h"
#include "peripherals/rng.h"
#include "peripherals/rtc.h"
#include "rtx/rtx.h"

#ifdef PLATFORM_MOD17
#include "calibration/calibInfo_Mod17.h"
#include "interfaces/platform.h"

extern mod17Calib_t mod17CalData;
#endif

using namespace std;
using namespace M17;

/*
 * M17 TYPE-field encryption value for AES, as transmitted on air.
 *
 * NOTE: M17 spec 2.0.4 (Table 3.5) defines the encryption type bits as
 * 00 = none, 01 = scrambler, 10 = AES. OpenRTX's EncryptionType enum predates
 * that and maps ENCRYPTION_AES = 1 (= scrambler on the wire), so it cannot be
 * used for the on-air value. We write the spec value (2) directly here, which
 * is also what libm17-based stacks and the reference ESP32 nodes use.
 */
static constexpr uint8_t M17_ENCTYPE_NONE = 0;
static constexpr uint8_t M17_ENCTYPE_AES  = 2;

/*
 * Clear-TX warning tone, matching the reference ESP32 nodes: an 800 Hz double
 * beep (50 ms on / 50 ms off / 50 ms on) followed by a 100 ms gap, so the
 * transmitter keys 250 ms after the PTT press. Watches the PTT throughout:
 * returns true if it stayed down the whole time (go ahead and key), or false
 * the moment it is released (abort, no RF). The caller owns the speaker path.
 */
static constexpr uint16_t CLEAR_WARN_TONE = 800;

/* No-key warning tone: a long low tone when TX is blocked because the selected
 * crypto mode has no key. Gated by the voice-prompt/beep level, so it is silent
 * for operators who keep beeps off (the red "No Key" indicator still shows) but
 * audible for those who enable warning tones. */
static constexpr uint16_t NOKEY_WARN_TONE = 300;
static constexpr int      NOKEY_WARN_MS   = 750;

static bool clearTxWarnTone()
{
    static const struct { uint16_t hz; int ms; } seq[] =
    {
        { CLEAR_WARN_TONE,  50 },   // beep
        { 0,                50 },   // gap
        { CLEAR_WARN_TONE,  50 },   // beep
        { 0,               100 },   // trailing gap -> 250 ms total before keying
    };

    for(unsigned s = 0; s < (sizeof(seq) / sizeof(seq[0])); s++)
    {
        if(seq[s].hz == 0)
            platform_beepStop();
        else
            platform_beepStart(seq[s].hz);

        for(int e = 0; e < seq[s].ms; e += 10)
        {
            sleepFor(0, 10);
            if(platform_getPttStatus() == false)
            {
                platform_beepStop();
                return false;
            }
        }
    }

    platform_beepStop();
    return true;
}

/*
 * Seconds elapsed from 2020-01-01 00:00:00 to the given UTC date/time, matching
 * the M17 META timestamp epoch. Returns 0 for dates before 2020.
 */
static uint32_t secondsSince2020(const datetime_t *t)
{
    int year = 2000 + t->year;
    if(year < 2020)
        return 0;

    static const uint16_t cumDays[12] =
        { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

    uint32_t days = 0;
    for(int y = 2020; y < year; y++)
        days += (((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0)) ? 366 : 365;

    days += cumDays[(t->month - 1) % 12];
    bool leap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
    if(leap && (t->month > 2))
        days += 1;
    days += (uint32_t)(t->date - 1);

    return (days * 86400UL) + ((uint32_t)t->hour * 3600UL)
         + ((uint32_t)t->minute * 60UL) + (uint32_t)t->second;
}

/*
 * Fill the 14-byte LSF META field with a fresh AES-CTR nonce: a 32-bit
 * timestamp (seconds since 2020) followed by 80 bits of random, per the M17
 * spec. The timestamp is taken from the RTC only when it reads as a real date
 * (year >= 2026); otherwise the whole nonce stays random so a default/unset
 * clock never reduces entropy. Interop does not depend on the layout: a
 * receiver copies these bytes into its counter verbatim.
 */
static void buildNonce(uint8_t nonce[14])
{
    for(int i = 0; i < 14; i += 4)
    {
        uint32_t r = rng_get();
        for(int j = 0; (j < 4) && ((i + j) < 14); j++)
            nonce[i + j] = (uint8_t)(r >> (8 * j));
    }

    datetime_t now = rtc_getTime();
    if((2000 + now.year) >= 2026)
    {
        uint32_t ts = secondsSince2020(&now);
        nonce[0] = (uint8_t)(ts >> 24);
        nonce[1] = (uint8_t)(ts >> 16);
        nonce[2] = (uint8_t)(ts >> 8);
        nonce[3] = (uint8_t)(ts);
    }
}

OpMode_M17::OpMode_M17() : startRx(false), startTx(false), locked(false),
                           dataValid(false), extendedCall(false),
                           invertTxPhase(false), invertRxPhase(false)
{

}

OpMode_M17::~OpMode_M17()
{
    disable();
}

void OpMode_M17::enable()
{
    codec_init();
    modulator.init();
    demodulator.init();
    locked       = false;
    dataValid    = false;
    extendedCall = false;
    startRx      = true;
    startTx      = false;
    txEncrypt    = false;
    rxEncrypt    = false;
    varKeyMode   = 0;
    varKeyExpiry = 0;
    clearWarned  = false;
    noKeyWarned  = false;
}

void OpMode_M17::disable()
{
    startRx = false;
    startTx = false;
    platform_ledOff(GREEN);
    platform_ledOff(RED);
    audioPath_release(rxAudioPath);
    audioPath_release(txAudioPath);
    codec_terminate();
    radio_disableRtx();
    modulator.terminate();
    demodulator.terminate();
}

void OpMode_M17::update(rtxStatus_t *const status, const bool newCfg)
{
    (void) newCfg;

    // Re-arm the once-per-key-up TX warnings whenever the PTT is released.
    // Done here (every FSM tick, any state) because offState returns early via
    // startRx after a transmission and would otherwise never reset them.
    if(platform_getPttStatus() == false)
    {
        clearWarned = false;
        noKeyWarned = false;
    }

    #if defined(PLATFORM_MD3x0) || defined(PLATFORM_MDUV3x0)
    //
    // Invert TX phase for all MDx models.
    // Invert RX phase for MD-3x0 VHF and MD-UV3x0 radios.
    //
    const hwInfo_t* hwinfo = platform_getHwInfo();
    invertTxPhase = true;
    if(hwinfo->vhf_band == 1)
        invertRxPhase = true;
    else
        invertRxPhase = false;
    #elif defined(PLATFORM_MOD17)
    //
    // Get phase inversion settings from calibration.
    //
    invertTxPhase = (mod17CalData.bb_tx_invert == 1) ? true : false;
    invertRxPhase = (mod17CalData.bb_rx_invert == 1) ? true : false;
    #elif defined(PLATFORM_CS7000) || defined(PLATFORM_CS7000P)
    invertTxPhase = true;
    #elif defined(PLATFORM_DM1701)
    invertTxPhase = true;
    invertRxPhase = true;
    #endif

    // Main FSM logic
    switch(status->opStatus)
    {
        case OFF:
            offState(status);
            break;

        case RX:
            rxState(status);
            break;

        case TX:
            txState(status);
            break;

        default:
            break;
    }

    // Led control logic
    switch(status->opStatus)
    {
        case RX:

            if(dataValid)
                platform_ledOn(GREEN);
            else
                platform_ledOff(GREEN);
            break;

        case TX:
            platform_ledOff(GREEN);
            platform_ledOn(RED);
            break;

        default:
            platform_ledOff(GREEN);
            platform_ledOff(RED);
            break;
    }
}

uint8_t OpMode_M17::effectiveTxMode()
{
    uint8_t mode = crypto_getMode();
    if(crypto_getAdaptiveRx() && (varKeyMode != 0) && (getTick() < varKeyExpiry))
        mode = varKeyMode;

    return mode;
}

void OpMode_M17::offState(rtxStatus_t *const status)
{
    radio_disableRtx();

    codec_stop(txAudioPath);
    audioPath_release(txAudioPath);

    if(startRx)
    {
        status->opStatus = RX;
        return;
    }

    bool ptt = platform_getPttStatus();

    // Encryption is selected but the key slot is empty: block TX entirely so
    // nothing ever goes on air clear or with a zero key. The UI shows a red
    // "No Key" indicator; sound a long low warning tone once per key-up.
    uint8_t txMode = effectiveTxMode();
    if(ptt && (txMode != CRYPTO_OFF) && !crypto_keyPresent(txMode))
    {
        // Audible only when warning tones are enabled (vpLevel >= vpBeep);
        // played directly because the voice-prompt queue is muted under PTT.
        if(!noKeyWarned && (state.settings.vpLevel >= vpBeep))
        {
            noKeyWarned = true;
            pathId warnPath = audioPath_request(SOURCE_MCU, SINK_SPK, PRIO_PROMPT);
            platform_beepStart(NOKEY_WARN_TONE);
            for(int e = 0; e < NOKEY_WARN_MS; e += 10)
            {
                sleepFor(0, 10);
                if(platform_getPttStatus() == false)
                    break;
            }
            platform_beepStop();
            audioPath_release(warnPath);
        }

        sleepFor(0, 30);
        return;
    }

    if(ptt && (status->txDisable == 0))
    {
        // Clear-TX warning: before keying an unencrypted transmission, sound
        // the double beep. If the operator releases PTT during it, abort with
        // no RF emitted. Played directly (not via the voice-prompt queue, which
        // is silenced while PTT is held).
        if((txMode == CRYPTO_OFF) && crypto_getClearTxWarn() && !clearWarned)
        {
            clearWarned = true;
            pathId warnPath = audioPath_request(SOURCE_MCU, SINK_SPK, PRIO_PROMPT);
            bool keep = clearTxWarnTone();
            audioPath_release(warnPath);

            if(!keep)
            {
                status->opStatus = OFF;   // PTT released during warning: no TX
                return;
            }
        }

        startTx = true;
        status->opStatus = TX;
        return;
    }

    // Sleep for 30ms if there is nothing else to do in order to prevent the
    // rtx thread looping endlessly and locking up all the other tasks
    sleepFor(0, 30);
}

void OpMode_M17::rxState(rtxStatus_t *const status)
{
    if(startRx)
    {
        demodulator.startBasebandSampling();

        radio_enableRx();

        startRx = false;
    }

    bool newData = demodulator.update(invertRxPhase);
    bool lock    = demodulator.isLocked();

    // Reset frame decoder when transitioning from unlocked to locked state.
    if((lock == true) && (locked == false))
    {
        decoder.reset();
        locked = lock;
    }

    if(locked)
    {
        // Process new data
        if(newData)
        {
            auto& frame   = demodulator.getFrame();
            auto  type    = decoder.decodeFrame(frame);
            auto  lsf     = decoder.getLsf();
            status->lsfOk = lsf.valid();

            if(status->lsfOk)
            {
                dataValid = true;

                // Retrieve stream source and destination data
                Callsign dst = lsf.getDestination();
                Callsign src = lsf.getSource();
                strncpy(status->M17_dst, dst, 10);
                
                // Copy source callsign (may be overridden for extended callsigns)
                strncpy(status->M17_src, src, 10);

                // Retrieve extended callsign data
                streamType_t streamType = lsf.getType();

                uint8_t encT   = streamType.fields.encType;
                bool    isClear = (encT == M17_ENCTYPE_NONE);
                uint8_t rxMode = 0;
                rxEncrypt = false;

                if(isClear)
                {
                    // Unencrypted stream: the META field carries meta data.
                    meta_t& meta = lsf.metadata();

                    switch(streamType.fields.encSubType)
                    {
                        case META_EXTD_CALLSIGN:
                        {
                            extendedCall = true;
                            Callsign exCall1(meta.extended_call_sign.call1);
                            Callsign exCall2(meta.extended_call_sign.call2);

                            // The source callsign only contains the last link when
                            // receiving extended callsign data: store the first
                            // extended callsign in M17_src.
                            strncpy(status->M17_src,  exCall1, 10);
                            strncpy(status->M17_refl, exCall2, 10);
                            strncpy(status->M17_link, src, 10);
                            break;
                        }
                        case META_TEXT:
                        {
                            metaText.addBlock(meta);
                            const char* txt = metaText.getText();
                            if(txt != nullptr)
                                strncpy(status->M17_meta_text, txt, sizeof(status->M17_meta_text) - 1);
                            break;
                        }
                        default:
                            // M17_src already set above
                            break;
                    }
                }
                else if(encT == M17_ENCTYPE_AES)
                {
                    // Encrypted stream: META holds the AES-CTR nonce. Decrypt
                    // when we hold the matching key and either we run in crypto
                    // mode or "hear encrypted" is enabled in clear mode.
                    rxMode = streamType.fields.encSubType + 1;   // 1/2/3
                    bool allow = crypto_keyPresent(rxMode)
                              && ((crypto_getMode() != CRYPTO_OFF)
                                  || crypto_getHearEncrypted());

                    if(allow)
                    {
                        meta_t& meta = lsf.metadata();
                        memcpy(rxNonce, meta.raw_data, sizeof(rxNonce));
                        crypto_streamStart(rxMode);
                        rxEncrypt = true;

                        // Adaptive RX key: adjust the reply key length to the
                        // incoming call for a short window. UP escalates only
                        // (never steps down to a weaker key); MATCH adopts the
                        // incoming length exactly, up or down. Neither ever
                        // falls back to clear (rxMode is always encrypted here).
                        uint8_t adapt = crypto_getAdaptiveMode();
                        if(adapt != CRYPTO_ADAPT_OFF)
                        {
                            if(adapt == CRYPTO_ADAPT_MATCH)
                            {
                                varKeyMode = rxMode;
                            }
                            else // CRYPTO_ADAPT_UP
                            {
                                uint8_t base = crypto_getMode();
                                if((varKeyMode != 0) && (getTick() < varKeyExpiry)
                                   && (varKeyMode > base))
                                    base = varKeyMode;

                                if(rxMode > base)
                                    varKeyMode = rxMode;
                            }

                            if(varKeyMode != 0)
                                varKeyExpiry = getTick()
                                    + ((long long)crypto_getAdaptiveSecs() * 1000);
                        }
                    }
                }

                // Decide whether this stream is audible. A clear stream is muted
                // in crypto mode unless "hear clear" is set; an encrypted stream
                // only plays when we are set up to decrypt it.
                bool playable;
                if(isClear)
                    playable = (crypto_getMode() == CRYPTO_OFF)
                            || crypto_getHearClear();
                else
                    playable = rxEncrypt;

                status->cryptoKey = rxEncrypt ? rxMode : 0;

                // Check CAN on RX, if enabled.
                // If check is disabled, force match to true.
                bool canMatch =  (streamType.fields.CAN == status->can)
                              || (status->canRxEn == false);

                // Check if the destination callsign of the incoming transmission
                // matches with ours
                bool callMatch = (Callsign(status->source_address) == dst)
                               || dst.isSpecial();

                // Open audio path only if CAN and callsign match and the stream
                // is audible under the current encryption settings.
                uint8_t pthSts = audioPath_getStatus(rxAudioPath);
                if((pthSts == PATH_CLOSED) && canMatch && callMatch && playable)
                {
                    rxAudioPath = audioPath_request(SOURCE_MCU, SINK_SPK, PRIO_RX);
                    pthSts = audioPath_getStatus(rxAudioPath);
                }

                // Extract audio data and sent it to codec
                if((type == FrameType::STREAM) && (pthSts == PATH_OPEN))
                {
                    // (re)start codec2 module if not already up
                    if(codec_running() == false)
                        codec_startDecode(rxAudioPath);

                    StreamFrame sf = decoder.getStreamFrame();

                    // Decrypt the voice payload in place before Codec2.
                    if(rxEncrypt)
                    {
                        uint16_t fn = sf.getFrameNumber() & 0x7FFF;
                        crypto_apply(sf.data(), rxNonce, fn);
                    }

                    codec_pushFrame(sf.data(),     false);
                    codec_pushFrame(sf.data() + 8, false);
                }
            }
        }
    }

    locked = lock;

    if(platform_getPttStatus())
    {
        demodulator.stopBasebandSampling();
        locked = false;
        status->opStatus = OFF;
    }

    // Force invalidation of LSF data as soon as lock is lost (for whatever cause)
    if(locked == false)
    {
        status->lsfOk = false;
        dataValid     = false;
        extendedCall  = false;
        rxEncrypt     = false;
        status->cryptoKey = 0;
        status->M17_meta_text[0] = '\0';
        status->M17_link[0] = '\0';
        status->M17_refl[0] = '\0';

        metaText.reset();
        codec_stop(rxAudioPath);
        audioPath_release(rxAudioPath);
    }
}

void OpMode_M17::txState(rtxStatus_t *const status)
{
    frame_t m17Frame;

    if(startTx)
    {
        startTx = false;

        LinkSetupFrame lsf;

        lsf.clear();
        lsf.setSource(status->source_address);

        Callsign dst(status->destination_address);
        if(!dst.isEmpty())
            lsf.setDestination(dst);

        streamType_t type;
        type.value           = 0;                   // clear all fields first
        type.fields.dataMode = DATAMODE_STREAM;     // Stream
        type.fields.dataType = DATATYPE_VOICE;      // Voice data
        type.fields.CAN      = status->can;             // Channel access number

        // Pick the encryption mode for this transmission. With variable-key on,
        // a recent encrypted call's key length is used for the reply; otherwise
        // the configured mode. Encryption only engages if the key slot holds a
        // key (an absent/zero key never goes on air).
        uint8_t txMode = effectiveTxMode();

        txEncrypt  = false;
        txFrameNum = 0;
        if(txMode != CRYPTO_OFF)
        {
            // offState blocks a keyless encrypted TX; guard here too so we can
            // never fall through to a clear transmission when crypto is on.
            if(!crypto_streamStart(txMode))
            {
                startRx           = true;
                status->opStatus  = OFF;
                status->cryptoKey = 0;
                return;
            }

            txEncrypt = true;
            buildNonce(txNonce);
            type.fields.encType    = M17_ENCTYPE_AES;
            type.fields.encSubType = txMode - 1;    // 0/1/2 = 128/192/256
        }

        lsf.setType(type);

        if(txEncrypt)
        {
            // Encrypted stream: the META field carries the AES nonce, so
            // meta-text and GNSS cannot share this transmission.
            memcpy(lsf.metadata().raw_data, txNonce, sizeof(txNonce));
        }
        else
        {
            if(strlen(state.settings.M17_meta_text) > 0) {
                metaText.setText(state.settings.M17_meta_text);
                metaText.getNextBlock(lsf.metadata());
            }

            if(state.settings.gps_enabled) {
                lsf.setGnssData(&state.gps_data, GNSS_STATION_HANDHELD);
                gpsTimer = 0;
            }
        }

        status->cryptoKey = txEncrypt ? txMode : 0;

        encoder.reset();
        encoder.encodeLsf(lsf, m17Frame);

        txAudioPath = audioPath_request(SOURCE_MIC, SINK_MCU, PRIO_TX);
        codec_startEncode(txAudioPath);
        radio_enableTx();

        modulator.invertPhase(invertTxPhase);
        modulator.start();
        modulator.sendPreamble();
        modulator.sendFrame(m17Frame);
    }
    payload_t dataFrame;
    bool      lastFrame = false;

    // Wait until there are 16 bytes of compressed speech, then send them
    codec_popFrame(dataFrame.data(),     true);
    codec_popFrame(dataFrame.data() + 8, true);

    if(platform_getPttStatus() == false)
    {
        lastFrame = true;
        startRx   = true;
        status->opStatus = OFF;
    }

    // Encrypt the voice payload in place before FEC. The AES-CTR counter uses
    // the stream nonce and this frame's number, mirrored from the encoder.
    if(txEncrypt)
        crypto_apply(dataFrame.data(), txNonce, txFrameNum);

    encoder.encodeStreamFrame(dataFrame, m17Frame, lastFrame);
    txFrameNum = (txFrameNum + 1) & 0x7FFF;
    modulator.sendFrame(m17Frame);

    // After encoding a stream frame the encoder advances its LICH counter.
    // When it wraps back to zero a new superframe begins and the encoder
    // will accept an updated LSF.  Schedule the next meta-text block or
    // GPS update at this boundary so the new data is transmitted during
    // the upcoming superframe.
    // Meta-text and GNSS updates are skipped for encrypted streams, whose META
    // field is reserved for the (constant) AES nonce.
    if(encoder.superframeBoundary() && !txEncrypt)
    {
        if(strlen(state.settings.M17_meta_text) > 0) {
            auto lsf = encoder.getCurrentLsf();
            metaText.getNextBlock(lsf.metadata());
            encoder.updateLsfData(lsf);
        }

        if(state.settings.gps_enabled) {
            gpsTimer++;

            if(gpsTimer >= GPS_UPDATE_TICKS) {
                auto lsf = encoder.getCurrentLsf();
                lsf.setGnssData(&state.gps_data, GNSS_STATION_HANDHELD);
                encoder.updateLsfData(lsf);
                gpsTimer = 0;
            }
        }
    }

    if(lastFrame)
    {
        encoder.encodeEotFrame(m17Frame);
        modulator.sendFrame(m17Frame);
        modulator.stop();
    }
}

bool OpMode_M17::compareCallsigns(const std::string& localCs,
                                  const std::string& incomingCs)
{
    if((incomingCs == "ALL") || (incomingCs == "INFO") || (incomingCs == "ECHO"))
        return true;

    std::string truncatedLocal(localCs);
    std::string truncatedIncoming(incomingCs);

    int slashPos = localCs.find_first_of('/');
    if(slashPos <= 2)
        truncatedLocal = localCs.substr(slashPos + 1);

    slashPos = incomingCs.find_first_of('/');
    if(slashPos <= 2)
        truncatedIncoming = incomingCs.substr(slashPos + 1);

    if(truncatedLocal == truncatedIncoming)
        return true;

    return false;
}
