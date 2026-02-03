# VCSEC keycard / key programming-related routines (Tesla ODJ)

Source files:
- `/root/downloads/tesla_odj/Model 3/VCSEC.odj.json`
- `/root/downloads/tesla_odj/Model Y/VCSEC.odj.json`

Models compared: Model 3, Model Y
Routines identical across models: **true**

Selection notes:
- The VCSEC ODJ JSON does not include human-readable routine descriptions; this index is based on routine names and their structured I/O fields.
- The requested themes “add/pair key”, “all keys lost”, “recovery”, “emergency” do not appear as explicit routine names in these VCSEC ODJ routines.

## Security level highlights (selected routines)
- security_level 0: ENABLE_NFC_READER, GET_CARD_ON_READER, GET_EPHEMERAL_PUBKEY, GET_KEYCHAIN_TOKEN, GET_PERMISSION_FOR_KEY, GET_SESSION_INFO, GET_WHITELIST_ENTRY, GET_WHITELIST_ENTRY_COUNT, KEYFOB_SELF_TEST, ROTATE_EPHEMERAL_KEY, SEND_APDU, SEND_PROTOBUF, SET_ROOT_TRUST_KEY
- security_level 1: (none)
- security_level ≥5: GENERATE_IMMOBILIZER_KEY

## Routine index
### `ENABLE_NFC_READER`
- **id:** 0x809
- **security_level:** start=0, stop=0, results=0
- **short description:** Control (enable/disable/sleep) an NFC reader channel for a specified time.
- **start input_size:** 3 bytes
  - **inputs:**
    - `READER_CHANNEL` (uint, 8 bits, byte 0) — enum: NFC_READER_CENTER_CONSOLE=1, NFC_READER_LEFT_B_PILLAR=0, NFC_READER_RIGHT_B_PILLAR=2
    - `READER_STATE` (uint, 8 bits, byte 1) — enum: NFC_READER_DISABLE=0, NFC_READER_ENABLE=1, NFC_READER_SLEEP=2
    - `TIME_IN_SECONDS` (uint, 8 bits, byte 2)
- **start output_size:** 0 bytes
  - **outputs:**
    - (none)

### `GET_CARD_ON_READER`
- **id:** 0x810
- **security_level:** start=0, stop=0, results=0
- **short description:** Read NFC card public keys currently observed by the reader (up to 4 keys + ages).
- **start input_size:** 0 bytes
  - **inputs:**
    - (none)
- **start output_size:** 276 bytes
  - **outputs:**
    - `PUB_KEY_1` (bytes, 520 bits, byte 0)
    - `PUB_KEY_2` (bytes, 520 bits, byte 65)
    - `PUB_KEY_3` (bytes, 520 bits, byte 130)
    - `PUB_KEY_4` (bytes, 520 bits, byte 195)
    - `PUB_KEY_1_AGE` (uint, 32 bits, byte 260)
    - `PUB_KEY_2_AGE` (uint, 32 bits, byte 264)
    - `PUB_KEY_3_AGE` (uint, 32 bits, byte 268)
    - `PUB_KEY_4_AGE` (uint, 32 bits, byte 272)

### `SEND_APDU`
- **id:** 0x802
- **security_level:** start=0, stop=0, results=0
- **short description:** Send an APDU payload to an NFC card via a selected reader/card channel; returns command status.
- **start input_size:** 98 bytes
  - **inputs:**
    - `NFCREADER_INDEX` (uint, 8 bits, byte 0) — enum: NFC_READER_CENTER_CONSOLE=1, NFC_READER_LEFT_B_PILLAR=0, NFC_READER_RIGHT_B_PILLAR=2
    - `NFCCARD_INDEX` (uint, 8 bits, byte 1) — enum: NFCCARD_CHANNEL0=0, NFCCARD_CHANNEL1=1, NFCCARD_CHANNEL2=2
    - `APDU_LENGTH` (uint, 16 bits, byte 2)
    - `APDU_DATA` (bytes, 752 bits, byte 4)
- **start output_size:** 1 bytes
  - **outputs:**
    - `APDU_COMMAND_STATUS` (uint, 8 bits, byte 0) — enum: 8 values

### `SEND_PROTOBUF`
- **id:** 0x710
- **security_level:** start=0, stop=0, results=0
- **short description:** Send an opaque protobuf blob to VCSEC (ODJ does not define the message schema).
- **start input_size:** 350 bytes
  - **inputs:**
    - `DATA` (bytes, 2800 bits, byte 0)
- **start output_size:** 0 bytes
  - **outputs:**
    - (none)

### `GET_KEYCHAIN_TOKEN`
- **id:** 0x730
- **security_level:** start=0, stop=0, results=0
- **short description:** Return a keychain token for a given channel (used by higher-level key operations).
- **start input_size:** 1 bytes
  - **inputs:**
    - `CHANNEL` (uint, 8 bits, byte 0)
- **start output_size:** 21 bytes
  - **outputs:**
    - `SUCCESS` (uint, 8 bits, byte 0)
    - `TOKEN` (bytes, 160 bits, byte 1)

### `GET_PERMISSION_FOR_KEY`
- **id:** 0x705
- **security_level:** start=0, stop=0, results=0
- **short description:** Query whether a specific permission is set for a given key identifier.
- **start input_size:** 2 bytes
  - **inputs:**
    - `KEYID` (uint, 8 bits, byte 0)
    - `PERMISSION` (uint, 8 bits, byte 1)
- **start output_size:** 1 bytes
  - **outputs:**
    - `ISSET` (uint, 1 bits, byte 0) — enum: FALSE=0, TRUE=1

### `GET_WHITELIST_ENTRY`
- **id:** 0x701
- **security_level:** start=0, stop=0, results=0
- **short description:** Read a whitelist slot (slot-filled flag, public key length, public key bytes).
- **start input_size:** 1 bytes
  - **inputs:**
    - `INDEX` (uint, 8 bits, byte 0)
- **start output_size:** 102 bytes
  - **outputs:**
    - `SLOTFILLED` (uint, 8 bits, byte 0)
    - `PUBKEYLENGTH` (uint, 8 bits, byte 1)
    - `PUBLICKEY` (bytes, 800 bits, byte 2)

### `GET_WHITELIST_ENTRY_COUNT`
- **id:** 0x708
- **security_level:** start=0, stop=0, results=0
- **short description:** Return the number of whitelist entries supported/present.
- **start input_size:** 0 bytes
  - **inputs:**
    - (none)
- **start output_size:** 1 bytes
  - **outputs:**
    - `ENTRY_COUNT` (uint, 8 bits, byte 0)

### `GET_SESSION_INFO`
- **id:** 0x735
- **security_level:** start=0, stop=0, results=0
- **short description:** Return session metadata for a key slot (public key + counters/epoch/time).
- **start input_size:** 1 bytes
  - **inputs:**
    - `KEY_SLOT` (uint, 8 bits, byte 0)
- **start output_size:** 90 bytes
  - **outputs:**
    - `SUCCESS` (uint, 8 bits, byte 0)
    - `COUNTER` (uint, 32 bits, byte 1)
    - `PUBLICKEY` (bytes, 520 bits, byte 5)
    - `EPOCH` (bytes, 128 bits, byte 70)
    - `TIME` (uint, 32 bits, byte 86)

### `GET_EPHEMERAL_PUBKEY`
- **id:** 0x715
- **security_level:** start=0, stop=0, results=0
- **short description:** Return the current ephemeral public key and its validity/length.
- **start input_size:** 0 bytes
  - **inputs:**
    - (none)
- **start output_size:** 103 bytes
  - **outputs:**
    - `KEYVALID` (bytes, 8 bits, byte 0)
    - `KEYLENGTH` (uint, 16 bits, byte 1)
    - `KEY` (bytes, 800 bits, byte 3)

### `ROTATE_EPHEMERAL_KEY`
- **id:** 0x770
- **security_level:** start=0, stop=0, results=0
- **short description:** Rotate/regenerate the ephemeral key; returns success boolean.
- **start input_size:** 0 bytes
  - **inputs:**
    - (none)
- **start output_size:** 1 bytes
  - **outputs:**
    - `SUCCESS` (uint, 1 bits, byte 0) — enum: FALSE=0, TRUE=1

### `SET_ROOT_TRUST_KEY`
- **id:** 0x725
- **security_level:** start=0, stop=0, results=0
- **short description:** Select which root trust key set to use (e.g., mothership vs region).
- **start input_size:** 1 bytes
  - **inputs:**
    - `ROOT_TRUST_KEY` (uint, 8 bits, byte 0) — enum: MOTHERSHIP=0, NORTH_AMERICA=1
- **start output_size:** 0 bytes
  - **outputs:**
    - (none)

### `GENERATE_IMMOBILIZER_KEY`
- **id:** 0x720
- **security_level:** start=5, stop=5, results=5
- **short description:** Generate immobilizer key material; gated by higher security level.
- **start input_size:** 0 bytes
  - **inputs:**
    - (none)
- **start output_size:** 18 bytes
  - **outputs:**
    - `SUCCESS` (bytes, 8 bits, byte 0)
    - `KEY` (bytes, 128 bits, byte 1)
    - `TIMERSTARTED` (bytes, 8 bits, byte 17)

### `KEYFOB_SELF_TEST`
- **id:** 0x531
- **security_level:** start=0, stop=0, results=0
- **short description:** Run a keyfob subsystem self-test routine (no structured I/O in ODJ).
- **start input_size:** 0 bytes
  - **inputs:**
    - (none)
- **start output_size:** 0 bytes
  - **outputs:**
    - (none)
