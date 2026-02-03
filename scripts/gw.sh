#!/usr/bin/env bash
# -----------------------------------------------------------------------------
#  CONFIG EDITOR (UDPAPI) - Enhanced Interactive Shell
#
#  Original concept + author credit preserved from:
#    config_editor.sh  (By: Talas9) :contentReference[oaicite:1]{index=1}
#
#  This tool sends RAW BYTES over UDP to Tesla Gateway UDPAPI using:
#    echo HEX | xxd -r -p | socat - udp:HOST:PORT
#
#  Notes:
#   - Success is typically an echo of the sent payload (hex).
#   - Failure signature seen in original: "ff"
# -----------------------------------------------------------------------------

set -u

# Defaults (override via env: UDP_HOST / UDP_PORT)
UDP_HOST="${UDP_HOST:-192.168.90.102}"
UDP_PORT="${UDP_PORT:-3500}"

UDPAPI_SIG_FAILURE="ff"
RETRY_COUNT_DEFAULT=3
RETRY_SLEEP_DEFAULT=1

# Response status codes (byte 1 of 2-byte responses)
# Format: <opcode><status>
# Example: 1801 = opcode 0x18, status 0x01
STATUS_OK_NO_CHANGE="00"
STATUS_OK_ACCEPTED="01"
STATUS_REJECTED="ff"

# --- UI helpers --------------------------------------------------------------

clear_screen() { echo ""; }

greeting() {
  cat <<'EOF'

  / ___/ _ \| \ | |  ___|_ _/ ___|
 | |  | | | |  \| | |_   | | |  _
 | |__| |_| | |\  |  _|  | | |_| |
  \____\___/|_| \_|_|   |___\____|

  By: Talas9
EOF
  echo ""
  echo "  Enhanced interactive UDPAPI editor"
  echo ""
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[ERROR] Missing dependency: $1"
    exit 1
  }
}

deps_check() {
  need_cmd socat
  need_cmd xxd
  need_cmd hexdump
  need_cmd printf
}

# --- Validation --------------------------------------------------------------

is_hex_even_len() {
  # Accepts lowercase/uppercase hex without 0x, must be even length
  local s
  s="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$s" =~ ^[0-9a-f]+$ ]] || return 1
  (( ${#s} % 2 == 0 )) || return 1
  return 0
}

strip_hex_prefixes_and_spaces() {
  # Converts:
  #  "0x18 0xba 0xbb 0xa0 0xad" -> "18babba0ad"
  #  "18 ba bb a0 ad"          -> "18babba0ad"
  #  "18babba0ad"              -> "18babba0ad"
  local in="$1"
  in="${in//0x/}"
  in="${in//0X/}"
  in="${in// /}"
  in="${in//,/}"
  echo "$in" | tr '[:upper:]' '[:lower:]'
}

# --- Core UDP send -----------------------------------------------------------

udp_send_hex() {
  # Sends HEX payload (no spaces, no 0x) and prints response HEX on stdout.
  # Returns:
  #  0 success echo-match
  #  2 secured/failure signature "ff"
  #  1 unexpected/timeout/mismatch after retries
  local hex
  hex="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  local retries="${2:-$RETRY_COUNT_DEFAULT}"
  local sleep_s="${3:-$RETRY_SLEEP_DEFAULT}"

  if ! is_hex_even_len "$hex"; then
    echo "[ERROR] Invalid hex payload (must be even-length hex): '$hex'" >&2
    return 1
  fi

  local cmd_hex="$hex"
  local rsp=""
  local attempt=1

  while (( attempt <= retries )); do
    # socat reads from stdin and writes response to stdout
    rsp="$(
      echo "$cmd_hex" \
        | xxd -r -p \
        | socat - "udp:${UDP_HOST}:${UDP_PORT}" 2>/dev/null \
        | hexdump -v -e '1/1 "%02x"'
    )"

    # If socat returns nothing (timeout/no reply), rsp will be empty.
    if [[ -z "$rsp" ]]; then
      echo "[WARN] No response (attempt $attempt/$retries)"
    else
      echo "RESPONSE: $rsp"

      # Check for full echo-match (some commands echo entire payload)
      if [[ "$rsp" == "$cmd_hex" ]]; then
        echo "[SUCCESS] Echo-match"
        return 0
      fi

      # Check for single-byte failure
      if [[ "$rsp" == "$UDPAPI_SIG_FAILURE" ]]; then
        echo "[FAIL] Config is secured (signature failure: ff)"
        return 2
      fi

      # Check for 2-byte status response: <opcode><status>
      if [[ ${#rsp} -eq 4 ]]; then
        local rsp_opcode="${rsp:0:2}"
        local rsp_status="${rsp:2:2}"
        local cmd_opcode="${cmd_hex:0:2}"

        # Verify opcode matches what we sent
        if [[ "$rsp_opcode" == "$cmd_opcode" ]]; then
          case "$rsp_status" in
            "$STATUS_OK_ACCEPTED")
              echo "[SUCCESS] Command accepted (status: 01)"
              return 0
              ;;
            "$STATUS_OK_NO_CHANGE")
              echo "[SUCCESS] OK / no change (status: 00)"
              return 0
              ;;
            "$STATUS_REJECTED")
              echo "[FAIL] Command rejected (status: ff)"
              return 2
              ;;
            *)
              echo "[INFO] Unknown status byte: $rsp_status"
              ;;
          esac
        fi
      fi

      echo "[WARN] Unexpected response (attempt $attempt/$retries)"
    fi

    ((attempt++))
    sleep "$sleep_s"
  done

  echo "[FAIL] No valid echo-match after retries"
  return 1
}

# --- Protocol helpers --------------------------------------------------------

# Read config uses: 0b00<ID>
read_config_id() {
  local cfg_id_hex
  cfg_id_hex="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  if [[ ! "$cfg_id_hex" =~ ^[0-9a-f]{2}$ ]]; then
    echo "[ERROR] Config ID must be 1 byte hex (e.g. '3a' or '0f')"
    return 1
  fi
  local cmd="0b00${cfg_id_hex}"
  echo "READ CMD: $cmd"
  local rsp
  rsp="$(
    echo "$cmd" | xxd -r -p | socat - "udp:${UDP_HOST}:${UDP_PORT}" 2>/dev/null | hexdump -v -e '1/1 "%02x"'
  )"
  echo "Current config value is: ${rsp:-<no response>}"
}

# Write config uses: 0c00<ID><VAL...>
write_config() {
  local cmd_hex
  cmd_hex="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  echo "WRITE CMD: $cmd_hex"
  udp_send_hex "$cmd_hex"
  return $?
}

# gw-diag style: raw bytes (already)
gw_diag_send() {
  local raw_in="$1"
  local hex
  hex="$(strip_hex_prefixes_and_spaces "$raw_in")"
  echo "GW-DIAG HEX: $hex"
  udp_send_hex "$hex"
  return $?
}

# --- Menus -------------------------------------------------------------------

configure_target() {
  clear_screen
  echo "Current target: ${UDP_HOST}:${UDP_PORT}"
  echo "Press Enter to keep current values."
  read -r -p "UDP Host [${UDP_HOST}]: " h
  read -r -p "UDP Port [${UDP_PORT}]: " p
  [[ -n "${h:-}" ]] && UDP_HOST="$h"
  [[ -n "${p:-}" ]] && UDP_PORT="$p"
  echo "Target set: ${UDP_HOST}:${UDP_PORT}"
  echo ""
}

menu_das_hw() { # 59 (0x3b)
  local cfg_id_dec=59
  local cfg_id
  cfg_id="$(printf "%02x" "$cfg_id_dec")"

  clear_screen
  read_config_id "$cfg_id"
  echo ""
  echo "Choose DAS HW (CFG ${cfg_id_dec} / 0x${cfg_id}):"
  echo "1) PARKER_PASCAL_2_5  -> 03"
  echo "2) TESLA_AP3          -> 04"
  echo "3) Back"
  read -r -p "> " c
  case "$c" in
    1) write_config "0c00${cfg_id}03" ;;
    2) write_config "0c00${cfg_id}04" ;;
    *) return 0 ;;
  esac
}

menu_headlights() { # 28 (0x1c)
  local cfg_id_dec=28
  local cfg_id
  cfg_id="$(printf "%02x" "$cfg_id_dec")"

  clear_screen
  read_config_id "$cfg_id"
  echo ""
  echo "Choose headlights option (CFG ${cfg_id_dec} / 0x${cfg_id}):"
  echo "1) Base    -> 00"
  echo "2) Premium -> 01"
  echo "3) Global  -> 02"
  echo "4) Back"
  read -r -p "> " c
  case "$c" in
    1) write_config "0c00${cfg_id}00" ;;
    2) write_config "0c00${cfg_id}01" ;;
    3) write_config "0c00${cfg_id}02" ;;
    *) return 0 ;;
  esac
}

menu_map_region() { # 66 (0x42)
  local cfg_id_dec=66
  local cfg_id
  cfg_id="$(printf "%02x" "$cfg_id_dec")"

  clear_screen
  read_config_id "$cfg_id"
  echo ""
  echo "Choose map region (CFG ${cfg_id_dec} / 0x${cfg_id}):"
  echo "1) US   -> 00"
  echo "2) EU   -> 01"
  echo "3) NONE -> 02"
  echo "4) CN   -> 03"
  echo "5) AU   -> 04"
  echo "6) JP   -> 05"
  echo "7) TW   -> 06"
  echo "8) KR   -> 07"
  echo "9) ME   -> 08"
  echo "10) HK  -> 09"
  echo "11) MO  -> 0a"
  echo "12) SE  -> 0b"
  echo "13) Back"
  read -r -p "> " c
  case "$c" in
    1)  write_config "0c00${cfg_id}00" ;;
    2)  write_config "0c00${cfg_id}01" ;;
    3)  write_config "0c00${cfg_id}02" ;;
    4)  write_config "0c00${cfg_id}03" ;;
    5)  write_config "0c00${cfg_id}04" ;;
    6)  write_config "0c00${cfg_id}05" ;;
    7)  write_config "0c00${cfg_id}06" ;;
    8)  write_config "0c00${cfg_id}07" ;;
    9)  write_config "0c00${cfg_id}08" ;;
    10) write_config "0c00${cfg_id}09" ;;
    11) write_config "0c00${cfg_id}0a" ;;
    12) write_config "0c00${cfg_id}0b" ;;
    *) return 0 ;;
  esac
}

menu_country() { # 06 (0x06) ASCII 2 bytes in original
  local cfg_id_dec=6
  local cfg_id
  cfg_id="$(printf "%02x" "$cfg_id_dec")"

  clear_screen
  read_config_id "$cfg_id"
  echo ""
  echo "Choose country (CFG ${cfg_id_dec} / 0x${cfg_id}) [ASCII 2 letters]:"
  echo "1) US"
  echo "2) DE"
  echo "3) NL"
  echo "4) AE"
  echo "5) PL"
  echo "6) JO"
  echo "7) UK"
  echo "8) RU"
  echo "9) Back"
  read -r -p "> " c
  local cc=""
  case "$c" in
    1) cc="US" ;;
    2) cc="DE" ;;
    3) cc="NL" ;;
    4) cc="AE" ;;
    5) cc="PL" ;;
    6) cc="JO" ;;
    7) cc="UK" ;;
    8) cc="RU" ;;
    *) return 0 ;;
  esac
  local cc_hex
  cc_hex="$(printf "%s" "$cc" | hexdump -v -e '1/1 "%02x"')"
  write_config "0c00${cfg_id}${cc_hex}"
}

menu_supercharging_access() { # 30 (0x1e)
  local cfg_id_dec=30
  local cfg_id
  cfg_id="$(printf "%02x" "$cfg_id_dec")"

  clear_screen
  read_config_id "$cfg_id"
  echo ""
  echo "Choose supercharging access (CFG ${cfg_id_dec} / 0x${cfg_id}):"
  echo "1) NOT_ALLOWED -> 00"
  echo "2) ALLOWED     -> 01"
  echo "3) PAY_AS_YOU_GO-> 02"
  echo "4) Back"
  read -r -p "> " c
  case "$c" in
    1) write_config "0c00${cfg_id}00" ;;
    2) write_config "0c00${cfg_id}01" ;;
    3) write_config "0c00${cfg_id}02" ;;
    *) return 0 ;;
  esac
}

menu_unlock_switch() {
  clear_screen
  echo "Unlock switch (gw-diag equivalent): 18 BA BB A0 AD"
  echo ""
  # Your original unlockSwitch() does: set_config 18babba0ad
  gw_diag_send "18babba0ad"
}

menu_promote() {
  clear_screen
  echo "Promote/privilege packet (as per original): 14 DE AD BE EF"
  echo ""
  gw_diag_send "14deadbeef"
}

menu_set_vin() {
  clear_screen
  read -r -p "Enter VIN (17 chars, A-Z 0-9): " vin
  vin="$(echo "$vin" | tr '[:lower:]' '[:upper:]')"
  if [[ ! "$vin" =~ ^[0-9A-Z]{17}$ ]]; then
    echo "[ERROR] Invalid VIN format"
    return 1
  fi
  local vin_hex
  vin_hex="$(printf "%s" "$vin" | hexdump -v -e '1/1 "%02x"')"
  local cmd="0c0000${vin_hex}"
  write_config "$cmd"
}

menu_other_config() {
  clear_screen
  read -r -p "Enter config ID (hex, 1 byte, e.g. 0f or 3a): " cfg_id
  cfg_id="$(echo "$cfg_id" | tr '[:upper:]' '[:lower:]')"
  cfg_id="${cfg_id#0x}"
  if [[ ! "$cfg_id" =~ ^[0-9a-f]{2}$ ]]; then
    echo "[ERROR] Config ID must be 2 hex chars"
    return 1
  fi

  read -r -p "Enter value (hex, any length, e.g. 01 or 4145): " cfg_val
  cfg_val="$(echo "$cfg_val" | tr '[:upper:]' '[:lower:]')"
  cfg_val="${cfg_val#0x}"
  cfg_val="${cfg_val// /}"

  if ! is_hex_even_len "$cfg_val"; then
    echo "[ERROR] Value must be even-length hex"
    return 1
  fi

  write_config "0c00${cfg_id}${cfg_val}"
}

menu_gw_diag_custom() {
  clear_screen
  echo "GW-DIAG / Raw UDP packet sender"
  echo "Enter either:"
  echo "  - compact hex: 18babba0ad"
  echo "  - or bytes:    0x18 0xba 0xbb 0xa0 0xad"
  echo "Empty input = back"
  echo ""
  while true; do
    read -r -p "gw-diag> " line
    [[ -z "${line:-}" ]] && return 0
    gw_diag_send "$line"
    echo ""
  done
}

main_menu() {
  while true; do
    clear_screen
    echo "Target: ${UDP_HOST}:${UDP_PORT}"
    echo ""
    echo "1) Configure target host/port"
    echo "2) DAS HW"
    echo "3) Headlights"
    echo "4) Map Region"
    echo "5) Country"
    echo "6) Supercharging Access"
    echo "7) Promote (14deadbeef)"
    echo "8) UnlockSwitch (18babba0ad)"
    echo "9) Set VIN"
    echo "10) Other config write (0c00<ID><VAL>)"
    echo "11) GW-DIAG custom (raw bytes)"
    echo "0) Quit"
    echo ""
    read -r -p "> " choice
    case "$choice" in
      1) configure_target ;;
      2) menu_das_hw ;;
      3) menu_headlights ;;
      4) menu_map_region ;;
      5) menu_country ;;
      6) menu_supercharging_access ;;
      7) menu_promote ;;
      8) menu_unlock_switch ;;
      9) menu_set_vin ;;
      10) menu_other_config ;;
      11) menu_gw_diag_custom ;;
      0) exit 0 ;;
      *) echo "Invalid choice"; sleep 1 ;;
    esac
    echo ""
    read -r -p "Press Enter to continue..." _
  done
}

# --- Entry -------------------------------------------------------------------

deps_check
greeting
main_menu
