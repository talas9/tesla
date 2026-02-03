#!/bin/bash

UDPAPI_SIG_FAILURE="ff"

clear() {
    echo ""
    # echo -e "\e[1;1H\e[2J"
}

greeting() {
    echo "
  / ___/ _ \| \ | |  ___|_ _/ ___|
 | |  | | | |  \| | |_   | | |  _
 | |__| |_| | |\  |  _|  | | |_| |
  \____\___/|_| \_|_|   |___\____|

  By: Talas9
  "
}

read_config() {
    clear
    echo "0b00$1" | xxd -r -p >cmd
    CURRENT_CFG_VAL=$(cat cmd | socat - udp:192.168.90.102:3500 | hexdump -v -e '1/1 "%02x"')
    echo "Current config value is: $CURRENT_CFG_VAL"
}

set_config() {
    echo $1
    echo $1 | xxd -r -p >cmd
    local COUNT=3
    local CMD_HEX=$(hexdump -v -e '1/1 "%02x"' cmd)
    while [ "$COUNT" -gt 0 ]; do
        local RSP=$(cat cmd | socat - udp:192.168.90.102:3500 | hexdump -v -e '1/1 "%02x"')
        echo "RESPONSE IS:"
        echo $RSP
        [ "$RSP" == "$CMD_HEX" ] && echo "[SUCCESS] Config changed" && return 0
        [ "$RSP" == "$UDPAPI_SIG_FAILURE" ] && echo "[FAIL] Config is secured" && return 2
        echo "Unexpected response from UDPAPI: '$RSP'"
        COUNT=$((COUNT - 1))
        sleep 1
    done
    echo "[FAIL]"
    return 1
}

dasHw() { # 59
    CFG_ID_DEC=59
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose DAS HW: '
    COLUMNS=1
    options=("PARKER_PASCAL_2_5" "TESLA_AP3" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "PARKER_PASCAL_2_5 -> 03") CFG_VAL_DEC=03 ;;
        "TESLA_AP3 -> 04") CFG_VAL_DEC=04 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        dasHw
    done

}

headlights() { # 28
    CFG_ID_DEC=28
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose headlights option: '
    COLUMNS=1
    options=("Base" "Premium" "Global" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "Base -> 00") CFG_VAL_DEC=00 ;;
        "Premium -> 01") CFG_VAL_DEC=01 ;;
        "Global -> 02") CFG_VAL_DEC=02 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" continue ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        headlights
    done
}

mapRegion() { # 66
    CFG_ID_DEC=66
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose map region: '
    COLUMNS=1
    options=("NONE" "US" "EU" "CN" "AU" "JP" "TW" "KR" "ME" "HK" "MO" "SE" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "NONE -> 02") CFG_VAL_DEC=02 ;;
        "US -> 00") CFG_VAL_DEC=00 ;;
        "EU -> 01") CFG_VAL_DEC=01 ;;
        "CN -> 03") CFG_VAL_DEC=03 ;;
        "AU -> 04") CFG_VAL_DEC=04 ;;
        "JP -> 05") CFG_VAL_DEC=05 ;;
        "TW -> 06") CFG_VAL_DEC=06 ;;
        "KR -> 07") CFG_VAL_DEC=07 ;;
        "ME -> 08") CFG_VAL_DEC=08 ;;
        "HK -> 09") CFG_VAL_DEC=09 ;;
        "MO -> 10") CFG_VAL_DEC=10 ;;
        "SE -> 11") CFG_VAL_DEC=11 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        mapRegion
    done
}

country() { # 06
    CFG_ID_DEC=6
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose country: '
    COLUMNS=1
    options=("US" "DE" "NL" "AE" "PL" "JO" "UK" "RU" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "US") ;;
        "DE") ;;
        "NL") ;;
        "AE") ;;
        "PL") ;;
        "JO") ;;
        "UK") ;;
        "RU") ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf $opt | hexdump -v -e '1/1 "%02x"')
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        country
    done
}

tiltscreen() { # 132
    CONF_ID_DEC=132
    CFG_ID=$(printf "%02x" $CONF_ID_DEC)
    read_config $CFG_ID
    PS3='Choose tilt screen option: '
    COLUMNS=1
    options=("0" "1" "2" "3" "4" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "0") ;;
        "1") ;;
        "2") ;;
        "3") ;;
        "4") ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf $opt | hexdump -v -e '1/1 "%02x"')
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        tiltscreen
    done
}

caliperColorType() { # 150
    CFG_ID_DEC=150
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose caliper color option: '
    COLUMNS=1
    options=("0" "1" "2" "3" "4" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "0") ;;
        "1") ;;
        "2") ;;
        "3") ;;
        "4") ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf $opt | hexdump -v -e '1/1 "%02x"')
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        caliperColorType
    done

}

frontUsbHubType() { #133
    CFG_ID_DEC=133
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose front USB hub type: '
    COLUMNS=1
    options=("0" "1" "2" "3" "4" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "0") ;;
        "1") ;;
        "2") ;;
        "3") ;;
        "4") ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf $opt | hexdump -v -e '1/1 "%02x"')
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        frontUsbHubType
    done
}

plcSupportType() { # 70
    CFG_ID_DEC=70
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose PLC support type: '
    COLUMNS=1
    options=("NONE" "ONBOARD_ADAPTER" "NATIVE_CHARGE_PORT" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "NONE") CFG_VAL_DEC=00 ;;
        "ONBOARD_ADAPTER") CFG_VAL_DEC=01 ;;
        "NATIVE_CHARGE_PORT") CFG_VAL_DEC=02 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        plcSupportType
    done
}

trackModePackage() { # 64
    CFG_ID_DEC=64
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose track mode package: '
    COLUMNS=1
    options=("NONE" "PERFORMANCE" "ENABLED_UI_SOS" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "NONE") CFG_VAL_DEC=00 ;;
        "PERFORMANCE") CFG_VAL_DEC=01 ;;
        "ENABLED_UI_SOS") CFG_VAL_DEC=02 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        trackModePackage
    done

}

performancePackage() { # 48
    CFG_ID_DEC=48
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose performance package: '
    COLUMNS=1
    options=("BASE" "PERFORMANCE" "BASE_PLUS" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "BASE") CFG_VAL_DEC=00 ;;
        "PERFORMANCE") CFG_VAL_DEC=01 ;;
        "BASE_PLUS") CFG_VAL_DEC=03 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        performancePackage
    done
}

superchargingAccess() { # 30
    CFG_ID_DEC=30
    CFG_ID=$(printf "%02x" $CFG_ID_DEC)
    read_config $CFG_ID
    PS3='Choose supercharging access: '
    COLUMNS=1
    options=("NOT_ALLOWED" "ALLOWED" "PAY_AS_YOU_GO" "Back" "Quit")

    select opt in "${options[@]}"; do
        case $opt in
        "NOT_ALLOWED") CFG_VAL_DEC=00 ;;
        "ALLOWED") CFG_VAL_DEC=01 ;;
        "PAY_AS_YOU_GO") CFG_VAL_DEC=02 ;;
        "Back") mainMenu ;;
        "Quit") exit ;;
        *) echo "invalid option $REPLY" ;;
        esac
        CFG_VAL=$(printf "%02x" $CFG_VAL_DEC)
        CMD="0c00${CFG_ID}${CFG_VAL}"
        set_config $CMD
        sleep 1
        superchargingAccess
    done
}

rearfog() {
    read_config 0c003a
    set_config 0c003a01
    sleep 2
    mainMenu
}

spoiler_rear() {
    read_config 0c0043
    set_config 0c004302
    sleep 2
    mainMenu
}

homelink() {
    read_config 0c0012
    set_config 0c001201
    sleep 2
    mainMenu
}

boombox() {
    read_config 0c002c
    set_config 0c002c01
    sleep 2
    mainMenu
}

unlockSwitch() {
    set_config 18babba0ad
    mainMenu
}

promote() {
    # set_config 0c000f03
    set_config 14deadbeef
    sleep 2
    mainMenu
}

vin() {
    echo "Enter VIN: "
    read VIN
    echo "VIN IS ${VIN}"
    REGEX="^[0-9A-Z-]{17}$"
    if [[ ! $VIN =~ $REGEX ]]; then
        echo "Wrong input!"
        return 0
    fi
    VIN=$(printf $VIN | hexdump -v -e '1/1 "%02x"')
    CMD="0c0000${VIN}"
    set_config $CMD
}
other() {
    echo "Enter config ID [in hex] [15 is 0f] "
    read CFG_ID
    echo "Enter value [in hex] [1 is 01]"
    read CFG_VAL
    CMD="0c00${CFG_ID}${CFG_VAL}"
    set_config $CMD
}
custom() {
    echo "Enter command:"
    read a
    echo $a | xxd -r -p >cmd
    local COUNT=3
    local CMD_HEX=$(hexdump -v -e '1/1 "%02x"' cmd)
    echo response is:
    echo $(cat cmd | socat - udp:192.168.90.102:3500 | hexdump -v -e '1/1 "%02x"')
    custom
}

mainMenu() {
    clear
    echo "1. dasHw"
    echo "2. headlights"
    echo "3. mapRegion"
    echo "4. country"
    echo "5. tiltscreen"
    echo "6. caliperColorType"
    echo "7. frontUsbHubType"
    echo "8. plcSupportType"
    echo "9. trackModePackage"
    echo "10. performancePackage"
    echo "11. superchargingAccess"
    echo "12. rearfog"
    echo "13. spoiler_rear"
    echo "14. homelink"
    echo "15. Boombox"
    echo "16. promote"
    echo "17. unlockSwitch"
    echo "18. VIN"
    echo "19. Other"
    echo "20. Quit"

    echo "Enter your choice [ 1 - 20 ]"
    read choice
    case $choice in
    1) dasHw ;;
    2) headlights ;;
    3) mapRegion ;;
    4) country ;;
    5) tiltscreen ;;
    6) caliperColorType ;;
    7) frontUsbHubType ;;
    8) plcSupportType ;;
    9) trackModePackage ;;
    10) performancePackage ;;
    11) superchargingAccess ;;
    12) rearfog ;;
    13) spoiler_rear ;;
    14) homelink ;;
    15) boombox ;;
    16) promote ;;
    17) unlockSwitch ;;
    18) vin ;;
    19) other ;;
    20) exit 0 ;;
    99) custom ;;
    *) echo "Invalid input..." ;;
    esac
}

greeting
echo ""
echo ""
mainMenu
