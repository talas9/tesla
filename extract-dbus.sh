#!/bin/bash
BINARIES=(
  "/root/downloads/mcu2-extracted/usr/tesla/UI/bin/QtCarServer"
  "/root/downloads/mcu2-extracted/usr/tesla/UI/lib/libQtCarGUI.so"
  "/root/downloads/mcu2-extracted/usr/tesla/UI/lib/libQtCarVAPI.so"
  "/root/downloads/mcu2-extracted/usr/tesla/UI/lib/libQtCarServiceMgr.so"
  "/root/downloads/mcu2-extracted/usr/tesla/UI/lib/libQtCarDiag.so"
)

echo "# D-Bus Interface Extraction from Tesla MCU2 Binaries"
echo ""

for bin in "${BINARIES[@]}"; do
  if [ -f "$bin" ]; then
    echo "## $(basename $bin)"
    echo ""
    strings "$bin" | grep -E '<interface name=|<method name=|<signal name=|<property name=' | sort -u
    echo ""
  fi
done
