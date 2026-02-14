#!/usr/bin/env bash
# Copyright 2026 The Zaparoo Project Contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Validates PN532 I2C communication on real hardware.
# Intended for Raspberry Pi with PN532 connected via I2C.
#
# Usage:
#   ./scripts/i2c-validate.sh              # auto-detect bus
#   ./scripts/i2c-validate.sh /dev/i2c-1   # specific bus
#
# Prerequisites:
#   - i2c-tools (apt install i2c-tools)
#   - Go toolchain
#   - User in i2c group or running as root

set -euo pipefail

# i2cdetect lives in /usr/sbin which may not be in PATH for non-login shells
export PATH="/usr/sbin:/sbin:$PATH"

PN532_ADDR_7BIT="24"
PN532_ADDR_HEX="0x24"

echo "PN532 I2C Validation"
echo "===================="
echo ""

# Check prerequisites
for cmd in i2cdetect go make; do
	if ! command -v "$cmd" &>/dev/null; then
		echo "FAIL: $cmd not found. Install it and try again."
		exit 1
	fi
done

# Extract bus number from a device path like /dev/i2c-1
bus_num() {
	echo "$1" | sed 's/.*-//'
}

# Check if a bus has a device at the PN532 address.
# Captures i2cdetect output before grepping to avoid SIGPIPE from grep -q
# killing i2cdetect and triggering a pipefail false-negative.
bus_has_pn532() {
	local output
	output=$(i2cdetect -y "$1" 2>/dev/null) || true
	echo "$output" | grep -q " ${PN532_ADDR_7BIT} "
}

# Find bus with PN532
find_pn532_bus() {
	local bus_path="${1:-}"
	if [ -n "$bus_path" ]; then
		local num
		num=$(bus_num "$bus_path")
		if bus_has_pn532 "$num"; then
			echo "$bus_path"
			return 0
		fi
		echo ""
		return 1
	fi

	for dev in /dev/i2c-*; do
		[ -e "$dev" ] || continue
		local num
		num=$(bus_num "$dev")
		if bus_has_pn532 "$num"; then
			echo "$dev"
			return 0
		fi
	done
	echo ""
	return 1
}

echo "Step 1: Scanning for PN532 on I2C buses..."
BUS=$(find_pn532_bus "${1:-}") || true

if [ -z "$BUS" ]; then
	echo "FAIL: No device found at address ${PN532_ADDR_HEX} on any I2C bus."
	echo ""
	echo "Troubleshooting:"
	echo "  - Check wiring (SDA, SCL, VCC, GND)"
	echo "  - Verify I2C is enabled: raspi-config -> Interface Options -> I2C"
	echo "  - Check permissions: ls -la /dev/i2c-*"
	echo "  - Run: i2cdetect -y 1"
	exit 1
fi

BUS_NUM=$(bus_num "$BUS")
echo "PASS: Found PN532 at ${BUS}:${PN532_ADDR_HEX}"
echo ""

echo "Step 2: Full i2cdetect output for bus ${BUS_NUM}:"
i2cdetect -y "$BUS_NUM"
echo ""

echo "Step 3: Building cmd/reader..."
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
make -C "$REPO_ROOT" reader
echo "PASS: Build successful"
echo ""

READER="${REPO_ROOT}/cmd/reader/reader"
DEVICE_PATH="${BUS}:${PN532_ADDR_HEX}"

echo "Step 4: Running diagnostics (firmware, self-test, RF field)..."
echo "Device path: ${DEVICE_PATH}"
echo ""

if timeout 15 "$READER" --device "$DEVICE_PATH" --debug 2>&1; then
	echo ""
	echo "PASS: Reader exited normally"
else
	rc=$?
	if [ "$rc" -eq 124 ]; then
		echo ""
		echo "PASS: Reader ran for 15s without error (timed out as expected)"
	else
		echo ""
		echo "FAIL: Reader exited with code $rc"
		exit 1
	fi
fi

echo ""
echo "===================="
echo "Validation complete."
echo ""
echo "Next steps:"
echo "  - Place an NFC tag near the reader and run:"
echo "    ${READER} --device ${DEVICE_PATH} --debug"
echo "  - To write NDEF text:"
echo "    ${READER} --device ${DEVICE_PATH} --write \"Hello\""
echo "  - To run stress test:"
echo "    ${READER} --device ${DEVICE_PATH} --test"
