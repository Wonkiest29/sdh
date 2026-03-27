# Smart Dumb House

**Smart Dumb House** is an access control and microclimate monitoring system based on Arduino and Python.

The system uses RFID tags for user authorization, a temperature sensor for climate monitoring, a servo motor to mimic a door lock, and an LCD screen to display the system's status. All data is logged into a local SQLite database on the server side (Python). An IR remote control is used to navigate the screens and view logs.

---

## 🛠 Hardware
- **Arduino** (Uno/Nano/Mega)
- **MFRC522** — RFID module for reading access cards.
- **DHT11** — Temperature and humidity sensor.
- **IR Receiver** — Infrared receiver for the remote control.
- **Servo Motor** — Door lock simulator (opens upon successful authorization).
- **LCD 16x2 (I2C)** — Display for information output.

## 💻 Software Stack
- **Server**: Python 3, `pyserial` library.
- **Database**: SQLite3 (`access_control.db` with tables: `users`, `entrylog`, `temp_logs`).
- **Microcontroller**: C++ (Arduino IDE) using libraries: `LiquidCrystal_I2C`, `DHT`, `IRremote`, `SPI`, `MFRC522`, `Servo`.

---

## 🎮 IR Remote Control
The system can be controlled via an IR remote:
- **Button 4** (code `0x16`): Request recent entry logs (Audit Entry).
- **Button 6** (code `0x18`): Request recent temperature logs (Audit Temp).
- **UP Button** (`0x07`): Scroll logs backward (previous entry).
- **DOWN Button** (`0x15`): Scroll logs forward (next entry).

The system automatically returns to the main screen after a period of inactivity (idle timeout).

### 📦 Packet Structure
All packets follow this exact format:
```text
┌────────┬──────────┬─────────┬─────────────┐
│ HEADER │   TYPE   │  LEN    │    DATA     │
│ 0xAA   │ 1 byte   │ 1 byte  │ 0-128 bytes │
└────────┴──────────┴─────────┴─────────────┘
```
- **HEADER**: Always `0xAA` (170). Used for stream synchronization.
- **TYPE**: Command type (see below).
- **LENGTH**: Length of the `PAYLOAD` in bytes (0-255). The Arduino array buffer is limited to 128 bytes.

### 🗂 Packet Types

**Arduino → Server (Requests):**
| Type | Code | Payload | Description |
|------|------|---------|-------------|
| UID | `0x10` | UID (hex string) | RFID card read |
| TEMP | `0x11` | Temperature (string)| Current temperature |
| AUDIT_ENTRY_REQ | `0x12` | (empty) | Request entry logs |
| AUDIT_TEMP_REQ | `0x13` | (empty) | Request temperature log |
| ACK | `0xFE` | 1 byte | Acknowledge receipt of a heavy packet |

**Server → Arduino (Responses):**
| Type | Code | Payload | Description |
|------|------|---------|-------------|
| GRANT | `0x01` | Username (string) | Access granted + open door |
| DENY | `0x02` | (empty) | Access denied |
| AUDIT_DATA | `0x03` | `[len][entry]...` | Entry log data (up to 4 records) |
| AUDIT_TEMP_DATA | `0x04` | `[len][entry]...` | Temperature log data (up to 4 records) |

### 💡 Protocol Examples

**Example 1: GRANT Response**
```text
Bytes: [0xAA] [0x01] [0x04] [J] [o] [h] [n]
       ^^^^^^  ^^^^   ^^^^   ^^^^^^^^^^^^^^^^^
       Header  Type   Len    Payload: "John"
```

**Example 2: AUDIT_DATA Response (Multiple Entries)**
Payload Format: `[entry_len][entry_data][entry_len][entry_data]...`
```text
Raw bytes:
[0xAA] [0x03] [0x28]
[14] [John,12:34:56] [15] [Jane,11:22:33] [13] [Bob,10:11:12]

Decoded:
- Entry 1: "John,12:34:56" (14 bytes)
- Entry 2: "Jane,11:22:33" (15 bytes)  
- Entry 3: "Bob,10:11:12" (13 bytes)
```
