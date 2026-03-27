import logging
import re
import sqlite3
import time
from datetime import datetime

import serial

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

logger.info("=" * 50)
logger.info("Starting program")
logger.info("=" * 50)

try:
    ser = serial.Serial("/dev/cu.usbmodem11101", 9600, timeout=1)
    logger.info(f"Serial port opened: {ser.port} (speed: {ser.baudrate})")
except Exception as e:
    logger.error(f"Error opening Serial port: {e}")
    exit(1)

time.sleep(2)
logger.info("Pause 2 sec for Arduino initialization")

try:
    conn = sqlite3.connect("access_control.db")
    cur = conn.cursor()
    logger.info("Database connected: access_control.db")
except Exception as e:
    logger.error(f"Error connecting to database: {e}")
    exit(1)

cur.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfid_id TEXT UNIQUE,
    name TEXT)""")

cur.execute("""CREATE TABLE IF NOT EXISTS entrylog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datetime TEXT DEFAULT (datetime('now','localtime')),
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id))""")

cur.execute("""CREATE TABLE IF NOT EXISTS temp_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    temperature REAL,
    log_time TEXT DEFAULT (datetime('now','localtime')))""")

conn.commit()
logger.info("Tables initialized")

# ========== BINARY PROTOCOL DEFINITIONS ==========
HEADER = 0xAA

# Packet types (Arduino → Server)
TYPE_UID = 0x10
TYPE_TEMP = 0x11
TYPE_AUDIT_ENTRY_REQ = 0x12
TYPE_AUDIT_TEMP_REQ = 0x13
TYPE_ACK = 0xFE

# Packet types (Server → Arduino)
TYPE_GRANT = 0x01
TYPE_DENY = 0x02
TYPE_AUDIT_DATA = 0x03
TYPE_AUDIT_TEMP_DATA = 0x04

MAX_PAYLOAD = 255


def send_packet(packet_type, payload_bytes):
    """Send binary packet: [HEADER][TYPE][LEN][DATA...]"""
    try:
        length = len(payload_bytes)
        if length > MAX_PAYLOAD:
            logger.error(f"Payload too large: {length} > {MAX_PAYLOAD}")
            return False

        # Clear input buffer before sending to avoid sync issues
        while ser.in_waiting > 0:
            ser.read(1)
        time.sleep(0.05)

        packet = bytes([HEADER, packet_type, length]) + payload_bytes
        ser.write(packet)
        ser.flush()
        logger.info(
            f"SENT BIN: type=0x{packet_type:02X}, len={length}, data={payload_bytes[:32]}"
        )

        # Give Arduino time to process
        time.sleep(0.1)
        return True
    except Exception as e:
        logger.error(f"Send error: {e}")
        return False


def handle_uid(uid):
    """Process RFID - send GRANT or DENY packet"""
    logger.info(f"Received UID: {uid}")
    cur.execute("SELECT id, name FROM users WHERE rfid_id=?", (uid,))
    row = cur.fetchone()
    if row:
        user_id, name = row
        payload = name.encode()
        send_packet(TYPE_GRANT, payload)
        logger.info(f"Access granted for: {name}")
        cur.execute("INSERT INTO entrylog (user_id) VALUES (?)", (user_id,))
    else:
        send_packet(TYPE_DENY, b"")
        logger.warning(f"Access DENIED for UID: {uid}")
    conn.commit()


def handle_temp(temp):
    """Process temperature"""
    logger.debug(f"Received temperature: {temp}C")
    cur.execute("INSERT INTO temp_logs (temperature) VALUES (?)", (temp,))
    conn.commit()
    logger.debug(f"Temperature {temp}C logged to database")


def handle_audit_entry():
    """Process audit entry request - send binary AUDIT_DATA packet"""
    logger.info("AUDIT_ENTRY request received")
    cur.execute("""SELECT users.name, entrylog.datetime
                   FROM entrylog
                   JOIN users ON entrylog.user_id = users.id
                   ORDER BY entrylog.id DESC
                   LIMIT 4""")
    rows = cur.fetchall()

    if rows:
        payload = b""
        for i, (name, timedate) in enumerate(rows):
            entry = f"{name},{timedate}".encode()
            entry_len = len(entry)
            if entry_len > 255:
                logger.warning(f"Entry too long, truncating: {entry_len}")
                entry = entry[:255]
                entry_len = 255
            logger.debug(f"Audit entry {i}: len={entry_len}, data={entry}")
            payload += bytes([entry_len]) + entry

        logger.info(
            f"Sending AUDIT_DATA packet: {len(rows)} entries, total {len(payload)} bytes"
        )
        send_packet(TYPE_AUDIT_DATA, payload)
        logger.info(f"Sent {len(rows)} audit records to Arduino")
    else:
        logger.warning("No audit data to send")
        send_packet(TYPE_AUDIT_DATA, b"")


def handle_audit_temp():
    """Process temperature audit request - send binary AUDIT_TEMP_DATA packet"""
    logger.info("AUDIT_TEMP request received")
    cur.execute("""SELECT temperature, log_time
                   FROM temp_logs
                   ORDER BY id DESC
                   LIMIT 12""")
    rows = cur.fetchall()

    if rows:
        deduped = []
        last_temp = None
        for temp, ttime in rows:
            try:
                ftemp = float(temp)
            except Exception:
                ftemp = temp
            if last_temp is None or ftemp != last_temp:
                deduped.append((temp, ttime))
                last_temp = ftemp

        selected = deduped[:4]
        payload = b""
        for i, (temp, ttime) in enumerate(selected):
            entry = f"{temp},{ttime}".encode()
            entry_len = len(entry)
            if entry_len > 255:
                logger.warning(f"Entry too long, truncating: {entry_len}")
                entry = entry[:255]
                entry_len = 255
            logger.debug(f"Temp entry {i}: len={entry_len}, data={entry}")
            payload += bytes([entry_len]) + entry

        logger.info(
            f"Sending AUDIT_TEMP_DATA packet: {len(selected)} entries, total {len(payload)} bytes"
        )
        send_packet(TYPE_AUDIT_TEMP_DATA, payload)
        logger.info(f"Sent {len(selected)} temperature records to Arduino")
    else:
        logger.warning("No temperature data to send")
        send_packet(TYPE_AUDIT_TEMP_DATA, b"")


def parse_binary_packet():
    """Parse incoming binary packet from Arduino"""
    if ser.in_waiting < 3:
        return None

    # Read header
    header = ser.read(1)
    if not header or header[0] != HEADER:
        logger.debug(
            f"Invalid header byte: 0x{header[0]:02X} (expected 0x{HEADER:02X})"
        )
        return None

    # Read type and length
    packet_type = ser.read(1)
    packet_len = ser.read(1)

    if not packet_type or not packet_len:
        logger.debug("Failed to read type or length")
        return None

    ptype = packet_type[0]
    plen = packet_len[0]

    logger.debug(f"Binary packet header: type=0x{ptype:02X}, len={plen}")

    if plen > MAX_PAYLOAD:
        logger.error(f"Packet length invalid: {plen}")
        return None

    # Wait for payload with timeout
    start_time = time.time()
    while ser.in_waiting < plen:
        if time.time() - start_time > 1.0:  # 1 second timeout
            logger.warning(
                f"Timeout waiting for payload: have {ser.in_waiting}, need {plen}"
            )
            return None
        time.sleep(0.001)

    # Read payload
    if plen > 0:
        payload = ser.read(plen)
    else:
        payload = b""

    logger.info(f"RECV BIN: type=0x{ptype:02X}, len={plen}, data={payload[:32]}")
    return (ptype, payload)


def handle_uid_binary(payload):
    """Handle UID packet from Arduino"""
    uid = payload.decode().strip()
    logger.info(f"Received UID: {uid}")
    handle_uid(uid)


def handle_temp_binary(payload):
    """Handle temperature packet from Arduino"""
    if len(payload) < 4:
        logger.error("Temperature packet too short")
        return

    try:
        # Assuming float (4 bytes) in big-endian or text format
        temp_str = payload.decode().strip()
        temp = float(temp_str)
        handle_temp(temp)
    except Exception as e:
        logger.error(f"Error parsing temperature binary packet: {e}")


def handle_audit_entry_req_binary():
    """Handle audit entry request packet"""
    logger.info("AUDIT_ENTRY request received (binary)")
    handle_audit_entry()


def handle_audit_temp_req_binary():
    """Handle audit temperature request packet"""
    logger.info("AUDIT_TEMP request received (binary)")
    handle_audit_temp()


# Main loop
logger.info("=" * 50)
logger.info("Main loop started, waiting for binary commands...")
logger.info("=" * 50)

try:
    while True:
        try:
            # Try to parse binary packet first
            packet = parse_binary_packet()

            if packet:
                ptype, payload = packet

                if ptype == TYPE_UID:
                    handle_uid_binary(payload)
                elif ptype == TYPE_TEMP:
                    handle_temp_binary(payload)
                elif ptype == TYPE_AUDIT_ENTRY_REQ:
                    handle_audit_entry_req_binary()
                elif ptype == TYPE_AUDIT_TEMP_REQ:
                    handle_audit_temp_req_binary()
                elif ptype == TYPE_ACK:
                    ack_type = payload[0] if payload else 0xFF
                    logger.info(f"ACK received for type=0x{ack_type:02X}")
                else:
                    logger.warning(f"Unknown packet type: 0x{ptype:02X}")
            else:
                # Fallback: try to read legacy string-based commands for compatibility
                if ser.in_waiting > 0:
                    try:
                        # Read first byte to check if it's binary
                        first_byte = ser.read(1)
                        if not first_byte:
                            time.sleep(0.01)
                            continue

                        # If it's a binary header, skip it (incomplete packet)
                        if first_byte[0] == HEADER:
                            logger.debug("Skipped incomplete binary packet")
                            continue

                        # Try to read rest of line as text
                        try:
                            rest = ser.readline()
                            line = (first_byte + rest).decode().strip()
                        except UnicodeDecodeError:
                            logger.debug("Skipped corrupted/binary data")
                            continue

                        if not line:
                            time.sleep(0.01)
                            continue

                        if line.startswith("TEMP:"):
                            logger.debug(f"RECEIVED (legacy): {line}")
                        else:
                            logger.info(f"RECEIVED (legacy): {line}")

                        if line.startswith("UID:"):
                            uid = line[4:]
                            handle_uid(uid)
                        elif line.startswith("TEMP:"):
                            temp_part = line[5:].strip()
                            if temp_part.endswith("C") or temp_part.endswith("c"):
                                temp_part = temp_part[:-1].strip()
                            cleaned = "".join(
                                ch for ch in temp_part if ch in "0123456789.-"
                            )
                            m = re.search(r"-?\d+\.?\d*", cleaned)
                            if m:
                                try:
                                    temp = float(m.group(0))
                                    handle_temp(temp)
                                except ValueError:
                                    logger.error(
                                        f"Error parsing temperature: {temp_part}"
                                    )
                        elif line.startswith("AUDIT_ENTRY"):
                            handle_audit_entry()
                        elif line.startswith("AUDIT_TEMP"):
                            handle_audit_temp()
                        elif line.startswith("IR code:"):
                            logger.debug(f"IR code: {line}")
                        elif line.startswith("Parsed"):
                            logger.debug(f"Arduino: {line}")
                        else:
                            logger.debug(f"Unknown command: {line}")
                    except Exception as e:
                        logger.debug(
                            f"Fallback parsing error (skipped): {type(e).__name__}"
                        )
                else:
                    time.sleep(0.01)

        except Exception as e:
            logger.error(f"Processing error: {e}")

        time.sleep(0.01)

except KeyboardInterrupt:
    logger.info("\n" + "=" * 50)
    logger.info("Stopping program (Ctrl+C)")
    logger.info("=" * 50)
except Exception as e:
    logger.critical(f"Critical error: {e}")
finally:
    if ser.is_open:
        ser.close()
        logger.info("Serial port closed")
    if conn:
        conn.close()
        logger.info("Database connection closed")
    logger.info("Program finished")
