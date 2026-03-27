#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <DHT.h>
#include <IRremote.hpp>
#include <SPI.h>
#include <MFRC522.h>
#include <Servo.h>

#define DHTPIN 2
#define DHTTYPE DHT11
#define IR_PIN 4

#define SCREEN_MAIN 0
#define SCREEN_AUDIT 1
#define SCREEN_TEMP 2
#define SCREEN_TEMP_AUDIT 3

#define IDLE_TIMEOUT 10000

#define SS_PIN 10
#define RST_PIN 9

#define SERVO_PIN 3

// ========== BINARY PROTOCOL DEFINITIONS ==========
#define HEADER 0xAA
#define MAX_PAYLOAD 128

// Packet types (Server → Arduino)
#define TYPE_GRANT 0x01
#define TYPE_DENY 0x02
#define TYPE_AUDIT_DATA 0x03
#define TYPE_AUDIT_TEMP_DATA 0x04

// Packet types (Arduino → Server)
#define TYPE_UID 0x10
#define TYPE_TEMP 0x11
#define TYPE_AUDIT_ENTRY_REQ 0x12
#define TYPE_AUDIT_TEMP_REQ 0x13

// Binary packet buffer (shared RX/TX)
uint8_t buffer[MAX_PAYLOAD];

LiquidCrystal_I2C lcd(0x27, 16, 2);
DHT dht(DHTPIN, DHTTYPE);
MFRC522 mfrc522(SS_PIN, RST_PIN);
Servo doorServo;
unsigned long lastUpdate = 0;
unsigned long servoOpenTime = 0;
unsigned long lastActivity = 0;
uint8_t currentScreen = SCREEN_MAIN;
float tempLog[4];
uint8_t tempLogIndex = 0;
unsigned long lastTempLog = 0;
float currentTemp = 0;

String auditEntries[4];
int auditEntryCount = 0;
int auditEntryIndex = 0;
unsigned long auditScreenStart = 0;

String tempEntries[4];
int tempEntryCount = 0;
int tempEntryIndex = 0;
unsigned long tempAuditStart = 0;

void showMainScreen();
void updateMainScreen();
void displayAuditEntry();
void displayTempAuditEntry();

// ========== BINARY PROTOCOL FUNCTIONS ==========

// Send binary packet: [HEADER][TYPE][LEN][DATA...]
void sendPacket(uint8_t packetType, const uint8_t* payload, uint8_t len) {
  if (len > MAX_PAYLOAD) {
    return;
  }

  Serial.write(HEADER);
  Serial.write(packetType);
  Serial.write(len);

  if (len > 0) {
    Serial.write(payload, len);
  }

  Serial.flush();
}

// Send binary packet with string payload
void sendPacketString(uint8_t packetType, const String& data) {
  uint8_t len = min((uint8_t)data.length(), MAX_PAYLOAD - 1);
  for (uint8_t i = 0; i < len; i++) {
    buffer[i] = (uint8_t)data[i];
  }
  sendPacket(packetType, buffer, len);
}

// Send temperature as string in binary packet
void sendPacketTemp(float temp) {
  String tempStr = String(temp);
  sendPacketString(TYPE_TEMP, tempStr);
}

// Send UID to server
void sendUID(const String& uid) {
  sendPacketString(TYPE_UID, uid);
}

// Request audit entries from server
void sendAuditEntryRequest() {
  sendPacket(TYPE_AUDIT_ENTRY_REQ, nullptr, 0);
}

// Request temperature audit from server
void sendAuditTempRequest() {
  sendPacket(TYPE_AUDIT_TEMP_REQ, nullptr, 0);
}

// Send acknowledgment packet to server
void sendAck(uint8_t forType) {
  uint8_t ackData[1] = {forType};
  sendPacket(0xFE, ackData, 1);  // 0xFE = ACK
}

// Parse and handle incoming binary packet from server
void handleBinaryPacket() {
  if (Serial.available() < 3) {
    return;
  }

  // Peek at first byte to verify it's a header
  uint8_t header = Serial.peek();
  if (header != HEADER) {
    // Skip this byte if not header
    Serial.read();
    return;
  }

  // Read header
  Serial.read();
  
  uint8_t packetType = Serial.read();
  uint8_t payloadLen = Serial.read();

  if (payloadLen > MAX_PAYLOAD) {
    return;
  }

  // Wait for payload with timeout
  unsigned long startTime = millis();
  uint8_t bytesRead = 0;

  while (bytesRead < payloadLen) {
    if (millis() - startTime > 1000) {
      return;
    }
    if (Serial.available() > 0) {
      buffer[bytesRead++] = Serial.read();
    }
  }

  // Handle packet by type
  switch (packetType) {
    case TYPE_GRANT:
      handleGrant(payloadLen);
      break;
    case TYPE_DENY:
      handleDeny();
      break;
    case TYPE_AUDIT_DATA:
      handleAuditData(payloadLen);
      sendAck(TYPE_AUDIT_DATA);
      break;
    case TYPE_AUDIT_TEMP_DATA:
      handleAuditTempData(payloadLen);
      sendAck(TYPE_AUDIT_TEMP_DATA);
      break;
    default:
      break;
  }
}

// Handle GRANT packet: extract username and show on LCD
void handleGrant(uint8_t payloadLen) {
  String name = "";
  for (uint8_t i = 0; i < payloadLen && i < 16; i++) {
    name += (char)buffer[i];
  }

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ACCESS GRANTED");
  lcd.setCursor(0, 1);
  lcd.print(name);

  doorServo.write(90);
  servoOpenTime = millis();
  delay(2000);
  currentScreen = SCREEN_MAIN;
  showMainScreen();
}

// Handle DENY packet
void handleDeny() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ACCESS DENIED");
  lcd.setCursor(0, 1);
  lcd.print("No access");
  delay(2000);
  currentScreen = SCREEN_MAIN;
  showMainScreen();
}

// Parse audit data packet
// Format: [len1][entry1][len2][entry2]...
void handleAuditData(uint8_t payloadLen) {
  auditEntryCount = 0;
  auditEntryIndex = 0;

  for (int i = 0; i < 4; i++) {
    auditEntries[i] = "";
  }

  uint8_t pos = 0;
  while (pos < payloadLen && auditEntryCount < 4) {
    uint8_t entryLen = buffer[pos++];

    if (pos + entryLen > payloadLen) {
      break;
    }

    String entry = "";
    for (uint8_t i = 0; i < entryLen; i++) {
      entry += (char)buffer[pos++];
    }

    auditEntries[auditEntryCount++] = entry;
  }

  // Always switch to audit screen when data arrives
  currentScreen = SCREEN_AUDIT;
  auditEntryIndex = 0;
  auditScreenStart = millis();
  displayAuditEntry();
}

// Parse temperature audit data packet
// Format: [len1][entry1][len2][entry2]...
void handleAuditTempData(uint8_t payloadLen) {
  tempEntryCount = 0;
  tempEntryIndex = 0;

  for (int i = 0; i < 4; i++) {
    tempEntries[i] = "";
  }

  uint8_t pos = 0;
  while (pos < payloadLen && tempEntryCount < 4) {
    uint8_t entryLen = buffer[pos++];

    if (pos + entryLen > payloadLen) {
      break;
    }

    String entry = "";
    for (uint8_t i = 0; i < entryLen; i++) {
      entry += (char)buffer[pos++];
    }

    tempEntries[tempEntryCount++] = entry;
  }

  // Always switch to temp audit screen when data arrives
  currentScreen = SCREEN_TEMP_AUDIT;
  tempEntryIndex = 0;
  tempAuditStart = millis();
  displayTempAuditEntry();
}

// ========== SETUP & LOOP ==========

void setup() {
  Serial.begin(9600);
  lcd.init();
  lcd.backlight();
  dht.begin();
  IrReceiver.begin(IR_PIN, ENABLE_LED_FEEDBACK);
  SPI.begin();
  mfrc522.PCD_Init();
  doorServo.attach(SERVO_PIN);
  doorServo.write(0);
  lastActivity = millis();
  showMainScreen();
}

void loop() {
  // Check RFID card
  if (mfrc522.PICC_IsNewCardPresent()) {
    if (mfrc522.PICC_ReadCardSerial()) {
      String uid = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (mfrc522.uid.uidByte[i] < 0x10) uid += "0";
        uid += String(mfrc522.uid.uidByte[i], HEX);
      }
      uid.toUpperCase();
      sendUID(uid);
      lcd.clear();
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
    }
  }

  // Handle incoming binary packets from server
  handleBinaryPacket();

  // Servo close after timeout
  if (millis() - servoOpenTime > 3000 && doorServo.read() > 45) {
    doorServo.write(0);
  }

  // Update temperature every 2 seconds
  if (millis() - lastUpdate > 2000) {
    lastUpdate = millis();
    currentTemp = dht.readTemperature();
    sendPacketTemp(currentTemp);

    if (millis() - lastTempLog > 30000) {
      lastTempLog = millis();
      if (!isnan(currentTemp)) {
        tempLog[tempLogIndex] = currentTemp;
        tempLogIndex = (tempLogIndex + 1) % 10;
      }
    }

    if (currentScreen == SCREEN_MAIN) {
      updateMainScreen();
    }
  }

  // Return to main screen on idle
  if (currentScreen != SCREEN_MAIN && millis() - lastActivity > IDLE_TIMEOUT) {
    currentScreen = SCREEN_MAIN;
    showMainScreen();
  }

  // Auto-exit audit screens
  if (currentScreen == SCREEN_AUDIT && millis() - auditScreenStart > 5000) {
    currentScreen = SCREEN_MAIN;
    showMainScreen();
  }

  if (currentScreen == SCREEN_TEMP_AUDIT && millis() - tempAuditStart > 5000) {
    currentScreen = SCREEN_MAIN;
    showMainScreen();
  }

  // Handle IR remote
  if (IrReceiver.decode()) {
    uint32_t code = IrReceiver.decodedIRData.command;
    lastActivity = millis();

    if (code == 0x16) {
      // Button 4: Request audit
      currentScreen = SCREEN_AUDIT;
      auditEntryIndex = 0;
      auditScreenStart = millis();
      sendAuditEntryRequest();
      displayAuditEntry();
    }
    else if (code == 0x18) {
      // Button 6: Request temperature audit
      currentScreen = SCREEN_TEMP_AUDIT;
      tempEntryIndex = 0;
      tempAuditStart = millis();
      sendAuditTempRequest();
      displayTempAuditEntry();
    }
    else if (code == 0x7 && (currentScreen == SCREEN_AUDIT || currentScreen == SCREEN_TEMP_AUDIT)) {
      // Button UP: Previous entry
      if (currentScreen == SCREEN_AUDIT) {
        if (auditEntryCount > 0) {
          auditEntryIndex = (auditEntryIndex - 1 + auditEntryCount) % auditEntryCount;
          auditScreenStart = millis();
          displayAuditEntry();
        }
      } else {
        if (tempEntryCount > 0) {
          tempEntryIndex = (tempEntryIndex - 1 + tempEntryCount) % tempEntryCount;
          tempAuditStart = millis();
          displayTempAuditEntry();
        }
      }
    }
    else if (code == 0x15 && (currentScreen == SCREEN_AUDIT || currentScreen == SCREEN_TEMP_AUDIT)) {
      // Button DOWN: Next entry
      if (currentScreen == SCREEN_AUDIT) {
        if (auditEntryCount > 0) {
          auditEntryIndex = (auditEntryIndex + 1) % auditEntryCount;
          auditScreenStart = millis();
          displayAuditEntry();
        }
      } else {
        if (tempEntryCount > 0) {
          tempEntryIndex = (tempEntryIndex + 1) % tempEntryCount;
          tempAuditStart = millis();
          displayTempAuditEntry();
        }
      }
    }

    IrReceiver.resume();
  }
}

// ========== LCD DISPLAY FUNCTIONS ==========

void showMainScreen() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("SMART DUMB HOUSE");
  updateMainScreen();
}

void updateMainScreen() {
  lcd.setCursor(0, 1);
  lcd.print("Temp: ");
  if (isnan(currentTemp)) {
    lcd.print("Error   ");
  } else {
    lcd.print(currentTemp);
    lcd.print("C   ");
  }
}

void displayAuditEntry() {
  lcd.clear();
  if (auditEntryCount == 0) {
    lcd.setCursor(0, 0);
    lcd.print("No audit data");
    return;
  }

  String entry = auditEntries[auditEntryIndex];
  if (entry.length() == 0) {
    lcd.setCursor(0, 0);
    lcd.print("No audit data");
    return;
  }

  int commaIdx = entry.indexOf(',');
  if (commaIdx == -1) {
    lcd.setCursor(0, 0);
    lcd.print("Parse error");
    return;
  }

  lcd.setCursor(0, 0);
  lcd.print(entry.substring(0, min(commaIdx, 16)));

  lcd.setCursor(0, 1);
  String datetime = entry.substring(commaIdx + 1);
  if (datetime.length() >= 19) {
    lcd.print(datetime.substring(11, 19));
  } else {
    lcd.print(datetime);
  }
}

void displayTempAuditEntry() {
  lcd.clear();
  if (tempEntryCount == 0) {
    lcd.setCursor(0, 0);
    lcd.print("No temp data");
    return;
  }

  String entry = tempEntries[tempEntryIndex];

  if (entry.length() == 0) {
    lcd.setCursor(0, 0);
    lcd.print("No temp data");
    return;
  }

  int commaIdx = entry.indexOf(',');
  if (commaIdx == -1) {
    lcd.setCursor(0, 0);
    lcd.print("Parse error");
    return;
  }

  lcd.setCursor(0, 0);
  lcd.print(entry.substring(0, min(commaIdx, 16)));

  lcd.setCursor(0, 1);
  String datetime = entry.substring(commaIdx + 1);
  if (datetime.length() >= 19) {
    lcd.print(datetime.substring(11, 19));
  } else {
    lcd.print(datetime);
  }
}
