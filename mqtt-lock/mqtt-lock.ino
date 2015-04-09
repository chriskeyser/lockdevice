/******************************************************************************
The implementation is part of an example that simulates a system operating a lock
for a home.  A bootstrap process over a local network sets an MQTT server to 
access and an cryptographic key to use for signing and encryption operations.

It uses the following libraries:
** PubSlubClient - http://knolleary.net/arduino-client-for-mqtt/api/#subscribe used
 for mqtt.  Updated to increase max message size to 255. Added method to set 
 mqtt server/port after reading configuration.  (note: failed to initialize 
 properly with mqtt server when allocated with new operation).  Increased max message size.

** ArduinoJson - https://github.com/bblanchon/ArduinoJson/.  Used for parsing JSON.
Sent json is simple, so formed directly in strings to reduce overhead.

** AES - http://utter.chaos.org.uk/~markt/AES-library.zip.  Minor fixes for prog space that
did compile properly on 1.6.1.

** SHA256: https://github.com/Cathedrow/Cryptosuite.  Minor fixes for compile time errors with
1.6.1 and Print overloads, as well as prog memory compile errors.

*******************************************************************************/

#include <AES.h>
#include <SPI.h>
#include <Ethernet.h>
#include <EEPROM.h>
#include <EthernetUdp.h>
#define UDP_TX_PACKET_MAX_SIZE 144
#include <PubSubClient.h>
#include <sha256.h>
#include <avr/pgmspace.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ArduinoJson.h>

// Values for tracking state of device.
#define STATE_INIT 1
#define STATE_ASSIGNING 2
#define STATE_INITIALIZE_CONFIG 3
#define STATE_TESTING_CONFIG 4
#define STATE_CONNECTING 5
#define STATE_RUNNING 6

// the ports that the initialization protocol will use.
#define BCAST_PORT 9998
#define INIT_SEND 9997

// max ip lengths.
#define MAX_IP_STR_LEN    16

//encryption defines.  SAMPLE_PIN is an unconnected analog pin for random init...
#define SHA256_LENGTH     32
#define KEY_LENGTH        16
#define KEY_BITS          128
#define SAMPLE_PIN        15      
#define MAX_ENCRYPT_DATA_SIZE  (10*N_BLOCK)-1
#define TOTAL_ENCRYPT_SZ  11*N_BLOCK
#define ENCRYPT
#define START_ENCRYPT_DATA 24
#define MAX_ENCRYPT_MSG   START_ENCRYPT_DATA + TOTAL_ENCRYPT_SZ
#define MAX_TOTAL_MSG     MAX_ENCRYPT_MSG + SHA256_LENGTH
#define EIV

// EEPROM locations
#define CONFIG_LENGTH     100
#define START_CONFIG      500
#define MQTT_PORT_START   500
#define KEY_START         MQTT_PORT_START + sizeof(unsigned int) + 1
#define MQTT_SRV_START    KEY_START + KEY_LENGTH + 1
#define MQTT_PORT_MAX     sizeof(unsigned int)
#define MQTT_SRV_MAX      CONFIG_LENGTH - (MQTT_SRV_START-START_CONFIG) 
#define END_CONFIG        START_CONFIG + CONFIG_LENGTH
#define MAX_BUF_WRITE     254

#define MQTT_LAST_TIMESTAMP END_CONFIG + 1

// shared buffers to use.
char g_rcvPacketBuffer[UDP_TX_PACKET_MAX_SIZE+1];
char g_txPacketBuffer[UDP_TX_PACKET_MAX_SIZE+1];

// This would normally need to be read from a board setting rather than hardcoding.
byte g_mac[] = {
  0x00, 0xAA, 0xBB, 0xCC, 0x1E, 0x02
};

// global variables.
IPAddress g_myIp;
IPAddress g_configAgentIp;
byte g_mqttServerIp[4];
char g_mqttServerDNS[MQTT_SRV_MAX+1];
uint16_t g_mqttPort;
uint32_t g_lastMsgSequence;
byte g_currentState=STATE_INIT;
bool g_debug = true;

// encryption and signing globals
AES g_aes;

byte g_aesKey[KEY_LENGTH];
byte g_cipherBuf[MAX_TOTAL_MSG];
byte g_plainTextBuf[MAX_TOTAL_MSG];

// Callback function header
void mqttCallback(char* topic, byte* payload, unsigned int length);

// various clients to use in processing...
EthernetClient g_ethClient;
EthernetUDP g_Udp;

// initialization constants
const char initSig[] = "LINIT";
const char initReplySig[] = "LRPLY";
const char resetSig[] =  "RST";
const char successMsg[] = "success";
char g_lockId[] = "lock-00AABBCC1E02"; // typically would be read from register

// positions for fixed init msg
// size of signature + state + port + encryption key + string for domain or ip.
// take off one as we don't include terminating char.
#define SIGLEN                    sizeof(initSig) - 1
#define MIN_INIT_PACKET           SIGLEN + sizeof(byte) + sizeof(unsigned int) + KEY_LENGTH + 6
#define INIT_PACKET_PORT_INDEX    SIGLEN + sizeof(byte)
#define INIT_PACKET_COUNTER_INDEX INIT_PACKET_PORT_INDEX + sizeof(uint16_t)
#define INIT_PACKET_KEY_INDEX     INIT_PACKET_COUNTER_INDEX + sizeof(uint32_t)
#define INIT_PACKET_SERVER_INDEX  INIT_PACKET_KEY_INDEX + KEY_LENGTH

// IP addresses
byte g_server[] = { 0, 0, 0, 0 }; 
IPAddress g_myip(0, 0, 0, 0);

// MQTT defines
#define LOCK_CHALLENGE 1
#define LOCK_RESPONSE 2
#define LOCK_OPERATION 3
#define JSON_5_ATTRIBUTES   JSON_OBJECT_SIZE(5)

char controlTopic[] = "lockctl";
PubSubClient mqttClient(g_server, 1883, mqttCallback, g_ethClient);

//JSON processing

/**** End Declarations ************/

/************
* Functions for writing debug information out serial port.
*/
char *ipToStr(const IPAddress addr, char *target, const int maxlen) {
  if(addr != NULL) {
    snprintf(target, maxlen, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
  } else {
    *target = 0;
  }

  return target;
}

void printIP(const IPAddress addr) {
  if(g_debug) {
    char ipStr[24]; 
    Serial.print(ipToStr(addr, ipStr, 24));
  }
}

void logMessage(const char *msg) {
  if(g_debug) {Serial.println(msg);}
}

void logIntValue(const char *msg, const int value) {
  if(g_debug) {
    Serial.print(msg);
    Serial.println(value);
  }
}

void logStrValue(const char *msg, const char *value) {
  if(g_debug) {
    Serial.print(msg);
    Serial.println(value);
  }
}

void logBuffer(const char *title, const void *data, const int bufLength) {
  if(g_debug) {
    Serial.print(title);
    Serial.print("size:");
    Serial.print(bufLength);
    Serial.print(" data:");
    byte *bytes = (byte *) data;
    
    for(int i = 0; i < bufLength; i++) {
      Serial.print(bytes[i]);
      Serial.print(" ");
    }
    Serial.println();
  }
}

void logPacket(const int packetSize, const IPAddress addr, const int port, const char * data)
{
  if(g_debug) {
    char ipaddrStr[24];

    Serial.print("g_Udp rcv: ");
    Serial.print(packetSize);
    Serial.print( " bytes from: ");
    Serial.print(ipToStr(addr, ipaddrStr, 24));
    Serial.print(":");
    Serial.print(port);
    logBuffer("data", data, packetSize);
  }
}

/************
* Functions for working with network interactions.
*/
bool getDhcpAddr() {
  char ipaddrStr[24];

  if(Ethernet.begin(g_mac) == 0) {
    logMessage("Failed to configure Ethernet using DHCP");
    return false;
  }
  
  g_myIp = Ethernet.localIP();
  logStrValue("My IP address: ", ipToStr(g_myIp, ipaddrStr, 24));
  return true;
}

void udpSendPacket(const IPAddress dest, const int port, const char *data, const int len) {
  g_Udp.beginPacket(dest, port);
  g_Udp.write(data, len);
  g_Udp.endPacket();
}

int udpReadPacket() {
    int packetSize = g_Udp.parsePacket();   
    if(packetSize > 0) {
      g_Udp.read(g_rcvPacketBuffer,UDP_TX_PACKET_MAX_SIZE);
    }
    return packetSize;
}

/************
* Functions for managing state.
*/
void changeState(const byte newState) {
  int maxlen = 100;
  char logMsg[maxlen];

  snprintf(logMsg, maxlen, "changing state from: %d to %d", g_currentState,newState);
  logMessage(logMsg);
  g_currentState = newState;
}

int getState() {
  return g_currentState;
}

void resetInit(const char *msg, const int len) {
  changeState(STATE_ASSIGNING);
  
  if(msg == NULL) {
    sendReplyMessage(NULL, 0);
  } else {
      sendReplyMessage(msg, len);
  }
}

/**********************
  functions for working with EEPROM
*/
bool writeStrToEEProm(int start, const char *data, const byte dataSize) {
  writeBufToEEProm(start, (const void *) data, dataSize);
}

void writeUIntToEEProm(int start, const uint16_t val) {
  EEPROM.write(start, (byte)(val >> 8));
  EEPROM.write(start+1, (byte) val);
}

void writeULongToEEProm(int start, const uint32_t val) {
  EEPROM.write(start, (byte)(val >> 24));
  EEPROM.write(start+1, (byte)(val >> 16));
  EEPROM.write(start+2, (byte)(val >> 8));
  EEPROM.write(start+3, (byte)(val));
}

bool writeBufToEEProm(int start, const void *data, const byte dataSize) {
  if(dataSize > MAX_BUF_WRITE) {
    logMessage("attempt to write value to EEProm greatner than max buffer bytes");
    return false;
  }
  
  EEPROM.write(start, dataSize);
  int curPos = start + 1;
  const byte *buf = (const byte *) data;
  
  for(byte i = 0; i < dataSize; i++)  {
    EEPROM.write(curPos++, buf[i]);
  }
  
  return true;
}

bool readStrFromEEProm(int start, char *data, const byte maxSize) {
  byte bytesRead = readBufFromEEProm(start, (byte *) data, maxSize - 1);
  if(bytesRead > 0) {    // make sure zero terminated.
    data[bytesRead] = 0;
  }

  return bytesRead > 0;
}

byte readBufFromEEProm(int start, byte *data, const byte maxSize) {
  int maxlen = 100;
  char logmsg[maxlen];

  byte bufSize = EEPROM.read(start);
  
  if(bufSize == 255) { // not previously written
    return 0;
  }
  
  byte readSize = bufSize < maxSize ? bufSize : maxSize; // leave room for zero terminating.
  int curPos = start + 1;
    
  if(readSize < bufSize) {
   snprintf(logmsg, maxlen, "var size: %d, max size: %d, partial read EEProm", bufSize, maxSize);
    logMessage(logmsg);
  }

  for(byte i = 0; i < readSize; i++) {
    data[i] = EEPROM.read(curPos++);
  }
  
  return bufSize;
}

uint16_t readUIntFromEEProm(const int start) { 
  uint16_t result;
  result = ((uint16_t) EEPROM.read(start)) << 8;
  result |= EEPROM.read(start+1);
  return result;
}

uint32_t readULongFromEEProm(const unsigned int start) {
  uint32_t result;
  result = ((uint32_t) EEPROM.read(start)) << 24;
  result |= ((uint32_t) EEPROM.read(start+1)) << 16;
  result |= ((uint32_t) EEPROM.read(start+2)) << 8;
  result |= EEPROM.read(start+3);
  return result;
}


/***********
*  Functions for encrypting data
***/

void generateRandom(byte *buf, const int len) {
  for(int i = 0; i < len; i++) {
    buf[i] = (byte) random(UCHAR_MAX);
  }
}


int padPKCS5(byte *buffer, const int sz) {
  
  // PKCS5 padding method.

  int blocks = sz / N_BLOCK;
  int paddingSize = 0;
  byte paddingVal = 0;
  int start = 0;

  if(sz % N_BLOCK > 0) {
    blocks++;
    paddingVal = N_BLOCK- (sz % N_BLOCK);
    paddingSize = paddingVal;
    start = (blocks * N_BLOCK) - paddingSize;
  }else {
    blocks++;
    paddingVal = 0x10;
    paddingSize = N_BLOCK;
    start = ((blocks-1) * N_BLOCK);
  }

  for(int i = start; i < (blocks * N_BLOCK); i++) {
    g_plainTextBuf[i] = paddingVal;
  }

  return blocks;
}

byte *getSha256Hmac(byte *buffer, const int msgSize) {
  Sha256.initHmac(g_aesKey, KEY_LENGTH);

  for(int i = 0; i < msgSize; i++) {
    Sha256.write(buffer[i]);
  }
  
  return Sha256.resultHmac();


}

int signAndAppendSha256Hmac(void *buffer, const int msgSize, const int bufferSize) {
  int remaining = bufferSize-msgSize;

  if(remaining < SHA256_LENGTH) {
    logIntValue("signature exceeds space remaining:", remaining);
    return 0; 
  }
  
  byte *sha256Hmac = getSha256Hmac((byte *)buffer, msgSize);

  logBuffer("256 HMAC: ", sha256Hmac, SHA256_LENGTH);
  logBuffer("data:", buffer, msgSize);

  memcpy(buffer + msgSize, sha256Hmac, SHA256_LENGTH);

  return msgSize + SHA256_LENGTH;
}


int encryptDataEIV(const void *data, const byte dataSize){
  byte iv[N_BLOCK];  
  int encryptSize = 0;

  if(dataSize >MAX_ENCRYPT_DATA_SIZE ) {
    logIntValue("encrypt max blk size exceeded: ", dataSize);
    return 0;
  }

  byte sz = dataSize + 1;

  //Explicit Initialization Vector (discard 1st block),  put in random data
  generateRandom(g_plainTextBuf, N_BLOCK); 
  g_plainTextBuf[N_BLOCK] = dataSize;
  memcpy(&g_plainTextBuf[N_BLOCK+1], data, dataSize);

  int msgSize = N_BLOCK + sz;   // account for throw away first block...
 
  int blocks = padPKCS5(g_plainTextBuf, msgSize);
  encryptSize = blocks * N_BLOCK;

  logIntValue("Blocks encrypting:", blocks);
  logIntValue("Data size: ", sz);
  logIntValue("Encrypt size:", encryptSize);
  
  generateRandom(iv, N_BLOCK);              // generate an iv
  logBuffer("iv:", iv, N_BLOCK);

  logBuffer("plaintext: ", g_plainTextBuf, encryptSize);

  byte succ = g_aes.cbc_encrypt(g_plainTextBuf, g_cipherBuf, blocks, iv);
  
  if(succ == SUCCESS) {
    return encryptSize;
  } else {
    logMessage("Failed on encrypt operation");
    return 0;
  }
}


byte decryptData(byte *cipher, byte *decrypted, const int size, const int bufsize) {
  byte iv[N_BLOCK];
  int blocks = size / N_BLOCK;
  byte datasize = 0;
  int maxlen = 100;
  char logmsg [maxlen];
  logIntValue("encrypt size: ", size);

  if(size % N_BLOCK > 0 && size > 0) {
    logIntValue("warning: invalid size decrypted buffer:", size);
    return 0;
  }
  
  logIntValue(" number of blocks: ", blocks);

  // iv doesn't matter since using EIV
  if(g_aes.cbc_decrypt(cipher, g_plainTextBuf, blocks, iv) == FAILURE) {
      logMessage("failure on decrypt");
      return 0;
  } else {
    logBuffer("decrypted: ", g_plainTextBuf, size);
    logMessage((char*) g_plainTextBuf);

    datasize = g_plainTextBuf[N_BLOCK];
    
    if( bufsize < datasize) {
      snprintf(logmsg, maxlen, "decrypt: bufsize: %d too small size: %d", bufsize, datasize);
      logMessage(logmsg);
      return 0;
    }

    memcpy(decrypted, &g_plainTextBuf[N_BLOCK+1], datasize);  
    return datasize;
  }
}


/************
* Functions to help with packet parsing, validation and creation
****/
bool validateHeader(const char *buf, const int buflen) {
  int sigSize = strlen(initSig);
  int maxlen = 100;
  char logmsg[maxlen];
  
  if(buf == NULL || buflen < (sigSize + 1) || strncmp(buf, initSig, sigSize) != 0) {
    logBuffer("validate buf: ", buf, buflen);
    logMessage("state missing from packet header, resetting to init");
    
    if(strncmp(buf, initSig, sigSize) != 0) {
      logMessage("bad header");
      logStrValue("buf:",buf);
      logStrValue("fixed sig:", initSig);
    }

    changeState(STATE_INIT);
    return false;
  }
  
  byte state = (byte) buf[sigSize];
  
  if(state != g_currentState) {
    snprintf(logmsg, maxlen, "Invalid state expect %d got %d restarting...", g_currentState, state);
    logMessage(logmsg);
    changeState(STATE_INIT);
    return false;
  }
  
  logIntValue("valid header, state: ", state);
  return true;
}

int addReplyHdr(char *buf) { 
  int replyLength = strlen(initReplySig);
  strncpy(buf, initReplySig, replyLength);
  buf[replyLength] = g_currentState;
  return replyLength + sizeof(byte);
}

void sendReplyMessage(const char *msgData, int dataSize) {
  int hdrSize = addReplyHdr(g_txPacketBuffer);
  int msgSize = hdrSize + dataSize;
  
  if(msgData != NULL) {
    memcpy(&g_txPacketBuffer[hdrSize], msgData, dataSize);
  }
  
  udpSendPacket(g_configAgentIp, INIT_SEND, g_txPacketBuffer, msgSize);
  logBuffer("tx msg: ", g_txPacketBuffer, msgSize);
}

bool parseServerIpAddress() {
  int partCnt;
  char *current = g_mqttServerDNS;
  char *next;
  bool isValid = true;
  
  for(int i = 0; i < 4 && isValid; i++) {
    long ipAddrPart = strtol(current, &next, 10);
    
    if((*next == '.' || *next == 0) && ipAddrPart <= 255 ) {
      g_mqttServerIp[i] = (byte) ipAddrPart;
      current = next+1;
    } else {
      isValid = false;
    }
  }  
  return isValid;
}

/******
* Methods for dealing with config
***/
bool readConfig() {
  g_mqttPort = readUIntFromEEProm(MQTT_PORT_START);
  int maxlen = 100;
  char logmsg [maxlen];  

  readStrFromEEProm(MQTT_SRV_START, g_mqttServerDNS, MQTT_SRV_MAX);
  g_lastMsgSequence = readULongFromEEProm(MQTT_LAST_TIMESTAMP);

  if(g_mqttPort != UINT_MAX) {
    snprintf(logmsg, maxlen, "Read configuration: %s:%d", g_mqttServerDNS, g_mqttPort);
    logMessage(logmsg);
    readBufFromEEProm(KEY_START, g_aesKey, KEY_LENGTH);
    logBuffer("key: ", g_aesKey, KEY_LENGTH);
    return true;
  }   
  return false;
}

bool writeConfig(const char *mqttSrv, const uint32_t port, const byte *key, const uint32_t seq) {
  if(mqttSrv == NULL || key == NULL) {
    return false;
  } 

  int srvSize = strlen(mqttSrv);
  int maxlen = 100;
  char logmsg[maxlen];

  if(g_mqttPort != 0) { 
    writeUIntToEEProm(MQTT_PORT_START, g_mqttPort);
    writeStrToEEProm(MQTT_SRV_START, mqttSrv, srvSize);
    writeBufToEEProm(KEY_START, key, KEY_LENGTH);    
    writeULongToEEProm(MQTT_LAST_TIMESTAMP, seq);
    snprintf(logmsg, maxlen, "Write configuration: %s:%d", mqttSrv, g_mqttPort);
    logMessage(logmsg);
    return true;
  }
  return false;
}


void setMqttConfig() {
    int maxlen = MQTT_SRV_MAX + 30;
    char logmsg[maxlen];
    char ipaddStr[24];

    if(parseServerIpAddress()) {
      snprintf(logmsg, maxlen,"Connect mqtt @ address: %s:%d", 
          ipToStr(g_mqttServerIp, ipaddStr, 24), g_mqttPort);
      logMessage(logmsg);
      mqttClient.setServer(g_mqttServerIp, g_mqttPort);
    } else {
      snprintf(logmsg, maxlen, "Connect mqtt @ address: %s:%d", g_mqttServerDNS, g_mqttPort);
      logMessage(logmsg);
      mqttClient.setServer(g_mqttServerDNS, g_mqttPort);        
    }  
}

/*****
*  Functions to process states.
*/
void initializeState() {
  randomSeed(analogRead(SAMPLE_PIN)); // make sure random for iv generation.
  if(getDhcpAddr()) {
    if(!readConfig()) {
      changeState(STATE_ASSIGNING);
      g_Udp.begin(BCAST_PORT);
    } else {
      // check if IP address, if so then initiate with ip else initiate with dns.
      setMqttConfig();

      byte succ = g_aes.set_key (g_aesKey, KEY_BITS);     
      if(succ != SUCCESS) {
         logMessage("Failure setting encryption key");
      }
changeState(STATE_CONNECTING);
    }
  }
}

void assignState() {
  int packetSize = udpReadPacket();
  
  if( packetSize > 0)  {
    g_configAgentIp = g_Udp.remoteIP();
    logPacket(packetSize, g_configAgentIp, g_Udp.remotePort(), g_rcvPacketBuffer);
    
    if(validateHeader(g_rcvPacketBuffer, UDP_TX_PACKET_MAX_SIZE)){
      changeState(STATE_INITIALIZE_CONFIG);
      sendReplyMessage(g_lockId, strlen(g_lockId));
    }
  }
}

void configState() {
  int packetSize = udpReadPacket();
  int maxlen = MQTT_SRV_MAX + 30;
  char logmsg[maxlen];

  if( packetSize > 0)  { 
      logPacket(packetSize, g_Udp.remoteIP(), g_Udp.remotePort(), g_rcvPacketBuffer); 
   
     if(g_configAgentIp == g_Udp.remoteIP() && packetSize > MIN_INIT_PACKET) {
       logBuffer("rcvd config: ", g_rcvPacketBuffer, packetSize);     
       
       if(validateHeader(g_rcvPacketBuffer, packetSize)) { 
          g_mqttPort = ((uint16_t) g_rcvPacketBuffer[INIT_PACKET_PORT_INDEX]) << 8 
                            | g_rcvPacketBuffer[INIT_PACKET_PORT_INDEX+1];
          g_lastMsgSequence =((uint32_t) g_rcvPacketBuffer[INIT_PACKET_COUNTER_INDEX] << 24 
                           | (uint32_t) g_rcvPacketBuffer[INIT_PACKET_COUNTER_INDEX+1] << 16
                           | (uint16_t) g_rcvPacketBuffer[INIT_PACKET_COUNTER_INDEX+2] << 8
                           | (byte) g_rcvPacketBuffer[INIT_PACKET_COUNTER_INDEX]);

          memcpy(g_aesKey, &g_rcvPacketBuffer[INIT_PACKET_KEY_INDEX], KEY_LENGTH);
          int sizeServer = packetSize - INIT_PACKET_SERVER_INDEX;

          if(sizeServer > 0 && sizeServer < MQTT_SRV_MAX-1) {                   
            strncpy(g_mqttServerDNS, &g_rcvPacketBuffer[INIT_PACKET_SERVER_INDEX], sizeServer);
            logStrValue("config server: ", g_mqttServerDNS);
            g_mqttServerDNS[sizeServer] = 0;
            snprintf(logmsg, maxlen, "configured server: %s:%d", g_mqttServerDNS, g_mqttPort);
            logMessage(logmsg);
            logBuffer("key: ", g_aesKey, KEY_LENGTH);
          
            if(writeConfig(g_mqttServerDNS, g_mqttPort, g_aesKey, g_lastMsgSequence)) {
               logMessage( "config completed");
               readConfig();
                g_aes.set_key (g_aesKey, KEY_BITS);
               changeState(STATE_TESTING_CONFIG);
               sendReplyMessage(NULL, 0);
             } else {
               char msg[] = "Save failed for data";
               resetInit(msg, sizeof(msg));            
             }
           }
           else
           {
             logMessage("invalid server size, <= 0");
             char msg[] = "invalid header received";
             resetInit(msg, sizeof(msg)); 
           }
         }
       } 
       else {
         logMessage( "Failed to validate header");
         char msg[] = "invalid header received";
         resetInit(msg, sizeof(msg));
       }
    }
}

void testMqttState() {
  int maxlen = MQTT_SRV_MAX + 30;
  char logmsg[maxlen];
 
  setMqttConfig();

  if(connectMqttState()) {
    sendReplyMessage(successMsg, sizeof(successMsg));
 } else {
   snprintf(logmsg, maxlen, "failed connect: %s:%d", g_mqttServerDNS, g_mqttPort);
   int sz = strnlen(logmsg, maxlen); 
   sendReplyMessage(logmsg, sz);
   logMessage(logmsg);
 }
}

bool connectMqttState() {
  logMessage("attempting to communicate with mqtt server");
  
  if (mqttClient.connect("locker")) {
    mqttClient.publish("lockregister",g_lockId);
    mqttClient.subscribe(g_lockId);
    changeState(STATE_RUNNING);
  } else {
      logMessage("failed to connect with mqtt server");
      delay(2000);
  }
}

void runState() {
  mqttClient.loop();
}

/****
* Handle mqtt message send/receive
*****/

int encryptAndSignMessagePayload(char *target, const char *payload, const int bufSize) {
    int size = strlen(payload);

    // first serialize to json and encrypt payload.
    logStrValue("unencrypted payload:", payload);

    int encryptSize = encryptDataEIV(payload, size);
    logBuffer("encrypted: ", g_cipherBuf, encryptSize);

    // encryptData will limit result to MAX_ENCRYPT_DATA_SIZE, will return 0 if exceeded.
    int totalSize = encryptSize + START_ENCRYPT_DATA + SHA256_LENGTH;

    if(encryptSize > 0 && totalSize <= bufSize) {
      strncpy( (char *) target, g_lockId, MAX_ENCRYPT_MSG );
      memcpy(target + START_ENCRYPT_DATA, g_cipherBuf, encryptSize);
      signAndAppendSha256Hmac(target, encryptSize + START_ENCRYPT_DATA, bufSize);
      return totalSize;
    } else {
       logIntValue("encrypt failed, exceeded size of max encrypt:", totalSize);
       return 0;
    }
}

bool isValidSequence(uint32_t seq) {
  if(seq > g_lastMsgSequence ) {
    g_lastMsgSequence = seq;
    writeULongToEEProm(MQTT_LAST_TIMESTAMP, seq);
    return true;
  }

  return false;
}

void handleLockMessage(char *message, const int size) {
  StaticJsonBuffer<JSON_5_ATTRIBUTES> jsonBuffer;
  JsonObject& msg = jsonBuffer.parseObject(message);
  const char *lockMsg;
  char encryptedMsg[MAX_ENCRYPT_MSG];

  if(!msg.success()) {
    logMessage("failed to parse json");
  } else {
    msg.printTo(Serial);
    bool lockState = (bool) msg["lock"];
    uint32_t seq = (uint32_t) msg["seq"];

   
    if(isValidSequence(seq)) {
      if(lockState) {
         lockMsg = "{\"locked\":true}";
      } else {
         lockMsg = "{\"locked\":false}";
      }

      int size = encryptAndSignMessagePayload(encryptedMsg, lockMsg, MAX_ENCRYPT_MSG);    
      mqttClient.publish(controlTopic, (byte*) encryptedMsg, size);
      logBuffer("ending msg ", encryptedMsg, size);
    }else {
      int msglen = 100;
      char message[msglen];
      snprintf(message, msglen, "invalid seq: %lu", seq);
      logMessage(message);

      // ignore bad messages, could be a replay.  Intentionally no reply.
    }
  }
}


int validateAndDecrypt(byte *signedCipher, byte *decrypted, int length, int buflen) {
  int encryptSize = length - SHA256_LENGTH; 
  byte *sig = getSha256Hmac(signedCipher, encryptSize);

  if(memcmp(sig, &signedCipher[encryptSize], SHA256_LENGTH) == 0) {
     logMessage("Signature match");
     byte plainSize = decryptData(signedCipher, decrypted, encryptSize, buflen);
     return plainSize;
  } else {
     logMessage("Signature mismatch");
     logBuffer("calc: ", sig, SHA256_LENGTH);
     logBuffer("msg: ", &signedCipher[encryptSize], SHA256_LENGTH);
     return 0;
  }
}

/****
*  Mqtt callback function for published events.
***/
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  // Warning: pubsub lib reuses buffer for receive and send, overwrite on send.
  
  if(length <= TOTAL_ENCRYPT_SZ) {
      int maxlen = 100;
      char logmsg[maxlen];
      byte plain[length];  // decrypt message will always be < encrypt, so message safe.

      snprintf(logmsg,maxlen, "mqtt rcv topic: %s size: %d", topic, length);
      logMessage(logmsg);
      logBuffer("rcv data:", payload, length);
           
      int plainSize = validateAndDecrypt(payload, plain, length, length);

      logIntValue("decrypt buf size: ", plainSize);
      logBuffer("decrypted data:", plain, plainSize);

      if(plainSize > 0) {
        handleLockMessage((char*)plain, plainSize);
      }
   } else {
      logIntValue("message too big: ", length);
   }
}


void setup() {
  g_rcvPacketBuffer[UDP_TX_PACKET_MAX_SIZE] = 0;  // safety termination for strings.
  Serial.begin(9600);
}


void loop() {
  switch(g_currentState)
  {
    case STATE_INIT:
      logMessage("entering init");
      initializeState();
      break;
    case STATE_ASSIGNING:
      assignState();
      break;
    case STATE_INITIALIZE_CONFIG:
       configState();
       break; 
    case STATE_TESTING_CONFIG:
      testMqttState();
      break;
    case STATE_CONNECTING:
      connectMqttState();
      break;
    case STATE_RUNNING:   
     runState();
      break;
    default:
      logIntValue("Resetting to init, invalid state: ", g_currentState);
      changeState(STATE_INIT);
      break;
  }
}


