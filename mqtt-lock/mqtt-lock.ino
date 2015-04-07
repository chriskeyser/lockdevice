
#include <AES.h>
#include <SPI.h>
#include <Ethernet.h>
#include <EEPROM.h>
#include <EthernetUdp.h>
#include <sha256.h>

#define UDP_TX_PACKET_MAX_SIZE 144
#include <PubSubClient.h>
#define MQTT_MAX_PACKET_SIZE 255
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

//encryption defines.  SAMPLE_PIN is an unconnected analog pin...
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

// shared buffers to use.
char rcvPacketBuffer[UDP_TX_PACKET_MAX_SIZE+1];
char txPacketBuffer[UDP_TX_PACKET_MAX_SIZE+1];

// This would normally need to be read from a board setting rather than hardcoding.
byte mac[] = {
  0x00, 0xAA, 0xBB, 0xCC, 0x1E, 0x02
};

// global variables.
IPAddress myIp;
IPAddress configAgentIp;
byte mqttServerIp[4];
char mqttServerDNS[MQTT_SRV_MAX+1];
unsigned int mqttPort;
byte currentState=STATE_INIT;

// encryption and signing globals
AES aes;

byte aesKey[KEY_LENGTH];
byte cipherBuf[MAX_TOTAL_MSG];
byte plainTextBuf[MAX_TOTAL_MSG];

// Callback function header
void callback(char* topic, byte* payload, unsigned int length);

// various clients to use in processing...
EthernetClient ethClient;
EthernetUDP Udp;

// initialization constants
#define SIGLEN 5
const char initSig[] PROGMEM = "LINIT";
const char initReplySig[] PROGMEM = "LRPLY";
const char resetSig[] PROGMEM =  "RST";
char deviceId[] = "lock-00AABBCC1E02"; // typically would be read from register
const char successMsg[] PROGMEM = "success";

// positions for fixed init msg
// size of signature + state + port + encryption key + string for domain or ip.
#define MIN_INIT_PACKET          SIGLEN + sizeof(byte) + sizeof(unsigned int) + KEY_LENGTH + 6
#define INIT_PACKET_PORT_INDEX   SIGLEN + sizeof(byte)
#define INIT_PACKET_KEY_INDEX    INIT_PACKET_PORT_INDEX + sizeof(unsigned int)
#define INIT_PACKET_SERVER_INDEX INIT_PACKET_KEY_INDEX + KEY_LENGTH

// IP addresses
byte server[] = { 0, 0, 0, 0 }; 
IPAddress myip(0, 0, 0, 0);

// MQTT defines
#define LOCK_CHALLENGE 1
#define LOCK_RESPONSE 2
#define LOCK_OPERATION 3
#define JSON_5_ATTRIBUTES   JSON_OBJECT_SIZE(5)

char controlTopic[] = "lockctl";
PubSubClient mqttClient(server, 1883, callback, ethClient);

//JSON processing

/**** End Declarations ************

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
  char ipStr[24]; 
  Serial.print(ipToStr(addr, ipStr, 24));
}

void logMessage(const char *msg) {
  Serial.println(msg);
}

void logIntValue(const char *msg, const int value) {
   Serial.print(msg);
   Serial.println(value);
}

void logStrValue(const char *msg, const char *value) {
  Serial.print(msg);
  Serial.println(value);
}

void logBuffer(const char *title, const void *data, const int bufLength) {
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

void logPacket(const int packetSize, const IPAddress addr, const int port, const char * data)
{
  char ipaddrStr[24];

  Serial.print("Udp rcv: ");
  Serial.print(packetSize);
  Serial.print( " bytes from: ");
  Serial.print(ipToStr(addr, ipaddrStr, 24));
  Serial.print(":");
  Serial.print(port);
  logBuffer("data", data, packetSize);
}

/************
* Functions for working with network interactions.
*/
bool getDhcpAddr() {
  char ipaddrStr[24];

  if(Ethernet.begin(mac) == 0) {
    logMessage("Failed to configure Ethernet using DHCP");
    return false;
  }
  
  myIp = Ethernet.localIP();
  logStrValue("My IP address: ", ipToStr(myIp, ipaddrStr, 24));
  return true;
}

void udpSendPacket(const IPAddress dest, const int port, const char *data, const int len) {
  Udp.beginPacket(dest, port);
  Udp.write(data, len);
  Udp.endPacket();
}

int udpReadPacket() {
    int packetSize = Udp.parsePacket();   
    if(packetSize > 0) {
      Udp.read(rcvPacketBuffer,UDP_TX_PACKET_MAX_SIZE);
    }
    return packetSize;
}

/************
* Functions for managing state.
*/
void changeState(const byte newState) {
  int maxlen = 100;
  char logMsg[maxlen];

  snprintf(logMsg, maxlen, "changing state from: %d to %d", currentState,newState);
  logMessage(logMsg);
  currentState = newState;
}

int getState() {
  return currentState;
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
bool writeStrToEEProm(const int start, const char *data, const byte dataSize) {
  writeBufToEEProm(start, (const void *) data, dataSize);
}

bool writeBufToEEProm(const int start, const void *data, const byte dataSize) {
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

bool readStrFromEEProm(const unsigned int start, char *data, const byte maxSize) {
  byte bytesRead = readBufFromEEProm(start, (byte *) data, maxSize - 1);
  if(bytesRead > 0) {    // make sure zero terminated.
    data[bytesRead] = 0;
  }

  return bytesRead > 0;
}

byte readBufFromEEProm(const unsigned int start, byte *data, const byte maxSize) {
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

void writeIntToEEProm(const unsigned int start, const unsigned int val) {
  byte hi = (byte) (val >> 8);
  byte lo = (byte) val;
  EEPROM.write(start, hi);
  EEPROM.write(start+1, lo);
}

unsigned int readUIntFromEEProm(const int start) {
  unsigned int result;
  byte hi = EEPROM.read(start);
  byte lo = EEPROM.read(start+1);
  result = hi;
  result <<= 8;
  result |= lo;
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


void padPKCS5(byte *buffer, const int sz, const int encryptSize) {

  // PKCS5 padding method.
  int paddingSize = N_BLOCK-(sz % N_BLOCK);
  int start = encryptSize - paddingSize;

  for(int i = start; i < encryptSize; i++) {
    plainTextBuf[i] = paddingSize;
  }
}

byte *getSha256Hmac(byte *buffer, const int msgSize) {
  Sha256.initHmac(aesKey, KEY_LENGTH);

  for(int i = 0; i < msgSize; i++) {
    Sha256.write(buffer[i]);
  }
  
  return Sha256.resultHmac();


}

int signAndAppendSha256Hmac(byte *buffer, const int msgSize, const int bufferSize) {
  int remaining = bufferSize-msgSize;

  if(remaining < SHA256_LENGTH) {
    logIntValue("signature exceeds space remaining:", remaining);
    return 0; 
  }
  
  byte *sha256Hmac = getSha256Hmac(buffer, msgSize);

  logBuffer("256 HMAC: ", sha256Hmac, SHA256_LENGTH);
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

  int blocks = (sz / N_BLOCK) + 1;

  if(sz % N_BLOCK > 0) { blocks++; }

  encryptSize = blocks * N_BLOCK;

  logIntValue("Blocks encrypting:", blocks+1);
  logIntValue("Data size: ", sz);
  
  generateRandom(iv, N_BLOCK);              // generate an iv
  logBuffer("iv:", iv, N_BLOCK);
  padPKCS5(plainTextBuf, sz, encryptSize);  // set unused bytes to pad value.

  //Explicit Initialization Vector (discard 1st block),  put in random data
  generateRandom(plainTextBuf, N_BLOCK);    
  
  plainTextBuf[N_BLOCK] = dataSize;
  memcpy(&plainTextBuf[N_BLOCK+1], data, dataSize);
  logBuffer("plaintext: ", plainTextBuf, encryptSize);
  byte succ = aes.cbc_encrypt(plainTextBuf, cipherBuf, blocks, iv);
  
  logIntValue("Encrypt size:", encryptSize);
  
  if(succ == SUCCESS) {
    int totalSize = signAndAppendSha256Hmac(cipherBuf, encryptSize, MAX_TOTAL_MSG);
    logIntValue("signed size:", totalSize);
    if(totalSize > 0) {   
      logBuffer("Signed message: ", cipherBuf, totalSize);
      return totalSize;
    } else {
      logMessage("Signing failed with encrypt operation");
      return 0;
    }
  } else {
    logMessage("Failed on encrypt operation");
    return 0;
  }
}

int encryptDataSendIV(const void *data, const byte dataSize){
  byte iv[N_BLOCK];  
  int encryptSize = 0;

  if(dataSize > MAX_ENCRYPT_DATA_SIZE) {
    logIntValue("encrypt max blk size exceeded: ", dataSize);
    return 0;
  }

  byte sz = dataSize + 1;
  int blocks = sz / N_BLOCK;

  if(sz % N_BLOCK > 0) { blocks++; }
  encryptSize = blocks * N_BLOCK;

  logIntValue("Blocks encrypting:", blocks+1);
  logIntValue("Data size: ", sz);
  
  generateRandom(iv, N_BLOCK);              // generate an iv
  logBuffer("iv:", iv, N_BLOCK);
  padPKCS5(plainTextBuf, sz, encryptSize);  // set unused bytes to pad value.

  plainTextBuf[0] = dataSize;
  memcpy(&plainTextBuf[1], data, dataSize); 
  byte succ = aes.cbc_encrypt(plainTextBuf, &cipherBuf[N_BLOCK], blocks, iv);  
  memcpy(cipherBuf, iv, N_BLOCK);
  encryptSize += N_BLOCK;

  logIntValue("Encrypt size:", encryptSize);
  
  if(succ == SUCCESS) {
    int totalSize = signAndAppendSha256Hmac(cipherBuf, encryptSize, MAX_TOTAL_MSG);
    if(totalSize > 0) {   
      logBuffer("Signed message: ", cipherBuf, totalSize);
      return totalSize;
    } else {
      logMessage("Signing failed with encrypt operation");
      return 0;
    }
  } else {
    logMessage("Failed on encrypt operation");
    return 0;
  }
}



byte decryptData(byte *cipher, byte *decrypted, const int totalsize, const int bufsize) {
  byte iv[N_BLOCK];
  int size = totalsize -  SHA256_LENGTH;
  int blocks = size / N_BLOCK;
  byte datasize = 0;
  int maxlen = 100;
  char logmsg [maxlen];
  logIntValue("encrypt size: ", size);

  if(size % N_BLOCK > 0) {
    logIntValue("warning: invalid size decrypted buffer:", size);
    return 0;
  }
  
  byte *sig = getSha256Hmac(cipher, size);
  if(memcmp(sig, &cipher[size], SHA256_LENGTH) == 0) {
  

    logIntValue(" number of blocks: ", blocks);

    // iv doesn't matter since using EIV
    if(aes.cbc_decrypt(cipher, plainTextBuf, blocks, iv) == FAILURE) {
      logMessage("failure on decrypt");
    } else {
      logMessage("decrypted");
      logBuffer("decrypted: ", plainTextBuf, size);
      logMessage((char*) plainTextBuf);

      datasize = plainTextBuf[N_BLOCK];
    
      if( bufsize < datasize) {
        snprintf(logmsg, maxlen, "decrypt: bufsize: %d too small size: %d", bufsize, datasize);
        logMessage(logmsg);
        return 0;
      }

      memcpy(decrypted, &plainTextBuf[N_BLOCK+1], datasize);  
      return datasize;
    }
  } else {
     logMessage("Signature mismatch");
     logBuffer("msg: ", &cipher[size], SHA256_LENGTH);
     logBuffer("calc:", sig, SHA256_LENGTH);
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
    logMessage("state missing from packet header, resetting to init");
    changeState(STATE_INIT);
    return false;
  }
  
  byte state = (byte) buf[sigSize];
  
  if(state != currentState) {
    snprintf(logmsg, maxlen, "Invalid state expected %d got %d restarting...", currentState, state);
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
  buf[replyLength] = currentState;
  return replyLength + sizeof(byte);
}

void sendReplyMessage(const char *msgData, int dataSize) {
  int hdrSize = addReplyHdr(txPacketBuffer);
  int msgSize = hdrSize + dataSize;
  
  if(msgData != NULL) {
    memcpy(&txPacketBuffer[hdrSize], msgData, dataSize);
  }
  
  udpSendPacket(configAgentIp, INIT_SEND, txPacketBuffer, msgSize);
  logBuffer("tx msg: ", txPacketBuffer, msgSize);
}

bool parseServerIpAddress() {
  int partCnt;
  char *current = mqttServerDNS;
  char *next;
  bool isValid = true;
  
  for(int i = 0; i < 4 && isValid; i++) {
    long ipAddrPart = strtol(current, &next, 10);
    
    if((*next == '.' || *next == 0) && ipAddrPart <= 255 ) {
      mqttServerIp[i] = (byte) ipAddrPart;
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
  mqttPort = readUIntFromEEProm(MQTT_PORT_START);
  int maxlen = 100;
  char logmsg [maxlen];  

  readStrFromEEProm(MQTT_SRV_START, mqttServerDNS, MQTT_SRV_MAX);

  if(mqttPort != UINT_MAX) {
    snprintf(logmsg, maxlen, "Read configuration: %s:%d", mqttServerDNS, mqttPort);
    logMessage(logmsg);
    readBufFromEEProm(KEY_START, aesKey, KEY_LENGTH);
    logBuffer("key: ", aesKey, KEY_LENGTH);
    return true;
  }   
  return false;
}

bool writeConfig(const char *mqttSrv, const int port, const byte *key) {
  if(mqttSrv == NULL || key == NULL) {
    return false;
  } 

  int srvSize = strlen(mqttSrv);
  int maxlen = 100;
  char logmsg[maxlen];

  if(mqttPort != 0) { 

    writeIntToEEProm(MQTT_PORT_START, mqttPort);
    writeStrToEEProm(MQTT_SRV_START, mqttSrv, srvSize);
    writeBufToEEProm(KEY_START, key, KEY_LENGTH);    
    
    snprintf(logmsg, maxlen, "Write configuration: %s:%d", mqttSrv, mqttPort);
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
          ipToStr(mqttServerIp, ipaddStr, 24), mqttPort);
      logMessage(logmsg);
      mqttClient.setServer(mqttServerIp, mqttPort);
    } else {
      snprintf(logmsg, maxlen, "Connect mqtt @ address: %s:%d", mqttServerDNS, mqttPort);
      logMessage(logmsg);
      mqttClient.setServer(mqttServerDNS, mqttPort);        
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
      Udp.begin(BCAST_PORT);
    } else {
      // check if IP address, if so then initiate with ip else initiate with dns.
      setMqttConfig();

      byte succ = aes.set_key (aesKey, KEY_BITS);     
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
    configAgentIp = Udp.remoteIP();
    logPacket(packetSize, configAgentIp, Udp.remotePort(), rcvPacketBuffer);
    
    if(validateHeader(rcvPacketBuffer, UDP_TX_PACKET_MAX_SIZE)){
      changeState(STATE_INITIALIZE_CONFIG);
      sendReplyMessage(deviceId, strlen(deviceId));
    }
  }
}

void configState() {
  int packetSize = udpReadPacket();
  int maxlen = MQTT_SRV_MAX + 30;
  char logmsg[maxlen];

  if( packetSize > 0)  { 
      logPacket(packetSize, Udp.remoteIP(), Udp.remotePort(), rcvPacketBuffer); 
   
     if(configAgentIp == Udp.remoteIP() && packetSize > MIN_INIT_PACKET) {
       logBuffer("rcvd config: ", rcvPacketBuffer, packetSize);     
       
       if(validateHeader(rcvPacketBuffer, packetSize)) { 
          mqttPort = ((int) rcvPacketBuffer[INIT_PACKET_PORT_INDEX]) << 8 
                            | rcvPacketBuffer[INIT_PACKET_PORT_INDEX+1];
          memcpy(aesKey, &rcvPacketBuffer[INIT_PACKET_KEY_INDEX], KEY_LENGTH);
          int sizeServer = packetSize - INIT_PACKET_SERVER_INDEX;

          if(sizeServer > 0 && sizeServer < MQTT_SRV_MAX-1) {          
            strncpy(mqttServerDNS, &rcvPacketBuffer[INIT_PACKET_SERVER_INDEX], sizeServer);
            mqttServerDNS[sizeServer] = 0;
            snprintf(logmsg, maxlen, "configured server: %s:%d", mqttServerDNS, mqttPort);
            logMessage(logmsg);
            logBuffer("key: ", aesKey, KEY_LENGTH);
          
            if(writeConfig(mqttServerDNS, mqttPort, aesKey)) {
               logMessage( "config completed");
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
   snprintf(logmsg, maxlen, "failed connect: %s:%d", mqttServerDNS, mqttPort);
   int sz = strnlen(logmsg, maxlen); 
   sendReplyMessage(logmsg, sz);
   logMessage(logmsg);
 }
}

bool connectMqttState() {
  logMessage("attempting to communicate with mqtt server");
  
  if (mqttClient.connect("locker")) {
    mqttClient.publish("lockregister",deviceId);
    mqttClient.subscribe(deviceId);
    changeState(STATE_RUNNING);
  } else {
      logMessage("failed to connect with mqtt server");
      delay(2000);
  }
}

void runState() {
  delay(500);
  mqttClient.loop();
}

void setup() {
  rcvPacketBuffer[UDP_TX_PACKET_MAX_SIZE] = 0;  // safety termination for strings.
  Serial.begin(9600);
}

void loop() {
  switch(currentState)
  {
    case STATE_INIT:
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
      logIntValue("Resetting to init, invalid state: ", currentState);
      changeState(STATE_INIT);
      break;
  }
}


int encryptMessagePayload(char *target, const char *payload, const int bufSize) {
    int size = strlen(payload);

    // first serialize to json and encrypt payload.
    logStrValue("unencrypted payload:", payload);

    int encryptSize = encryptDataEIV(payload, size);

    // encryptData will limit result to MAX_ENCRYPT_DATA_SIZE, will return 0 if exceeded.
    int totalSize = encryptSize + START_ENCRYPT_DATA;

    if(encryptSize > 0 && totalSize <= bufSize) {
      //expensive to put encrypted data into json since each byte takes several char. Skipping.
      strncpy( (char *) target, deviceId, MAX_ENCRYPT_MSG );
      memcpy(target + START_ENCRYPT_DATA, cipherBuf, encryptSize);
      return totalSize;
    } else {
       logIntValue("encrypt failed, exceeded size of max encrypt:", totalSize);
       return 0;
    }
}


void handleLockMessage(char *message, const int size) {
  StaticJsonBuffer<JSON_5_ATTRIBUTES> jsonBuffer;
  JsonObject& msg = jsonBuffer.parseObject(message);
  char lockMsg[MAX_ENCRYPT_DATA_SIZE];
  char encryptedMsg[MAX_ENCRYPT_MSG];
  int guard = 0xF0F0;

  if(!msg.success()) {
    logMessage("failed to parse json");
  } else {
    msg.printTo(Serial);
    bool lockState = (bool) msg["lock"];

    if(lockState) {
       snprintf(lockMsg, MAX_ENCRYPT_DATA_SIZE, "{\"locked\":true, \"devId\":\"%s\"}", deviceId);
    } else {
       snprintf(lockMsg, MAX_ENCRYPT_DATA_SIZE, "{\"locked\":false, \"devId\":\"%s\"}", deviceId);
    }


    int size = encryptMessagePayload(encryptedMsg, lockMsg, MAX_ENCRYPT_MSG);
    mqttClient.publish(controlTopic, (byte*) encryptedMsg, size);
    logBuffer("ending msg ", encryptedMsg, size);
  }
  if(guard != 0xF0F0) {
    logMessage("stack overrun");
  }else {
    logMessage("exiting handleLockMessage");
  }
}


// Callback function
void callback(char* topic, byte* payload, unsigned int length) {
  // In order to republish this payload, a copy must be made
  // as the original payload buffer will be overwritten whilst
  // constructing the PUBLISH packet.
  
  // Allocate the correct amount of memory for the payload copy
  if(length <= TOTAL_ENCRYPT_SZ) {
      int maxlen = 100;
      char logmsg[maxlen];
      int bufLen = length;
      
      snprintf(logmsg,maxlen, "mqtt rcv topic: %s size: %d", topic, length);
      logMessage(logmsg);
      logBuffer("rcv data:", payload, length);
      
#ifdef ENCRYPT      
      byte plain[length];
      byte plainSize = decryptData(payload, plain, length, length); 

      logIntValue("decrypt buf size: ", plainSize);
      logBuffer("decrypted data:", plain, plainSize);      
      handleLockMessage((char*)plain, plainSize);
#else
      handleLockMessage((char*)payload, length);
#endif  
   } else {
      logIntValue("message too big: ", length);
   }
}


