#include <AES.h>
#include <SPI.h>
#include <Ethernet.h>
#include <EEPROM.h>
#include <EthernetUdp.h>
#define UDP_TX_PACKET_MAX_SIZE 192
#include <PubSubClient.h>
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
#define KEY_LENGTH        16
#define KEY_BITS          128
#define SAMPLE_PIN        15      
#define MAX_ENCRYPT_SIZE  (3*N_BLOCK)-1
#define TOTAL_ENCRYPT_SZ  4*N_BLOCK
#undef ENCRYPT

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

// encryption globals
AES aes;
byte aesKey[KEY_LENGTH];
byte cipherBuf[TOTAL_ENCRYPT_SZ];
byte plainTextBuf[TOTAL_ENCRYPT_SZ];

// Callback function header
void callback(char* topic, byte* payload, unsigned int length);

// various clients to use in processing...
EthernetClient ethClient;
EthernetUDP Udp;

// initialization constants
#define SIGLEN 5
const char initSig[] = "LINIT";
const char initReplySig[] = "LRPLY";
const char resetSig[] = "RST";
char deviceId[] = "lock-00AABBCC1E02"; // typically would be read from register
const char successMsg[] = "success";

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
#define MAX_JSON_MSG   JSON_OBJECT_SIZE(10)
char controlTopic[] = "lockctl";
PubSubClient mqttClient(server, 1883, callback, ethClient);

//JSON processing


/**** End Declarations ************

/************
* Functions for writing debug information out serial port.
*/
String ipToStr(IPAddress addr) {
  if(addr != NULL) {
    String addrStr = String(addr[0]);
    for (int i = 1; i < 4; i++) {
      addrStr += (".");
      addrStr += addr[i];
    }  
    return addrStr;
  } else {
    return String();
  }
}

void printIP(IPAddress addr) {
  Serial.print(ipToStr(addr));
}

void logMessage(String msg) {
  Serial.println(msg);
}

void printBuffer(char *title, void *data, int bufLength) {
  Serial.print(title);
  byte *bytes = (byte *) data;
  
  for(int i = 0; i < bufLength; i++) {
    Serial.print(bytes[i]);
    Serial.print(" ");
  }
  Serial.println();
}

void logPacket(int packetSize, IPAddress addr, int port, char * data)
{
  Serial.print("Udp rcv: ");
  Serial.print(packetSize);
  Serial.print( " bytes from: ");
  Serial.print(ipToStr(addr));
  Serial.print(":");
  Serial.print(port);
  printBuffer("data", data, packetSize);
}

/************
* Functions for working with network interactions.
*/
bool getDhcpAddr() { 
  if(Ethernet.begin(mac) == 0) {
    logMessage("Failed to configure Ethernet using DHCP");
    return false;
  }
  
  myIp = Ethernet.localIP();
  logMessage(String("My IP address: ") + ipToStr(myIp));
  return true;
}

void udpSendPacket(IPAddress dest, int port, char *data, int len) {
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
void changeState(byte newState) {
  String logMsg = String("changing state from:") + currentState + " to:" + + newState;
  logMessage(logMsg);
  currentState = newState;
}

int getState() {
  return currentState;
}

void resetInit(const char *msg, int len) {
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
bool writeStrToEEProm(int start, char *data, byte dataSize) {
  writeBufToEEProm(start, (void *) data, dataSize);
}

bool writeBufToEEProm(int start, void *data, byte dataSize) {
  if(dataSize > MAX_BUF_WRITE) {
    logMessage("attempt to write value to EEProm greatner than max buffer bytes");
    return false;
  }
  
  EEPROM.write(start, dataSize);
  int curPos = start + 1;
  byte *buf = (byte *) data;
  
  for(byte i = 0; i < dataSize; i++)  {
    EEPROM.write(curPos++, buf[i]);
  }
  
  return true;
}

bool readStrFromEEProm(unsigned int start, char *data, byte maxSize) {
  byte bytesRead = readBufFromEEProm(start, (byte *) data, maxSize - 1);
  Serial.println(bytesRead);
  if(bytesRead > 0) {    // make sure zero terminated.
    data[bytesRead] = 0;
  }

  return bytesRead > 0;
}

byte readBufFromEEProm(unsigned int start, byte *data, byte maxSize) {
  byte bufSize = EEPROM.read(start);
  
  if(bufSize == 255) { // not previously written
    return 0;
  }
  
  byte readSize = bufSize < maxSize ? bufSize : maxSize; // leave room for zero terminating.
  int curPos = start + 1;
    
  if(readSize < bufSize) {
    logMessage(String("var size: ") + bufSize + " is greater than max size:" + maxSize + ", only reading partial");
  }

  for(byte i = 0; i < readSize; i++) {
    data[i] = EEPROM.read(curPos++);
  }
  
  return bufSize;
}

void writeIntToEEProm(unsigned int start, unsigned int val) {
  byte hi = (byte) (val >> 8);
  byte lo = (byte) val;
  EEPROM.write(start, hi);
  EEPROM.write(start+1, lo);
}

unsigned int readUIntFromEEProm(int start) {
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

void generateRandom(byte *buf, int len) {
  for(int i = 0; i < len; i++) {
    buf[i] = (byte) random(UCHAR_MAX);
  }
}

int encryptData(byte *data, byte dataSize){
  byte iv[N_BLOCK];  

  if(dataSize > MAX_ENCRYPT_SIZE) {
    return 0;
  }

  byte sz = dataSize + 1;

  int blocks = (sz / N_BLOCK) + 1;

  if(sz % N_BLOCK > 0) {
    blocks++;
  }

  generateRandom(iv, N_BLOCK);
  generateRandom(plainTextBuf, blocks * N_BLOCK);

  //Explicit Initialization Vector (discard 1st block) 
  plainTextBuf[N_BLOCK] = dataSize;
  memcpy(&plainTextBuf[N_BLOCK+1], data, dataSize);
  aes.cbc_encrypt(plainTextBuf, cipherBuf, blocks, iv);
  return (blocks + 1) * N_BLOCK;
}

byte decryptData(byte *cipher, byte *decrypted, int size, int bufsize) {
  byte iv[N_BLOCK];
  int blocks = size / N_BLOCK;
  byte datasize = 0;

  if(size % N_BLOCK > 0) {
    logMessage("warning: invalid size decrypted buffer");
    return 0;
  }
  
  // iv doesn't matter since using EIV
  aes.cbc_decrypt(cipher, plainTextBuf, blocks, iv);
  datasize = plainTextBuf[N_BLOCK];
  
  if( bufsize < datasize) {
    logMessage(String("decrypt: buf too small: ") + bufsize + ":" + datasize);
    return 0;
  }

  memcpy(decrypted, &plainTextBuf[N_BLOCK+1], datasize);
  return datasize;
}



/************
* Functions to help with packet parsing, validation and creation
****/
bool validateHeader(char *buf, int buflen) {
  int sigSize = strlen(initSig);
  
  if(buf == NULL || buflen < (sigSize + 1) || strncmp(buf, initSig, sigSize) != 0) {
    logMessage("state missing from packet header, resetting to init");
    changeState(STATE_INIT);
    return false;
  }
  
  byte state = (byte) buf[sigSize];
  
  if(state != currentState) {
    logMessage(String("invalid state, expected: ") + currentState + " got: " + state + "restarting...");
    changeState(STATE_INIT);
    return false;
  }
  
  logMessage(String("valid header, state: ") + state);
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
  printBuffer("tx msg: ", txPacketBuffer, msgSize);
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

  if(mqttPort != UINT_MAX) {
    readStrFromEEProm(MQTT_SRV_START, mqttServerDNS, MQTT_SRV_MAX);
    logMessage( String("Read configuration: ") + mqttServerDNS + ":" +  mqttPort);
    readBufFromEEProm(KEY_START, aesKey, KEY_LENGTH);
    printBuffer("key: ", aesKey, KEY_LENGTH);
    return true;
  }   
  return false;
}

bool writeConfig(char *mqttSrv, int port, byte *key) {
  if(mqttSrv == NULL || key == NULL) {
    return false;
  } 
  int srvSize = strlen(mqttSrv);
    
  if(mqttPort != 0) { 
    writeIntToEEProm(MQTT_PORT_START, mqttPort);
    writeStrToEEProm(MQTT_SRV_START, mqttSrv, srvSize);
    writeBufToEEProm(KEY_START, key, KEY_LENGTH);    
    logMessage( String("Wrote configuration: ") + mqttSrv + ":" + mqttPort);
    return true;
  }
  return false;
}


void setMqttConfig() {
    if(parseServerIpAddress()) {
      logMessage(String("Connecting to mqtt with IP address: ") + ipToStr(mqttServerIp) + ":" + mqttPort);
      mqttClient.setServer(mqttServerIp, mqttPort);
    } else {
     logMessage(String("Connecting to mqtt with domain: ") + mqttServerDNS);
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
       
  if( packetSize > 0)  { 
      logPacket(packetSize, Udp.remoteIP(), Udp.remotePort(), rcvPacketBuffer); 
   
     if(configAgentIp == Udp.remoteIP() && packetSize > MIN_INIT_PACKET) {
       printBuffer("rcvd config: ", rcvPacketBuffer, packetSize);     
       
       if(validateHeader(rcvPacketBuffer, packetSize)) { 
          mqttPort = ((int) rcvPacketBuffer[INIT_PACKET_PORT_INDEX]) << 8 | rcvPacketBuffer[INIT_PACKET_PORT_INDEX+1];
          memcpy(aesKey, &rcvPacketBuffer[INIT_PACKET_KEY_INDEX], KEY_LENGTH);
          int sizeServer = packetSize - INIT_PACKET_SERVER_INDEX;
          if(sizeServer > 0 && sizeServer < MQTT_SRV_MAX-1) {          
            strncpy(mqttServerDNS, &rcvPacketBuffer[INIT_PACKET_SERVER_INDEX], sizeServer);
            mqttServerDNS[sizeServer] = 0;
            logMessage(String("server: ") + mqttServerDNS + ":" + mqttPort);
            printBuffer("key: ", aesKey, KEY_LENGTH);
          
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
             logMessage("invalid server size, < 0");
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
  setMqttConfig();

  if(connectMqttState()) {
    sendReplyMessage(successMsg, sizeof(successMsg));
  } else {    
    String msg = String("failed connect: ") + mqttServerDNS + ":" + mqttPort;
    int sz = msg.length();
    char *msgToSend = (char *) malloc(sz);
    msg.toCharArray(msgToSend, sz);
    sendReplyMessage(msgToSend, sz);
    free (msgToSend);
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
      String invalidState = String("invalid state: ") + currentState;
      logMessage(invalidState);
      changeState(STATE_INIT);
      break;
  }
}

void handleLockMessage(char *message, int size) {
  StaticJsonBuffer<MAX_JSON_MSG> jsonBuffer;
  JsonObject& msg = jsonBuffer.parseObject(message);
  
  if(!msg.success()) {
    logMessage("failed to parse json");
  } else {
    msg.printTo(Serial);
    bool lockState = (bool) msg["lock"];

    StaticJsonBuffer<JSON_OBJECT_SIZE(3)> send;
    JsonObject& root = jsonBuffer.createObject();
    if(lockState) {
      root["isLocked"] = true;
    } else {
      root["isLocked"] = false;
    }

    root["deviceId"] = deviceId;
    char msg[256];
    int size = root.printTo(msg, 256);
   
    mqttClient.publish(controlTopic, (byte*) msg, size);
    Serial.print("sending: ");
    Serial.println(msg);
  }
}


// Callback function
void callback(char* topic, byte* payload, unsigned int length) {
  // In order to republish this payload, a copy must be made
  // as the original payload buffer will be overwritten whilst
  // constructing the PUBLISH packet.
  
  // Allocate the correct amount of memory for the payload copy
  if(length <= TOTAL_ENCRYPT_SZ) {
  
      int bufLen = length;
        
      Serial.print("mqtt rcv topic:");
      Serial.print(topic);
      Serial.print(" size:");
      Serial.println(length, DEC);
      printBuffer("rcv data:", payload, length);
      
#ifdef ENCRYPT      
      byte plain[bufLen];
      byte plainSize = decryptData(payload, plain, length, bufLen); 
      Serial.print("decrypt buf size: ");
      Serial.println(plainSize);
      printBuffer("decrypted data:", plain, plainSize);      
 
      for(int i = 0; i < plainSize; i++) {
        Serial.print((char) plain[i]);
      }
      handleLockMessage((char*)plain, plainSize);
#else
      handleLockMessage((char*)payload, length);
#endif  
   } else {
      Serial.print("message too big: ");
      Serial.println(length);
   }
}


