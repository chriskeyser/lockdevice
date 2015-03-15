#include <SPI.h>
#include <Ethernet.h>
#include <EEPROM.h>
#include <EthernetUdp.h>
#define UDP_TX_PACKET_MAX_SIZE 128
#include <PubSubClient.h>
#include <avr/pgmspace.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// Values for tracking state of device.
#define STATE_INIT 1
#define STATE_ASSIGNING 2
#define STATE_INITIALIZE_CONFIG 3
#define STATE_TESTING_CONFIG 4
#define STATE_CONNECTING 5
#define STATE_RUNNING 6
#define MAX_IP_STR_LEN 16

byte currentState=STATE_INIT;

// the ports that the initialization protocol will use.
#define BCAST_PORT 9998
#define INIT_SEND 9997

// EEPROM locations
#define START_CONFIG 500
#define MQTT_PORT_START 500
#define MQTT_SRV_START  502
#define MQTT_PORT_MAX  2
#define MQTT_SRV_MAX   97
#define MQTT_CONFIG_END 600
#define END_CONFIG 600

char *deviceId = "lock-00AABBCC1E02";

// This would normaily need to be read from a board setting rather than hardcoding.
byte mac[] = {
  0x00, 0xAA, 0xBB, 0xCC, 0x1E, 0x02
};

// global variables.
IPAddress myIp;
IPAddress configAgentIp;
byte mqttServerIp[4];
char mqttServer[MQTT_SRV_MAX+1];
unsigned int mqttPort;

char packetBuffer[UDP_TX_PACKET_MAX_SIZE+1];

// Callback function header
void callback(char* topic, byte* payload, unsigned int length);

// Network clients to use in processing...
EthernetClient ethClient;
EthernetUDP Udp;

const char *initSig = "LINIT";
const char *initReplySig = "LRPLY";
const char *resetSig = "RST";
const char *delimiter = ":";

byte server[] = { 0, 0, 0, 0 }; // placeholder.
PubSubClient client(server, 1883, callback, ethClient);

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

void logPacket(int packetSize, IPAddress addr, int port, char * data)
{
  Serial.print("Udp rcv: ");
  Serial.print(packetSize);
  Serial.print( " bytes from: ");
  Serial.print(ipToStr(addr));
  Serial.print(":");
  Serial.print(port);
  String msg = String("Udp rcv: ") + packetSize + " bytes from: " + ipToStr(addr) + ":" + port;
  Serial.print("data: ");
  for(int i = 0; i < packetSize; i++) {
    Serial.print(data[i]);
  }
  
  Serial.println();
}

/************
* Functions for working with network interactions.
*/
bool getDhcpAddr() {
  logMessage("GetDhcpAddr: obtaining Address");
  
  if(Ethernet.begin(mac) == 0) {
    logMessage("Failed to configure Ethernet using DHCP");
    return false;
  }
  
  myIp = Ethernet.localIP();
  logMessage(String("My IP address: ") + ipToStr(myIp));
  return true;
}

void udpSendStringPacket(IPAddress dest, int port, String data) {
  logMessage(String("Sending: ") + data);
  int strLength = data.length() + 1;
  char* cdata = (char*)malloc(strLength);  
  data.toCharArray(cdata, strLength);
  Udp.beginPacket(dest, port);
  Udp.write(cdata);
  Udp.endPacket();
  free(cdata);
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

void resetInit(char *msg) {
  changeState(STATE_INIT);
  String tosend = String(resetSig) + ":" + STATE_INIT;
  
  if(msg != NULL) {
    tosend += msg;
  }
  
  udpSendStringPacket(configAgentIp, INIT_SEND, tosend);
  Udp.begin(BCAST_PORT);
}

/**********************
  functions for working with EEPROM
*/
bool writeStrToEEProm(int start, char *data, byte dataSize) {
  if(dataSize == 255) {
    //255 is unwritten value, need to reserve)
    logMessage("attempt to write value to EEProm of 255 bytes");
  }
  
  EEPROM.write(start, dataSize);
  int curPos = start + 1;
  
  for(byte i = 0; i < dataSize; i++)  {
    EEPROM.write(curPos, data[i]);
    curPos++;
  }
}

bool readStrFromEEProm(unsigned int start, char *data, byte maxSize) {
  byte strSize = EEPROM.read(start);
  
  if(strSize == 255) { // not previously written
    return false;
  }
  
  // leave enough room for zero terminating.
  byte readSize = strSize < (maxSize-1) ? strSize : maxSize - 1;
  int curPos = start + 1;
    
  if(readSize < strSize) {
    logMessage(String("var size: ") + strSize + " is greater than max size:" + maxSize + ", only reading partial");
  }

  for(byte i = 0; i < readSize; i++) {
    data[i] = EEPROM.read(curPos);
    curPos++;
  }
  
  data[readSize] = 0;
  return true;
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

bool readConfig() {
  mqttPort = readUIntFromEEProm(MQTT_PORT_START);

  if(mqttPort != UINT_MAX) {
    readStrFromEEProm(MQTT_SRV_START, mqttServer, MQTT_SRV_MAX);
    logMessage( String("Read configuration: ") + mqttServer + ":" +  mqttPort);
    return true;
  }   
  return false;
}


/************
* Functions to help with packet parsing, validation and creation
*/
bool isValidHeader(char *signature, char *stateStr) {
  logMessage(String("signature: ") + signature + " state: " + stateStr);
  
  if(stateStr == NULL || signature == NULL || strncmp(signature, initSig, sizeof(initSig)) != 0) {
    logMessage("state missing from packet header, resetting to init");
    changeState(STATE_INIT);
    return false;
  }
  
  String s = String(stateStr);
  int state = s.toInt();
  
  if(state != currentState) {
    logMessage(String("invalid state, expected: ") + currentState + " got: " + state + "restarting...");
    changeState(STATE_INIT);
    return false;
  }
}

String makeReply(char *content) {
  String replyMsg = String(initReplySig) + delimiter + currentState;
  if(content != NULL) {
    replyMsg += delimiter;
    replyMsg += content;
  }
  return replyMsg;
}



bool parseServerIpAddress() {
  int partCnt;
  char *current = mqttServer;
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

/*****
*  Functions to process states.
*/
void initializeState() {
  if(getDhcpAddr()) {
    if(!readConfig()) {
      changeState(STATE_ASSIGNING);
      Udp.begin(BCAST_PORT);
    } else {
      // check if IP address, if so then initiate with ip else initiate with dns.
      if(parseServerIpAddress()) {
        logMessage(String("Connecting to mqtt with IP address: ") + ipToStr(mqttServerIp) + ":" + mqttPort);
        client.setServer(mqttServerIp, mqttPort);
      } else {
       logMessage(String("Connecting to mqtt with domain: ") + mqttServer);
        client.setServer(mqttServer, mqttPort);        
      }
      changeState(STATE_CONNECTING);
    }
  }
}

void assignState() {
  //TODO: will want to check config to see if already configured.  
  int packetSize = Udp.parsePacket();
  
  if( packetSize > 0)  {
    configAgentIp = Udp.remoteIP();
    Udp.read(packetBuffer,UDP_TX_PACKET_MAX_SIZE);
    logPacket(packetSize, configAgentIp, Udp.remotePort(), packetBuffer);
    String msg = String(packetBuffer);
    
    if(msg.startsWith(initSig)){
      String replyMsg = makeReply(deviceId);
      logMessage(replyMsg);
      udpSendStringPacket(configAgentIp, INIT_SEND, replyMsg);
      changeState(STATE_INITIALIZE_CONFIG);
    }
  }
}

bool saveConfig(char *mqttSrv, char * mqttPortStr) {
  
  int srvSize = strlen(mqttSrv);
  String port = String(mqttPortStr);
  mqttPort = port.toInt();  //safer than atoi
  strncpy(mqttServer, mqttSrv, MQTT_SRV_MAX);
  mqttServer[MQTT_SRV_MAX] = 0;

  if(mqttPort == 0) {
    return false;
  }
    
  if(srvSize < MQTT_SRV_MAX && mqttPort != 0) { 
    writeIntToEEProm(MQTT_PORT_START, mqttPort);
    writeStrToEEProm(MQTT_SRV_START, mqttSrv, srvSize);
    logMessage( String("Wrote configuration: ") + mqttSrv + ":" + mqttPort);
    return true;
  }
  
  return false;
}

void configState() {
  int packetSize = Udp.parsePacket();
    
  if( packetSize > 0)  {
     Udp.read(packetBuffer,UDP_TX_PACKET_MAX_SIZE);
     
     //ensure safety set for strtok with null terminate.
     packetBuffer[UDP_TX_PACKET_MAX_SIZE] = 0;
     logPacket(packetSize, Udp.remoteIP(), Udp.remotePort(), packetBuffer); 
     
     if(configAgentIp == Udp.remoteIP()) {
       logMessage(String("rcvd config packet: ") + packetBuffer);
       
       char *signature = strtok(packetBuffer, delimiter);
       char *state = strtok(NULL, delimiter);
       
       if(isValidHeader(signature, state)) {
         char *mqttSrv = strtok(NULL, delimiter);
         char *mqttPortStr = strtok(NULL, delimiter);
         
         if(mqttSrv == NULL || mqttPortStr == NULL) {
           logMessage("getConfig::invalid config packet, restarting config sequence");
           resetInit("missing server or port string");
         } else {
           if(saveConfig(mqttSrv, mqttPortStr)) {
             logMessage( "config completed");
             changeState(STATE_TESTING_CONFIG);
             makeReply(NULL);
           } else {
              resetInit("Save failed for data");            
           }
         }
       } else {
         logMessage( "Invalid config packet, restarting config sequence");
         resetInit("invalid header received");
       }
     }
  }
}

void testMqttState() {
  if(connectMqttState()) {
    makeReply("success");
  } else {
    String msg = String("failed: ") + mqttServer + ":" + mqttPort;
    unsigned int sz = msg.length()+1;    
    char msgToSend[sz];
    msg.toCharArray(msgToSend, sz);
    makeReply(msgToSend);
  }
}

bool connectMqttState() {
  logMessage("attempting to communicate with mqtt server");
  if (client.connect("locker")) {
    client.publish("register",deviceId);
    client.subscribe("lock");
    changeState(STATE_RUNNING);
  } else {
      logMessage("failed to connect with mqtt server");
      delay(2000);
  }
}

void runState() {
  delay(500);
  client.loop();
}

void setup() {
  packetBuffer[UDP_TX_PACKET_MAX_SIZE] = 0;  // safety termination for strings.
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

// Callback function
void callback(char* topic, byte* payload, unsigned int length) {
  // In order to republish this payload, a copy must be made
  // as the orignal payload buffer will be overwritten whilst
  // constructing the PUBLISH packet.
  
  // Allocate the correct amount of memory for the payload copy
  byte* p = (byte*)malloc(length);
  
  // Copy the payload to the new buffer
  memcpy(p,payload,length);
  client.publish("echoTopic", p, length);
  
  Serial.print("received message:");
  Serial.print(topic);
  Serial.print(" ,length: ");
  Serial.println(length, DEC);
  free(p);
}

