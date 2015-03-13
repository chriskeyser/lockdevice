#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#include <PubSubClient.h>
#include <avr/pgmspace.h>

#define STATE_INIT 1
#define STATE_ASSIGNING 2
#define STATE_GET_CONFIG 3
#define STATE_CONNECTING 4
#define STATE_RUNNING 5
#define INIT_PORT 9998

// gateway and subnet are optional:
byte mac[] = {
  0x00, 0xAA, 0xBB, 0xCC, 0x1E, 0x02
};

byte server[] = { 54, 172, 208, 237 };
IPAddress myIp;
IPAddress initIp;
IPAddress mqttServerIp;

byte state=STATE_INIT;
char packetBuffer[UDP_TX_PACKET_MAX_SIZE+1];

// Callback function header
void callback(char* topic, byte* payload, unsigned int length);

EthernetClient ethClient;
EthernetUDP Udp;
PubSubClient client(server, 9999, callback, ethClient);

char *deviceId = "lock-cl-DEEDBAFEFEEF";
char *initSig = "LINIT";
char *initReplySig = "LRPLY";

void printIP(IPAddress addr) {
  for (byte thisByte = 0; thisByte < 4; thisByte++) {
    // print the value of each byte of the IP address:
    Serial.print(addr[thisByte], DEC);
    Serial.print(".");
  }  
}

void logPacket(int packetSize, IPAddress addr, int port, char * data)
{
    Serial.print(">>>> Udp rcv: ");
    Serial.println(packetSize);
    Serial.print("bytes From ");
    initIp = Udp.remoteIP();
    printIP(initIp);
    Serial.print(":");
    Serial.println(port);
    
    for(int i = 0; i < packetSize; i++) {
      Serial.print(data[i]);
    }
    
    Serial.println("<<<<");
}

bool getDhcpAddr() {
  // start the Ethernet connection:
  Serial.println("GetDhcpAddr: obtaining Address");
  if(Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    return false;
  }
  
  // print your local IP address:
  Serial.print("My IP address: ");
  myIp = Ethernet.localIP();
  printIP(myIp); 
  Serial.println();
  return true;
}

void udpSendStringPacket(IPAddress dest, int port, String data) {
  int strLength = data.length() + 1;
  char* cdata = (char*)malloc(strLength);  
  data.toCharArray(cdata, strLength);
  Udp.beginPacket(dest, port);
  Udp.write(cdata);
  Udp.endPacket();
  free(cdata);
}   
 
void changeState(byte newState) {
  Serial.print("changing state from: ");
  Serial.print(state);
  Serial.print(" to: ");
  Serial.print(newState);
  Serial.println();
  state = newState;
}

void setup() {
  packetBuffer[UDP_TX_PACKET_MAX_SIZE] = 0;
  Serial.begin(9600);
}

void initialize() {
  if(getDhcpAddr()) {
    changeState(STATE_ASSIGNING);
    Udp.begin(INIT_PORT);
  }
}

void assign() {
  //TODO: will want to check config to see if already configured.  
  int packetSize = Udp.parsePacket();
  
  if( packetSize > 0)  {
    initIp = Udp.remoteIP();
    Udp.read(packetBuffer,UDP_TX_PACKET_MAX_SIZE);
    logPacket(packetSize, initIp, Udp.remotePort(), packetBuffer);   
    String msg = String(packetBuffer);
    if(msg.startsWith(initSig)){
      String replyMsg = String(initReplySig);
      replyMsg += ":";
      replyMsg += deviceId;
       udpSendStringPacket(initIp, INIT_PORT, replyMsg );
       changeState(STATE_GET_CONFIG);
    }
  }
}

void getConfig() {
  int packetSize = Udp.parsePacket();
  
  if( packetSize > 0)  {
     Udp.read(packetBuffer,UDP_TX_PACKET_MAX_SIZE);
     logPacket(packetSize, Udp.remoteIP(), Udp.remotePort(), packetBuffer); 
     if(initIp == Udp.remoteIP()) {
         Serial.println("rcvd config packet");
     }
  }
}

void connectMqtt() {
    Serial.println("attempting to communicate with mqtt server");
  if (client.connect("locker")) {
    client.publish("register",deviceId);
    client.subscribe("lock");
    changeState(STATE_RUNNING);
  } else {
      Serial.println("failed to connect with mqtt server");
  }
}

void loop() {
  switch(state)
  {
    case STATE_INIT:
      initialize();
      break;
    case STATE_ASSIGNING:
      assign();
      break;
    case STATE_GET_CONFIG:
       getConfig();
       break;
    case STATE_CONNECTING:
      connectMqtt();
      break;
    case STATE_RUNNING:   
      delay(500);
      client.loop();
      break;
    default:
      Serial.println();
      Serial.print("invalid state: ");
      Serial.print(state, HEX);
      Serial.println();
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
