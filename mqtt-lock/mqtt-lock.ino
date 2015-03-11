#include <SPI.h>
#include <Ethernet.h>
#include <PubSubClient.h>
#include <avr/pgmspace.h>

#define STATE_INIT 1
#define STATE_ASSIGNING 2
#define STATE_CONNECTING 3
#define STATE_RUNNING 4

// gateway and subnet are optional:
byte mac[] = {
  0x00, 0xAA, 0xBB, 0xCC, 0x1E, 0x02
};

byte server[] = { 54, 172, 208, 237 };
IPAddress ip;

byte state=STATE_INIT;

// Callback function header
void callback(char* topic, byte* payload, unsigned int length);

EthernetClient ethClient;
PubSubClient client(server, 9999, callback, ethClient);

boolean gotAMessage = false; // whether or not you got a message from the client yet
char *name = {"lock-cl-DEEDBAFEFEEF"};

bool getDhcpAddr() {
  // start the Ethernet connection:
  Serial.println("Trying to get an IP address using DHCP");
  if(Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    return false;
  }
  
  // print your local IP address:
  Serial.print("My IP address: ");
  ip = Ethernet.localIP();
  for (byte thisByte = 0; thisByte < 4; thisByte++) {
    // print the value of each byte of the IP address:
    Serial.print(ip[thisByte], DEC);
    Serial.print(".");
  }
  
  Serial.println();
  return true;
}

void setup() {
  // Open serial communications and wait for port to open:
  Serial.begin(9600);
}

void initialize() {
  if(getDhcpAddr()) {
    state = STATE_ASSIGNING;
  }
}

void assign() {
  //TODO: UDP to obtain server addr.
  state = STATE_CONNECTING;
}

void connectMqtt() {
    Serial.println("attempting to communicate with mqtt server");
  if (client.connect("locker")) {
    client.publish("register",name);
    client.subscribe("lock");
    state = STATE_RUNNING;
  } else {
      Serial.println("failed to connect with mqtt server");
  }
}

void loop() {
  switch(state)
  {
    case STATE_INIT:
      Serial.println("intializing");
      initialize();
      break;
    case STATE_ASSIGNING:
      Serial.println("assigning");
      assign();
      break;
    case STATE_CONNECTING:
      Serial.println("connecting");
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
      state = STATE_INIT;
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
