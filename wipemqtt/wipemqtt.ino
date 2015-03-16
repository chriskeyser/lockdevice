#include <EEPROM.h>

#define START_CONFIG 500
#define END_CONFIG 600

void setup() {
  Serial.begin(9600);
    
  bool isReset = true;
  
  for(int i = START_CONFIG; i < END_CONFIG; i++) {
     byte b = EEPROM.read(i);  
     if(b != 255) {
       Serial.print("need to clear @ byte ");
       Serial.println(b);
       isReset = false;
       break;
     }
  }
  
  if(isReset == true) {
    Serial.println("already reset...");
  } else {
    for(int i = START_CONFIG; i < END_CONFIG; i++) {
      EEPROM.write(i, 255);
    }
  }
  Serial.println("done reset");
}

void loop() {
  // put your main code here, to run repeatedly:
}
