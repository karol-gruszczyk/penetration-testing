#define OSX 0
#define WINDOWS 1
#define UBUNTU 2

#include "Keyboard.h"

int platform = UBUNTU;

void setup() {
}

void loop() {
  delay(1000);

  switch (platform) {
    case OSX:
      break;
    case WINDOWS:
      break;
    case UBUNTU:
      // CTRL-ALT-T:
      Keyboard.press(KEY_LEFT_CTRL);
      Keyboard.press(KEY_LEFT_ALT);
      Keyboard.press(KEY_T);
      Keyboard.releaseAll();
      delay(1000);

      Keyboard.print("echo lol");
      Keyboard.press(KEY_RETURN);
      Keyboard.releaseAll();
      break;
  }
}
