#!/usr/bin/env python3

from gpiozero import LED
import time

# Define the GPIO pins to use and create an LED object for each pin.
# (You can use LED class for generic on/off control even if you're not using an LED)
pins = [4, 17, 27, 22]
leds = [LED(pin) for pin in pins]

try:
    # Turn all "LEDs" on
    for led, pin in zip(leds, pins):
        led.off()
        print(f"GPIO {pin} turned OFF")
        time.sleep(0.05)
    time.sleep(3)  # Keep them on for 3 seconds

    # Turn all "LEDs" off
    for led, pin in zip(leds, pins):
        led.on()
        print(f"GPIO {pin} turned ON")
        time.sleep(0.05)

finally:
    # Optionally, gpiozero cleans up automatically when the objects are deleted.
    print("Script complete.")
