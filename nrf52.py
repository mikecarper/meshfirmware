#!/usr/bin/env python3

import sys
import time
import serial

# The special baud rate that triggers the bootloader
DFU_TOUCH_BAUD = 1200
# Time to wait after opening the port before closing it (in seconds)
SERIAL_PORT_OPEN_WAIT_TIME = 0.1
# Time to wait for the device to reset into DFU mode (in seconds)
TOUCH_RESET_WAIT_TIME = 1.5 

def force_dfu_mode(port_name):
    """
    Opens and closes a serial port at 1200 baud to force some
    microcontrollers (like certain Arduino or Adafruit models) into
    their DFU/bootloader mode.

    Args:
        port_name (str): The name of the serial port (e.g., COM3, /dev/ttyACM0)
    """
    print(f"--- Attempting to force DFU mode on {port_name} ---")

    try:

        print(f"Opening {port_name} at {DFU_TOUCH_BAUD} baud...")
        with serial.Serial(port_name, baudrate=DFU_TOUCH_BAUD) as ser:
            print("Port opened successfully.")

            time.sleep(SERIAL_PORT_OPEN_WAIT_TIME)

            print("Closing port...")
        print("Port closed.")

    except serial.SerialException as e:
        print(f"\nError: Could not access serial port '{port_name}'.")
        print(f"Details: {e}")
        print("Please check the following:")
        print("  - The device is connected.")
        print("  - The port name is correct.")
        print("  - You have the necessary permissions to access the port.")
        print("  - No other program (like a Serial Monitor) is using the port.")
        sys.exit(1)

    print(f"Waiting {TOUCH_RESET_WAIT_TIME} seconds for the device to enumerate in DFU mode...")
    time.sleep(TOUCH_RESET_WAIT_TIME)

    print("\n--- Operation complete. The device should now be in DFU mode. ---")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        script_name = sys.argv[0]
        print("Error: No serial port specified.")
        print(f"\nUsage: python {script_name} <SERIAL_PORT>")
        print(f"\nExample (Windows):    python {script_name} COM3")
        print(f"Example (Linux):      python {script_name} /dev/ttyACM0")
        print(f"Example (macOS):      python {script_name} /dev/cu.usbmodem1234")
        sys.exit(1)

    force_dfu_mode(sys.argv[1])
    
