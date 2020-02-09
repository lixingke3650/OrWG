#! python3

import random

WG_DEVICE_SBOX_SIZE = 256
INLINE = 4
Pool = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]

print("static __le32 SBox[WG_DEVICE_SBOX_SIZE] = {")
for _ in range(int(WG_DEVICE_SBOX_SIZE/INLINE)):
	print("    ", end="")
	temp = random.choice(Pool) + random.choice(Pool) + random.choice(Pool) + random.choice(Pool)
	print("0x" + temp + ", ", end="")
	temp = random.choice(Pool) + random.choice(Pool) + random.choice(Pool) + random.choice(Pool)
	print("0x" + temp + ", ", end="")
	temp = random.choice(Pool) + random.choice(Pool) + random.choice(Pool) + random.choice(Pool)
	print("0x" + temp + ", ", end="")
	temp = random.choice(Pool) + random.choice(Pool) + random.choice(Pool) + random.choice(Pool)
	print("0x" + temp + ",")
print("};")