import math as math
import base64 as b64
import argparse
import os as os
# one group per eight byte
def f(x):
	return x ^ 0xdeedbeafdeedbeaf
def CFB():
	msg = [0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444]
	print(f"Original msg is {msg}")
	for i in msg:
		assert (i >> 64) == 0
	iv = 0xffffffffffffffff
	dmsg = []

	# CFB encrypt now
	r = msg[0] ^ f(iv)
	dmsg.append(r)
	for i in range(1, len(msg)):
		r = f(dmsg[i-1]) ^ msg[i]
		dmsg.append(r)
	
	print(f"Encrypted msg is {dmsg}")

	# CFB decrypt now
	r = dmsg[0] ^ f(iv)
	msg = []
	msg.append(r)
	for i in range(1, len(dmsg)):
		r = dmsg[i] ^ f(dmsg[i-1])
		msg.append(r)
	print(f"Decrypted msg is {msg}")

CFB()


