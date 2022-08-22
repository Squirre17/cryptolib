import math as math
import base64 as b64


def f(x, i):
	return x ^ 0xdeedbeafdeedbeaf ^ ( i * 114514)

def OFB():
	msg = [0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444]
	print(f"Original msg is {msg}")
	for i in msg:
		assert (i >> 64) == 0
	iv = 0xffffffffffffffff
	dmsg = []

	# CFB encrypt now
	r = f(iv, 0) 
	dmsg.append(r ^ msg[0])
	for i in range(1, len(msg)):
		r = f(r, i) 
		dmsg.append(r ^ msg[i])
	
	print(f"Encrypted msg is {dmsg}")

	# CFB decrypt now
	msg = []
	r = f(iv, 0) 	
	msg.append(r ^ dmsg[0])
	for i in range(1, len(dmsg)):
		r = f(r, i) 
		msg.append(r ^ dmsg[i])

	print(f"Decrypted msg is {msg}")

OFB()