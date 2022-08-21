import math as math
import base64 as b64
import argparse
import os as os
# one group per eight byte
global grp_num
def str2num(x:str):
	num = 0
	for i in range(0, len(x)):
		num = (num << 8) + ord(x[i])
	return num

def num2str(x):
	assert x <= 0xffffffffffffffff
	s = ""
	while(x > 0):
		s = chr(x & 0xff) + s
		x >>= 8
	return s

def num2byte(x):
	return x.to_bytes(8 ,"little")

def byte2num(x):
	return int.from_bytes(x, "little")

def f(x):
	return x ^ 0xdeedbeafdeedbeaf

class CBC:
	def encrypt(self, pmsg_list: list, iv) -> list:
		dmsg_list = []
		dmsg_list.append(f(pmsg_list[0] ^ iv))
		for i in range(1, grp_num):
			r = f(dmsg_list[i-1] ^ pmsg_list[i])
			dmsg_list.append(r)
		return dmsg_list # number list

	def decrypt(self, dmsg_list: list, iv) -> list:
		pmsg_list = []
		grp_num = len(dmsg_list)
		pmsg_list.append(iv ^ f(dmsg_list[0]))
		for i in range(1, grp_num):
			r = dmsg_list[i-1] ^ f(dmsg_list[i])
			pmsg_list.append(r)
		return pmsg_list # number list
	
	def encrypt2base64(self, pmsg_list: list, iv):
		dmsg_list = self.encrypt(pmsg_list ,iv)# problem
		dmsg_str_list = list(map(lambda x: num2byte(x), dmsg_list))
		s = b"".join(dmsg_str_list)
		return b64.b64encode(s).decode()# base64 can decode byte corrently
	
	def base642decrypto(self, s: str, iv):
		s = b64.b64decode(s.encode())# don't decode , deal with bytes
		assert len(s) % 8 == 0

		pmsg_list = []
		for i in range(0, len(s), 8):
			pmsg_list.append(byte2num(s[i:i+8]))
		pmsg_list = self.decrypt(pmsg_list ,iv)
		
		pmsg_list = list(map(lambda x: num2str(x), pmsg_list))
		s = "".join(pmsg_list)
		return s

def padding(s):
	global grp_num
	grp_num = math.ceil(len(s) / 8)
	return s + (grp_num * 8 - len(s)) * '='

def test1():
	msg = "KFC_v_me_50"
	iv = 0xffffffffffffffff
	msg = padding(msg)
	assert len(msg) % 8 == 0

	pmsg_list = []
	for i in range(0, len(msg), 8):
		pmsg_list.append(msg[i :i+8])
	pmsg_list = list(map(lambda x: str2num(x), pmsg_list))
	c = CBC()
	res = c.decrypt(c.encrypt(pmsg_list, iv), iv)
	res = list(map(lambda x: num2str(x), res))
	print(res)

def test2():
	msg = "KFC_v_me_50"
	# msg = "1111111111111111"
	iv = 0xffffffffffffffff
	# iv = 0x0
	msg = padding(msg)
	print(msg)
	assert len(msg) % 8 == 0
	pmsg_list = []
	for i in range(0, len(msg), 8):
		pmsg_list.append(msg[i:i+8])
	# problem is there , padding \x00 cant be handled by str2num, so use '='
	pmsg_list = list(map(lambda x: str2num(x), pmsg_list))

	c = CBC()
	res = c.encrypt2base64(pmsg_list, iv)
	print("base64 result is " + res)
	res = c.base642decrypto(res, iv)
	print("decrypto msg is " + res)

def input2msg(x : str):
	msg = padding(x)
	print(msg)
	assert len(msg) % 8 == 0
	pmsg_list = []
	for i in range(0, len(msg), 8):
		pmsg_list.append(msg[i:i+8])
	# problem is there , padding \x00 cant be handled by str2num, so use '='
	pmsg_list = list(map(lambda x: str2num(x), pmsg_list))
	return pmsg_list

if __name__ == '__main__':
	ap = argparse.ArgumentParser()
	print('''
		\033[34mUsage :\033[0m python3 CBC.py -e <message you want to send> -k <secret key>
		\033[34mOr    :\033[0m python3 CBC.py -d <message you want to decrypt> -k <secret key>
	''')
	ap.add_argument('-e','--encrypto',help='encrypto a message',default=None)
	ap.add_argument('-d','--decrypto',help='decrypto a message', default=None)
	ap.add_argument('-k','--key',help='symmetrical key(decimal number plz)')

	args = ap.parse_args()
	e = args.encrypto
	d = args.decrypto
	key = int(args.key)
	pmsg_list = []

	c = CBC()
	if (e == None and d == None) or (e != None and d != None):
		print("\033[31mYOU ONLY CAN SPECIFIC ONE MODE FROM ENC OR DEC!\033[0m")
		os.exit(1)
	elif e != None:
		pmsg_list = input2msg(e)
		r = c.encrypt2base64(pmsg_list, key)
		print("Your encrypted message is : " + r)
	elif d != None:
		r = c.base642decrypto(d, key)
		print("Your decrypted message is : " + r)
	

