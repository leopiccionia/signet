#!/usr/bin/python

#requires: bcrypt, pycrypt

import getpass, os, sys
import bcrypt, base64
from Crypto.Cipher import AES

# Utils

def get_masterkey(password, factor):
	binary_password = password.encode()
	print('Generating master key... It may take some minutes.')
	master_key = bcrypt.hashpw(binary_password, bcrypt.gensalt(factor))
	master_key = bcrypt.kdf(password = binary_password, salt = b'sealed', desired_key_bytes = 32, rounds = factor)
	print('Master key generated.')
	return master_key

def get_factor():
	factor = int(input('Work factor (min = 4; max = 31; default = 18): '))
	return factor if factor and factor > 3 and factor < 32 else 18

def get_password():
	password = getpass.getpass('Password: ')
	repeat_password = getpass.getpass('Please, repeat your password: ')
	while password != repeat_password:
		password = getpass.getpass('Password: ')
		repeat_password = getpass.getpass('Please, repeat your password: ')
	return password

# Packing

def pack(input_path, output_path):
	if not os.path.isdir(input_path):
		sys.stderr.write('Invalid input path: ' + input_path + '.\n')
	elif not os.path.isdir(output_path):
		sys.stderr.write('Invalid output path: ' + output_path + '.\n')
	else:
		master_key = get_masterkey(get_password(), get_factor())
		#print base64.b64encode(master_key)
		pass #TODO

# Unpacking

def unpack(input_path, output_path):
	if not os.path.isdir(input_path):
		sys.stderr.write('Invalid input path: ' + input_path + '.\n')
	elif not os.path.isdir(output_path):
		sys.stderr.write('Invalid output path: ' + output_path + '.\n')
	else:
		pass #TODO

# Treating input

input_path = sys.argv[2] if len(sys.argv) > 2 else '.'
output_path = sys.argv[3] if len(sys.argv) > 3 else '.'

if len(sys.argv) > 1:
	if sys.argv[1] == '-p' or sys.argv[1] == '--pack':
		pack(input_path, output_path)
	elif sys.argv[1] == '-u' or sys.argv[1] == '--unpack':
		unpack(input_path, output_path)
	else:
		sys.stderr.write('Invalid first argument. Should be: -p, --pack, -u, --unpack.\n')
else:
	sys.stderr.write('Invalid number of arguments.\n')