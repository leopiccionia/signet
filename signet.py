#!/usr/bin/python

#requires: bcrypt, pycrypt

import getpass, os, sys
import tarfile
import bcrypt
from Crypto.Cipher import AES

# Utils

def get_factor():
	factor = int(input('Work factor (min = 4; max = 31; default = 18): '))
	return factor if factor and factor > 3 and factor < 32 else 18

def get_files(dir):
	files_list = []
	for root, subdirs, filenames in os.walk(dir):
		for filename in filenames:
			files_list.append(os.path.join(root, filename))
	return files_list

def get_masterkey(password, factor):
	binary_password = password.encode()
	print('Generating master key... It may take some minutes.')
	master_key = bcrypt.hashpw(binary_password, bcrypt.gensalt(factor))
	master_key = bcrypt.kdf(password = binary_password, salt = b'sealed', desired_key_bytes = 32, rounds = factor)
	print('Master key generated.')
	return master_key

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
		sys.stderr.write('Invalid directory: ' + input_path + '.\n')
	elif not os.path.isdir(output_path):
		sys.stderr.write('Invalid directory: ' + output_path + '.\n')
	else:
		master_key = get_masterkey(get_password(), get_factor())
		with tarfile.open('signet.tar.gz', 'w:gz') as tar:
			for name in get_files(input_path):
				tar.add(name)
		tar_file = open('signet.tar.gz', 'r')
		aes = AES.new(master_key, AES.MODE_CTR, counter = lambda: 'sealed0123456789')
		cipher = aes.encrypt(tar_file.read())
		pass #TODO

# Unpacking

def unpack(input_path, output_path):
	if not os.path.isdir(input_path):
		sys.stderr.write('Invalid directory: ' + input_path + '.\n')
	elif not os.path.isdir(output_path):
		sys.stderr.write('Invalid directory: ' + output_path + '.\n')
	else:
		pass #TODO

# Handling input from console

def main(args = sys.argv[1:]):
	input_path = args[1] if len(args) > 1 else os.path.expanduser('~')
	output_path = args[2] if len(args) > 2 else os.path.expanduser('~')
	if len(args) > 0:
		if args[0] == '-p' or args[0] == '--pack':
			pack(input_path, output_path)
		elif args[0] == '-u' or args[0] == '--unpack':
			unpack(input_path, output_path)
		else:
			sys.stderr.write('Invalid first argument. Should be: -p, --pack, -u, --unpack.\n')
	else:
		sys.stderr.write('Invalid number of arguments.\n')

if __name__ == '__main__':
	main()
