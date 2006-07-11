#!/usr/bin/env python

# Dit script kan gebruikt worden om van cachefiles weer gewone files te maken. 
# Een cachefile voor /media/pdf/file.pdf wordt dan dus weer een gewone pdf file.
# het script verwacht het volgende:
# een directory cachefiles met daaronder directory per site, bijvoobeeld:
# cachefiles/www.playboy.nl/
# cachefiles/www.kijk.nl/
# etc.
# In de directory 'recovered/' worden de files van elke site neergezet, bijvoorbeeld onder
# recovered/www.kijk.nl

import os
import os.path


CACHEFILEDIR = 'cachefiles'
RECOVERDIR = 'recovered'

def getSiteList():
	return os.listdir(CACHEFILEDIR)
	
def createFileList(dirname):
	fileList = os.listdir(dirname)
	cflist = []
	for filename in fileList:
		filename = os.path.join(dirname, filename)
		if os.path.isdir(filename):
			cflist += createFileList(filename)

		else:
			cflist.append(filename)
	
	return cflist

sites = getSiteList()
print sites

for site in sites:
	rootdir = os.path.join(RECOVERDIR, site)
	try:
		os.makedirs(rootdir)
	except OSError:
		pass
	cachefiles = createFileList(os.path.join(CACHEFILEDIR, site))
	for cachefilename in cachefiles:
		cachefile = open(cachefilename, 'r')
		path = cachefile.readline().strip()[1:]
		if path[0] == '/':
			path = path[1:]

		dir = os.path.join(rootdir, os.path.split(path)[0])
		try:
			os.makedirs(dir)
		except OSError:
			pass
	
		newfile = open(os.path.join(rootdir, path), 'w')
	
		# go past headers:
		while 1:
			line = cachefile.readline()
			if line == '\r\n' or line == '\n':
				break
		# copy file
		readbytes = cachefile.read()
		newfile.write(readbytes)

		cachefile.close()
		newfile.close()
	
	
	
	
