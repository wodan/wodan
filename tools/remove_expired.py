#!/usr/bin/python2.3
import sys, os
import time
from datetime import datetime,timedelta

mindelta = timedelta(seconds=1)

def checkExpired(expireTimeStr):
    parts = expireTimeStr.split()
    expireTimeStr = " ".join(parts[:-1])
    expireTime = datetime.fromtimestamp(time.mktime(time.strptime(expireTimeStr, "%a %d %b %Y %H:%M:%S")))
    if currentTime > expireTime:
        return 1
    else:
        return 0
        
def isExpired(file):
    # first line of cache file holds URL, fourth line hold the expiry time
    fd = open(file, "r")
    for i in range(0,4):
        line = fd.readline()
        if len(line) == 0: return 0
    fd.close()
    return checkExpired(line)

if __name__ == '__main__':

    currentTime = datetime.utcnow()
    nowstr = currentTime.strftime("%a %d %b %Y %H:%M:%S")
    testTime = datetime.fromtimestamp(time.mktime(time.strptime(nowstr, "%a %d %b %Y %H:%M:%S")))
    delta = currentTime - testTime
    assert(delta <= mindelta)
        
    # get cache directory.
    if len(sys.argv) < 2:
        print "usage: %s <cache-directory>" % (os.path.basename(sys.argv[0]))
        sys.exit(-1)
    else:
        cachedir = sys.argv[1]

    if not os.path.isdir(cachedir):
        print cachedir, "is not a directory"
        sys.exit(-1)
        
    # get files in directory
    directories = []
    directories.append(cachedir)
    removedfiles = 0
    try:
        while(1):
            directory = directories.pop()
            files = [os.path.join(directory, f) for f in os.listdir(directory)]
            for file in files:
                if os.path.isdir(file):
                    directories.append(file)
                elif os.path.isfile(file):
                    if isExpired(file):
                        removedfiles += 1
                        os.unlink(file)
                                 
    except IndexError:
        pass

    if removedfiles > 0:
        os.system("/usr/bin/logger -t wodan/gc removed %d files" % (removedfiles))
                    
                
                    
            

        
