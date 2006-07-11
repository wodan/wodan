#!/usr/bin/env python

import cgi
import socket
import urlparse
import os
import shutil

import hostconfig

class CGIOutput:
    def __init__(self):
        self.content = "Content-Type: text/html\n\n"
        headerfile = open("header.html")
        header = headerfile.read()
        headerfile.close()
        self.content += header
        

    def add(self, str):
        self.content = self.content + str + "\n"

    def finish(self):
        footerfile = open("footer.html")
        footer = footerfile.read()
        footerfile.close()
        self.content += footer
        
    def __repr__(self):
        
        return self.content


class Purger:
    def __init__(self):
        pass

    def purge(self):
        pass

class LocalPurger:
    """
    Purger for the local cache directories
    """
    def __init__(self, cachedir):
        self.cachedir = cachedir
        if not os.path.isdir(self.cachedir):
            raise Exception, "%s is not a directory!" % (self.cachedir)
        
    def purge(self):
        for file in os.listdir(self.cachedir):
            file = os.path.join(self.cachedir, file)
            if os.path.isdir(file):
                shutil.rmtree(file, 1)
            else:
                try:
                    os.remove(file)
                except Exception:
                    pass

class RemotePurger:
    def __init__(self, address, port):
        self.address = address
        self.port = port

    def purge(self):
        my_url = "http://%s?only_local=yes" % (os.environ['HTTP_HOST'])
        host = os.environ['HTTP_HOST']
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.address, self.port))	
		s.send("GET %s HTTP/1.1\n" % (my_url))
		s.send("Host: %s\n" % (host))
		s.close()
	except socket.error:
		pass

def getVirtualHostDomain():
    servername = os.environ['HTTP_HOST']
    return ".".join(servername.split('.')[1:])

def getVirtualHostShortName():
    servername = os.environ['HTTP_HOST']
    parts = servername.split('.')
    return parts[0]

def makePurgeLink(purgeURL, hostname, out):
    out.add("<div class=\"host\">")
    out.add("<a href=\"http://%s\">%s</a><br />" % (purgeURL,
                                                    hostname))
    out.add("</div>")
    
    
def makePurgeLinksPage(purgeHosts, out):
    out.add("<p>Kies een van de links hieronder om een website te purgen:</p>")
    hostKeys = purgeHosts.keys()
    hostKeys.sort()
    for hostKey in hostKeys:
        host = purgeHosts[hostKey]
        if allowedToPurge(host.shortname):
        	purgeURL = host.shortname + '.' + getVirtualHostDomain()
		makePurgeLink(purgeURL, host.hostname, out)

def allowedToPurge(hostShortname):
    """
    returns true if:
    
    1. the remote host's address is configured as a <purgeHost> in the
    global config.
    2. the remote host's address has an <allowedHost> field in the global config
    3. the remote host's address has an <allowedHost> field in the virtual host
    config.
    4. the remote username has an <allowedUser> field in the global config
    """
    remoteHost = os.environ['REMOTE_ADDR']
    
    # is remoteHost a purgeHost?
    for purgeHost in configReader.config['purgeHosts']:
        if remoteHost == purgeHost.address:
            return 1

    # is remoteHost configured as allowedHost?
    if (remoteHost in configReader.config['allowedHosts'] or
        remoteHost in configReader.getVirtualHost(hostShortname).allowedHosts):
        return 1

    # is remoteUser configured as allowedUser?
    try:
        remoteUser = os.environ['REMOTE_USER']
        if (remoteUser in configReader.config['allowedUsers'] or
            remoteUser in configReader.getVirtualHost(hostShortname).allowedUsers):
            return 1
    except KeyError:
        pass

    # no matches, so 0 is returned.
    return 0
    
    
parameters = cgi.FieldStorage()
configReader = hostconfig.HostConfigReader()

out = CGIOutput()

hostname = os.environ['HTTP_HOST']
if hostname == configReader.getMainPurgeSiteName():
    # show page for all configured sites
    makePurgeLinksPage(configReader.config['virtualHosts'], out)
else:
    if allowedToPurge(getVirtualHostShortName()):
        cachedir = configReader.getCacheDir(getVirtualHostShortName())
        hostname = configReader.getHostname(getVirtualHostShortName())

		# if needed, purge other purge hosts.
        if (not parameters.has_key('only_local') or
            parameters['only_local'].value != "yes"):
            other_hosts = configReader.config['purgeHosts']
            for host in other_hosts:
                rp = RemotePurger(host.address, host.port)
                rp.purge()
            
            out.add("<p>De cache van %s is ge-purged.</p>" % (hostname))
		
		# now purge the local cache dir.
        purger = LocalPurger(cachedir)
        purger.purge()


    else:
        # not allowed to purge
        out.add("<p>%s</p>" %
                (configReader.getHostname(getVirtualHostShortName())))
        out.add("<p>Je hebt niet de rechten om deze site te purgen.</p>")

out.finish()
print out
