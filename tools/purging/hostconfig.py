#!/usr/bin/env python

"""
hostconfig.py

read configuration for a purge config. The purge config file is
an XML-file, so we use a simple SAX Parser to parse it.

2004-01-10, Ilja Booij, ilja@ic-s.nl
"""
import xml.sax
import xml.sax.handler
import string
import os
import os.path

class VirtualHost:
    """
    Holds the information on the cache of one Virtual Host.
    """

    def __init__(self, hostname, shortname, cachedir):
        """
        create a new Virtual host.
        """
        self.hostname = hostname
        self.shortname = shortname
        self.cachedir = cachedir
        self.allowedHosts = [] # list of hosts that are allowed to purge this virtualHost
        self.allowedUsers = [] # list of users that are allowed to purge this virtualHost

class PurgeHost:
    """
    Holds the information on a purge host.

    A purge host is a host in the network that has a cache that can be in need
    of purging.
    """
    def __init__(self, address, port = 80):
        """
        construct a new PurgeHost
        """
        self.address = address
        self.port = port
        

def normalize_whitespace(text):
    """
    Remove redundant whitespace from a string
    """
    return ' '.join(text.split())

def isInt(i):
    """
    check if a variable is an int.
    """
    try:
        val = int(i)
    except ValueError:
        return 0
    else:
        return 1

class HostConfigContentHandler(xml.sax.handler.ContentHandler):
    """
    Content handler for purge-config.xml
    """
    def __init__(self):
        """
        initialize all fields in the handler
        """
        self.virtualHosts = {}
        self.purgeHosts = []
        self.allowedHosts = []
        self.allowedUsers = []
        self.defaultCachedir = ""
        self.inHostConfig = ''

    def startElement(self, name, attrs):
        """
        handle a start-element. e.g. <host> or <purgeHost>
        """
        if name == 'host':
            hostname = normalize_whitespace(attrs.get('hostname', ""))
            shortname = normalize_whitespace(attrs.get('shortname', ""))
            cachedir = normalize_whitespace(attrs.get('dir', ""))

            host = VirtualHost(hostname, shortname, cachedir) 
            self.virtualHosts[shortname] = host
	    self.inHostConfig = shortname
        elif name == 'purgeHost':
            address = normalize_whitespace(attrs.get('address', ""))
            port = normalize_whitespace(attrs.get('port', ""))
            if isInt(port):
                port = int(port)
                host = PurgeHost(address, port)
            else:
                host = PurgeHost(address)
            self.purgeHosts.append(host)
        elif name == 'defaultCachedir':
            self.defaultCachedir = normalize_whitespace(attrs.get('dir'))
        elif name == 'mainPurgeHost':
            self.mainPurgeHostname = normalize_whitespace(attrs.get('hostname'))
        elif name == 'allowedHost':
            address = normalize_whitespace(attrs.get('address', ""))
            if self.inHostConfig != '':
                self.virtualHosts[self.inHostConfig].allowedHosts.append(address)
            else:
                self.allowedHosts.append(address)
        elif name == 'allowedUser':
            user = normalize_whitespace(attrs.get('name', ''))
            if self.inHostConfig != '':
                self.virtualHosts[self.inHostConfig].allowedUsers.append(user)
            else:
                self.allowedUsers.append(user)
                
    def endElement(self, name):
        """
        handle end of element. e.g. </host>
        """
        if name == 'host':
		    self.inHostConfig = ''

    def getVirtualHosts(self):
        """
        get all virtual hosts
        """
        return self.virtualHosts

    def getPurgeHosts(self):
        """ 
        get all purgehosts
        """
        return self.purgeHosts

    def getDefaultCachedir(self):
        """
        get default cache dir
        """
        return self.defaultCachedir

    def getAllowedHosts(self):
            """
            get allowed hosts
            """
            return self.allowedHosts

    def getAllowedUsers(self):
        """
        get allowed users
        """
        return self.allowedUsers

    def getMainPurgeHostname(self):
        """
        get name of main purge host
        """
        return self.mainPurgeHostname

class HostConfigReader:
    """
    read host config. Is also used for accessing the parsed configuration.
    Yes.. this is admittedly quite ugly
    """
    def __init__(self, configFile = 'purge-config.xml'):
        """
        construct a new HostConfigReader and parse the config
        """
        self.config = {}
        self.parser = xml.sax.make_parser()
        self.handler = HostConfigContentHandler()
        self.parser.setContentHandler(self.handler)
        self.parser.parse(configFile)
        self.config['virtualHosts'] = self.handler.getVirtualHosts()
        self.config['purgeHosts'] = self.handler.getPurgeHosts()
        self.config['defaultCachedir'] = self.handler.getDefaultCachedir()
        self.config['allowedHosts'] = self.handler.getAllowedHosts()
        self.config['allowedUsers'] = self.handler.getAllowedUsers()

    def getCacheDir(self, shortname):
        """
        getCacheDir(string) -> string
        get the cache dir for the given shortname
        """
        try:
            host = self.handler.getVirtualHosts()[shortname]
        except KeyError:
            raise Exception, "No such host (%s) configured" % (shortname)
        defaultCachedir = self.config['defaultCachedir']
        return os.path.join(defaultCachedir, host.cachedir)

    def getHostname(self, shortname):
        """
        getHostname(string) -> string

        get a host name
        """
        try:
            host = self.handler.getVirtualHosts()[shortname]
        except KeyError:
            raise Exception, "No such host (%s) configured" % (shortname)

        return host.hostname

    def getVirtualHost(self, shortname):
        """
        getVirtualHost(string) -> string
        
        get virtual host for a shortname
        """
        try:
            virtualhost = self.handler.getVirtualHosts()[shortname]
        except KeyError:
            raise Exception, "No such host (%s) configured" % (shortname)

        return virtualhost
    
    def getPurgeHosts(self):
        purgeHosts = []
        allHosts = self.handler.getPurgeHosts()
        serverAddress = os.environ['SERVER_ADDR']

        for host in allHosts:
            if host.address != serverAddress:
                purgeHosts.append(host)
        return purgeHosts

    def getMainPurgeSiteName(self):
        return self.handler.getMainPurgeHostname()
    

if __name__ == '__main__':
    hcr = HostConfigReader()

    #print hcr.getHostname('test01')
    #print hcr.getCacheDir('test02')
    
