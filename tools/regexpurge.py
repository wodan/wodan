#!/usr/bin/env python

import cgi
import socket
import urlparse
import os
import shutil

import re
import urllib

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

class LocalRegexPurger:
    """
    Local Purger that purges URLs matching some regular expression
    """
    def __init__(self, cachedir, regex):
        self.cachedir = cachedir
        if not os.path.isdir(self.cachedir):
            raise Exception, "%s is not a directory!" % (self.cachedir)
	
	self.set_regex( regex )

    def set_regex( self, string ):
        self.regex = re.compile( string )

    # Wrapper for the recursive function
    def matchlist( self, max ):
        return self._matchlist( max, self.cachedir )

    # Recursive function that needs to have path argument
    def _matchlist( self, max, cachedir ):
        matches = []
    
        for file in os.listdir( cachedir ):
	    file = os.path.join( cachedir, file )
	    if os.path.isdir( file ):
	        matches += self._matchlist( max - len( matches ), file )
	    else:
	        url = self.get_url( file )
	        if ( self.matches_regex( url ) ):
		    matches.append( ( file, url ) )
            
	    if len( matches ) == max:
	        break
        return matches

    def purge( self ):
        self._purge( self.cachedir )

    def _purge( self, cachedir ):
        for file in os.listdir( cachedir ):
	    file = os.path.join( cachedir, file )
	    if os.path.isdir( file ):
	        self._purge( file )
	    else:
	        url = self.get_url( file )
	        if ( self.matches_regex( url ) ):
                    try:
                        os.remove(file)
                    except Exception:
                        pass

    def get_url( self, filename ):
        file = open( filename, "r" )
        url = file.readline()
	file.close()
	return url.strip()
	
    def matches_regex( self, url ):
	if ( self.regex.match( url ) == None ):
	    return 0
	else:
	    return 1


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

class RemoteRegexPurger:
    def __init__(self, address, port, regex):
        self.address = address
        self.port = port
	self.regex = urllib.quote_plus( regex )

    def purge(self):
	my_url = "http://%s?action=regex&regex=%s&confirm=yes&only_local=yes" % (os.environ['HTTP_HOST'], self.regex )
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
    out.add("<a href=\"http://%s\">%s</a>" % (purgeURL,
                                                    hostname))
    # Regex Link
    out.add('<sup><a href="http://%s?action=regex">[regex purge]</a></sup><br/>' % ( purgeURL, ) )
    out.add("</div>")
    
    
def makePurgeLinksPage(purgeHosts, out):
    out.add("<p>Kies een van de links hieronder om een website te purgen:</p>")
    for hostKey in purgeHosts.keys():
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

def handle_regex_purge( parameters, configReader, out ):
    if ( not parameters.has_key( 'regex' ) ):
        out.add( '<p><b>Purge %s</b></p>' % ( getVirtualHostShortName(), ) )
	out.add( '<form method="get" action="http://%s">' % ( os.environ['HTTP_HOST'], ) )
	out.add( '<input type="hidden" name="action" value="regex">' )
	out.add( 'Regular expression: <input type="text" name="regex" value=".*"><br/><br/>' )
	out.add( '<input type="submit" value="Purge">' )
	out.add( '</form>' )
    else:
        cachedir = configReader.getCacheDir(getVirtualHostShortName())

	if ( parameters.has_key( 'confirm' ) and parameters['confirm'].value == 'yes' ):
	    # if needed, purge other purge hosts.
            if (not parameters.has_key('only_local') or
                parameters['only_local'].value != "yes"):
                other_hosts = configReader.config['purgeHosts']
                for host in other_hosts:
                    rp = RemoteRegexPurger(host.address, host.port, parameters['regex'].value)
                    rp.purge()
			
	    # Purge!
	    try:
	        regex_purger = LocalRegexPurger( cachedir, parameters['regex'].value )
		regex_purger.purge()
                hostname = configReader.getHostname(getVirtualHostShortName())
                out.add( "Alle URLs die \"%s\" matchen zijn gepurged uit de cache van %s" % ( parameters['regex'].value, hostname ) )
		
	    except:
	        out.add( 'Er is iets misgegaan tijdens het purgen.' )
	else:
	    try:
                regex_purger = LocalRegexPurger( cachedir, parameters['regex'].value )
		list = regex_purger.matchlist( 10 )
            except:
	        out.add( "Foute syntaxis van reguliere expressie of fout bij het verwerken" )
	    	return

	    if ( len( list ) == 0 ):
	        out.add( '<p>Er zijn geen URLs die deze regular expression matchen</p>' )
		return

	    out.add( "<p>Onder andere de volgende URLs zullen gepurged worden met de regular expression \"<i>%s</i>\":<p>" % ( parameters['regex'].value, ) )
	    out.add( "<ul>" )
	    for match in list:
	        out.add( "<li>%s</li>" % ( match[1], ) )
	    out.add( "</ul>" )
            
	    purge_url = "http://" + os.environ['HTTP_HOST']
	    purge_url += ( '?action=regex&regex=%s&confirm=yes' % ( urllib.quote_plus( parameters['regex'].value ), ) )
	    out.add( "Weet u het zeker? <a href=\"%s\">Ja</a>" % ( purge_url, ) )
    
    
parameters = cgi.FieldStorage()
configReader = hostconfig.HostConfigReader()

out = CGIOutput()

hostname = os.environ['HTTP_HOST']
if hostname == configReader.getMainPurgeSiteName():
    # show page for all configured sites
    makePurgeLinksPage(configReader.config['virtualHosts'], out)
else:
    if allowedToPurge(getVirtualHostShortName()):
        if ( parameters.has_key( 'action' ) and parameters['action'].value == 'regex' ):
	    handle_regex_purge( parameters, configReader, out )
	else:
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
