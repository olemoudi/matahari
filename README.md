#	Matahari
#	Reverse HTTP shell

 author: Martin Obiols Herrera -- OleMoudi <olemoudi AT users.sourceforge.net>
 started: 09/Sept/2007
	
	Script to obtain a basic shell remotely on unix systems behind firewalls.
	Client gets commands by periodically polling the server and sends the output back
	after executing them. Traffic traverses firewall as standard outgoing HTTP GET/POST requests.
	HTTP requests/responses carry payload b64 encoded
	
	Polling period between requests can be modified sending commands like "%polling_type",
	where "polling_type" is one of the following:
		-insane: 10 seconds between requests
		-agressive: 25 seconds between requests
		-normal: 60 seconds between requests
		-polite: 5 mins between requests
		-paranoid: 30 mins between requests
		-stealth: 60 mins between requests
		-adaptative: dinamically increases polling period when no commands are received until
			     reaching stealth type.

	Be aware that when ids-evasion flag is set, all the above times are modified randomly with each
	polling period between original value and 2 x original value.

	Payload encryption uses ARC4 (requires python-crypto package). Client sends with each request a 
	special header with a unique salt (str(randint(1,1000)) + str(time.time()). Server response and
	next client POST request will be encrypted using the password+salt. This way client gets protected
	against retransmission attacks.
	

	TODO:
		-Better error handling
		-Support for interactive commands
		-Code clean up
		-Comments -_-zZZ

