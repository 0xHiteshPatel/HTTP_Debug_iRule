# HTTP Debugging iRule v1.0
# Cobbled together by Hitesh Patel <h.patel@f5.com> from various devcentral posts
# WARNING: This iRule may break things.  Use accordingly
#
# SUPPORT: This iRule is not officially supported by me or F5.  That
#          being said I will do my best to support as my time permits
#
# Version History:
#  v1.0 - Initial Release
#
# Configuration:
#  1) Set global vars in RULE_INIT event:
#   
#    $static::insertHeader configures the iRule to insert a random 
#    session ID in the X-F5-SessionID header.  This is useful for tracking 
#    the session through another LTM (DMZ LTM ->Internal LTM Traffic) or to 
#    the server where it can be read.  The iRule also checks for the 
#    X-F5-SessionID header on incoming traffic and if present inserts the 
#    header value into the log so they can be correlated between different 
#    LTM devices.
#
#    $static::removeHeader configures the iRule to remove the X-F5-SessionID 
#    if found in the HTTP Request
#
#  2) Attached to a Virtual Server with a HTTP profile and tail -f /var/log/ltm
#
#

when RULE_INIT {
	# Set to 1 to insert X-F5-SessionID header or 0 to not insert
	set static::insertHeader 1

        # Set to 1 to remove the X-F5-SessionID header if found, 0 to leave it in
        set static::removeHeader 1
}

when CLIENT_ACCEPTED {
	# Generate a random ID for this session
   	set count 20
   	set letters [ list a b c d e f g h i j k l m n o p q r s t u v w x y z ]
   	set random ""
   	set logme 0
   	for { set i 1 } { $i < $count } { incr i } {
      		append random [lindex $letters [expr { int (rand() * 26) }]]
   	}

   	# Get time for start of TCP connection in milleseconds
	set tcp_start_time [clock clicks -milliseconds]

	# Log the start of a new TCP connection
	log local0. ">$random< New TCP connection from [IP::client_addr]:[TCP::client_port] to [IP::local_addr]:[TCP::local_port]"
}

when HTTP_REQUEST {
	set logme 1

	if { [HTTP::header exists "X-F5-SessionID"] } {
                	log local0. ">$random< Got passed SessionID header: [HTTP::header X-F5-SessionID]"
			set random [HTTP::header "X-F5-SessionID"]
                        if { $static::removeHeader } {
                	       HTTP::header remove "X-F5-SessionID"
                        }
	} else {
	        if { $static::insertHeader } {
		        HTTP::header insert "X-F5-SessionID" $random
	        }
        }
	# Get time for start of HTTP request
	set http_request_time [clock clicks -milliseconds]

	# Log the start of a new HTTP request
	set LogString ">$random< Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
        log local0. ">$random< ============================================="
	log local0. "$LogString (request)"
	foreach aHeader [HTTP::header names] {
            log local0. ">$random< $aHeader: [HTTP::header value $aHeader]"
        }
        log local0. ">$random< ============================================="
}

when LB_SELECTED {
 if { $logme == 1 } {
	log local0. ">$random< Client [IP::client_addr]:[TCP::client_port]: Selected [LB::server]"
 }
}
when LB_FAILED {
	log local0. ">$random< Client [IP::client_addr]:[TCP::client_port]: Failed to [LB::server]"
}
when SERVER_CONNECTED {
 if { $logme == 1 } {
	log local0. ">$random< Client [IP::client_addr]:[TCP::client_port]: Connected to [IP::server_addr]:[TCP::server_port]"
 }
}
when HTTP_RESPONSE {
 if { $logme == 1 } {
	# Received the response headers from the server.  Log the pool name, IP and port, status and time delta
	log local0. ">$random< ============================================="
        log local0. "$LogString (response) - pool info: [LB::server] - status: [HTTP::status] (request/response delta: [expr {[clock clicks -milliseconds] - $http_request_time}] ms)"
        foreach aHeader [HTTP::header names] {
           log local0. ">$random< $aHeader: [HTTP::header value $aHeader]"
        }
        log local0. ">$random< ============================================="
 }   
}
when CLIENT_CLOSED {
	# Log the end time of the TCP connection
 if { $logme == 1 } {
	log local0. ">$random< Closed TCP connection from [IP::client_addr]:[TCP::client_port] to [IP::local_addr]:[TCP::local_port] (open for: [expr {[clock clicks -milliseconds] - $tcp_start_time}] ms)"
 }
}
