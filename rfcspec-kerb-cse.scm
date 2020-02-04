;	RFC Kerberos Standard Protocol
;	
;	* We replace our brands with RFC-defined brands and we then follow the rest of the RFC
;	* as closely as possible.
;
; 	** Variable Definitions
;
;		-	Principal variables
; 				usr	= User principal
; 				tgs = TGS principal
;				srv = Service principal requested by usr
;				kdc = KDC

;		-	Tickets
; 				tgt = Ticket Granting Ticket
; 				st = Service Ticket
;
;		-	Session keys
; 				ut-sk = User-TGS session key
; 				us-sk = User-Srv session key
;
;		-	Nonces
; 				n-usr-ase = user chosen nonce for ASE request
; 				n-usr-tgse = user chosen nonce for TGSE request
;
;		-	Timestamps 
;				time-usr-tgse = user chosen timestamp for TGSE 
;								request authenticator
;               time-usr-cse = user chosen timestamp for CSE request
;                              authenticator

;	** Assumptions
;
;		- Key usage values
;			2 = TGS LTK and Service LTK for tickets
;			3 = client's LTK for AS-REP
;			6 = key for checksum in authenticator for TGS-REQ
;			7 = use for authenticator
;			8 = use for session key encrypting TGS-REP
;			10 = key for checksum in authenticator
;			11 = use for authenticator in AP-REQ
;			12 = use for AP-REP encrypted part
;			....
;			1028 = bookkeeping encryption between user-ase and user-tgse
;			1030 = bookkeeping encryption between user-tgse and user-cse
;
;		- Tag numbers
;			1 = Ticket
;			2 = Authenticator
;			3 = Encrypted part of Ticket
;			10 = AS-REQ
;			11 = AS-REP
;			12 = TGS-REQ
;			13 = TGS-REP
;			14 = AP-REQ
;			15 = AP-REP
;			25 = AS-REP encryption for user
;			26 = TGS-REP encryption for user
;			27 = AP-REP encryption for user


(herald rfcspec-kerb-cse (bound 20) (limit 15000))

(defprotocol rfcspec-kerb-cse basic

; ********** RFC Kerberos Standard Protocol - Authentication Service Exchange (ASE) **********


	;;; User ASE Role
	;
	; Summary: User sends request for TGT to AS
	; and AS responds with session key component
	; encrypted with User's LTK and a TGT.

	(defrole user-ase
		(vars (usr as tgs name) (n-usr-ase text) (tgt mesg) (ut-sk skey))
		(trace

			; ****************************************
			; ************* Perform ASE **************

			; AS-REQ - does not include:
			;			padata
			;			req-body =
			;				kdc-options - set of options
			;				realm - realm of "tgs"
			;				from, till, rtime - options for ticket times
			;				enc-authorization-data - for TGS-REQ / optional in RFC
			;				addresses - IPs that ticket can be used / optional in RFC
			;				additional tickets - for TGS-REQ / optional in RFC
			;
			(send (cat "10" "pvno=5" "msg-type=10" (cat usr tgs n-usr-ase)))

			; AS-REP - does not include:
			;			padata - optional in RFC
			;			crealm - usr's realm
			;			ticket (TGT) =
			;				realm - tgs's realm
			;				enc-part - (encrypted portion missing some values - described in "as" role below)
			;
			;			enc-part (response to user encrypted in usr's LTK) =
			;				Plaintext =
			;					kvno - version of usr's LTK being used for encryption; 
			;							making this a tag fixes "tgs" problematic shape
			;				Ciphertext =
			;					last-req - last request/login time of user
			;					key-expiration - time when "usr" LTK expires - DEPRECATED/optional in RFC
			;					flags - assigned options for ticket based on "kdc-options" from AS-REQ
			;					authtime,starttime,endtime,renew-till - times in ticket for ticket lifetime
			;					caddr - addresses for where the ticket can be used / optional in RFC
			;
			(recv (cat "11" "pvno=5" "msg-type=11" usr (cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" tgt)) 
				(cat "kvno-usr" (enc "25" ut-sk n-usr-ase tgs (hash "3" (ltk usr as))
				))))

			; ***********************************************************
			; ******* Hash message transmission to user-tgse role *******
			;
			; REQUIRES key-usage value that is different from other messages
			(send (hash "hash from user-ase to user-tgse" "kvno-usr"
				(enc "hash record ase to tgse" usr tgs as n-usr-ase ut-sk 
					(cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" tgt)) 
					(hash "1028" (ltk usr as))) )) 
		)
		; User's nonce for ASE request should be uniquely originating, i.e., freshly generated
		(uniq-orig n-usr-ase)
	)

	;;; AS Role
	;
	; Summary: AS receives request from User
	; and returns message containing two components:
	; one for User (session key encrypted with User's
	; LTK) and TGT.

	(defrole as
		(vars (usr tgs as name) (n-usr-ase text) (ut-sk skey))
		(trace
			; ****************************************
			; ************* Perform ASE **************

			; AS-REQ - see above in "user-ase" role
			(recv (cat "10" "pvno=5" "msg-type=10" (cat usr tgs n-usr-ase)))

			; AS-REP - does not include:
			;			padata - could potentially return salt to use for "string-to-key" / optional in RFC
			;			crealm - usr's realm
			;			ticket (TGT) =
			;				realm - tgs's realm
			;				enc-part =
			;					Plaintext =
			;						kvno - version of "tgs" LTK used for encryption
			;					Ciphertext =
			;						flags - assigned options for ticket based on "kdc-options" from AS-REQ
			;						crealm - usr's realm
			;						transited - realms that ticket has passed through (used for RTGTs)
			;						authtime,startime,endtime,renew-till - times for ticket lifetime
			;						caddr - IP addreses for where ticket can be used
			;						authorization-data - passing of authorization information about usr
			;
			;			enc-part (encrypted response to usr using usr's LTK) =
			;				Plaintext =
			;					kvno - version of usr's LTK being used for encryption 
			;				Ciphertext =
			;					last-req - last request/login time of user
			;					key-expiration - time when "usr" LTK expires - DEPRECATED/optional in RFC
			;					flags - assigned options for ticket based on "kdc-options" from AS-REQ
			;					authtime,starttime,endtime,renew-till - times in ticket for ticket lifetime
			;					caddr - addresses for where the ticket can be used / optional in RFC
			;	
			(send (cat "11" "pvno=5" "msg-type=11" usr 
				(cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" (enc "3" "init" ut-sk usr (hash "2" (ltk tgs as))))) 
				(cat "kvno-usr" (enc "25" ut-sk n-usr-ase tgs (hash "3" (ltk usr as))
				))))
		)
		; User-TGS session key should always be uniquely originating, i.e., freshly generated
		(uniq-gen ut-sk)
	)

; ********** RFC Kerberos Standard Protocol - Ticket-Granting Service Exchange (TGSE) **********

	;;; User TGSE Role
	;
	; Summary: User uses received TGT and User-TGS
	; session key to request a ST from the TGS for the SRV.
	; User receives response message with two components: a User-SRV session
	; key encrypted with the User-TGS session key and the ST.

	(defrole user-tgse
		(vars (usr srv tgs as name) (n-usr-ase n-usr-tgse 
            time-usr-tgse text) (tgt st mesg) (ut-sk us-sk skey))
		(trace

			; *******************************************************************************
			; *** Network message reception and hash message reception from user-ase role ***

			; AS-REP message received in previous role of ASE
			(recv (cat "11" "pvno=5" "msg-type=11" usr (cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" tgt)) 
				(cat "kvno-usr" (enc "25" ut-sk n-usr-ase tgs (hash "3" (ltk usr as))
				))))

			; ** THIS MESSAGE IS ADDED BY US FOR BOOKEEPING BETWEEN USER ROLES **
			; REQUIRES key-usage value that is different from other messages
			(recv (hash "hash from user-ase to user-tgse" "kvno-usr"
				(enc "hash record ase to tgse" usr tgs as n-usr-ase ut-sk 
					(cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" tgt)) 
					(hash "1028" (ltk usr as))) )) 


			; ******************************************
			; ************* Perform TGSE ***************

			; TGS-REQ - does not include:
			;			padata = 
			;				ap-options - flags for processing of AP-REQ
			;				ticket (TGT) =
			;					realm = tgs's realm
			;					enc-part - (encrypted portion missing some values - 
			;								described in "tgs" role below)
			;
			;				authenticator =
			;					Ciphertext =
			;						crealm - usr's realm
			;						cusec - usr's local time in microseconds
			;						subkey - sub-session key to use for reply instead of session key
			;								 from TGT
			;						seq-number - sequence number (optional)
			;						authorization-data - any authorization related data required / optional in
			;											 RFC
			;
			;			req-body (checksum of this part is in authenticator; IS INCLUDED in our model) =
			;				kdc-options - flags for options for ST
			;				realm - requested service's realm
			;				from, till, rtime - requested length/expiration times for ST
			;				addresses - IP addresses that ST can be used
			;				enc-authorization-data - any authorization related data
			;				additional-tickets - any other tickets that must be provided
			;
			(send (cat "12" "pvno=5" "msg-type=12" 
				(cat "padata-type=1" 
					(cat "pvno=5" "14" 
						(cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" tgt)) 
						(cat (enc "2" "authenticator-vno=5" usr 
							(cat (hash srv n-usr-tgse (hash "6" ut-sk)))
							time-usr-tgse (hash "7" ut-sk))) )) 
				(cat srv n-usr-tgse) ))


			; TGS-REP - does not include:
			;			padata - optional in RFC
			;			crealm - usr's realm
			;			ticket (ST) for srv =
			;				realm - srv's realm
			;				enc-part - (encrypted portion missing some values -
			;							described in "tgs" role below)
			;			
			;			enc-part (encrypted part of response encrypted under "ut-sk") =
			;				Ciphertext =
			;					last-req - time of last request
			;					key-expiration - left out of TGS-REP (p. 84)
			;					flags - enabled options based on TGS policy and TGS-REQ
			;					authtime, starttime, endtime, renew-till - times in ticket based on TGS-REQ
			;																and KDC policy for STs
			;					srealm - srv's realm
			;					caddr - IP addresses that ST can be used based on TGS-REQ
			;
			(recv (cat "13" "pvno=5" "msg-type=13" usr 
				(cat "1" "tkt-vno=5" srv (cat "kvno-srv" st))
				(cat (enc "26" us-sk n-usr-tgse srv (hash "8" ut-sk)))
			))

			; ***********************************************************
			; ******* Hash message transmission to user-cse role ********

			; Hash message transmission to next entity role
			; ** THIS MESSAGE IS ADDED BY US FOR BOOKEEPING BETWEEN USER ROLES **
			; REQUIRES key-usage value that is different from all other messages
			; including previous bookeeping message
			(send (hash "hash from user-tgse to user-cse role" "kvno-usr"
				(enc "hash record" usr as tgs srv n-usr-ase n-usr-tgse time-usr-tgse
					ut-sk us-sk
					(cat "1" "tkt-vno=5" srv (cat "kvno-srv" st)) 
					(hash "1030" (ltk usr as)))))

		)
		; User's nonce in request for ST must always be uniquely originating
		(uniq-orig n-usr-tgse)
	)

	;;; TGS Role
	;
	; Summary: TGS receives SRV principal name, nonce, authenticator
	; and TGT from User and produces a ST for SRV.

	(defrole tgs
		(vars (usr srv tgs as name) (n-usr-ase n-usr-tgse 
            time-usr-tgse text) (ut-sk us-sk skey))
		(trace

			; *********************************************************
			; *************** Perform TGSE Subprotocol ****************

			; TGS-REQ - does not include:
			;			padata = 
			;				ap-options - flags for processing of AP-REQ
			;				ticket (TGT) =
			;					realm - tgs's realm
			;					enc-part =
			;						Plaintext =
			;							kvno - version of "tgs" LTK used for encryption
			;						Ciphertext =
			;							flags - assigned options for ticket based on "kdc-options" from
			;									AS-REQ
			;							crealm - usr's realm
			;							transited - realms that ticket has passed through (used for RTGTs)
			;							authtime,startime,endtime,renew-till - times for ticket lifetime
			;							caddr - IP addreses for where ticket can be used
			;							authorization-data - passing of authorization information about usr
			;
			;				authenticator =
			;					Ciphertext =
			;						crealm - usr's realm
			;						cusec - usr's local time in microseconds
			;						subkey - sub-session key to use for reply instead of session key
			;								 from TGT as chosen by usr
			;						seq-number - sequence number (optional)
			;						authorization-data - any authorization related data required / optional
			;											 in RFC
			;
			;			req-body (checksum of this part is in authenticator; IS INCLUDED in our model) =
			;				kdc-options - flags for options for ST
			;				realm - requested service's realm
			;				from, till, rtime - requested length/expiration times for ST
			;				addresses - IP addresses that ST can be used
			;				enc-authorization-data - any authorization related data
			;				additional-tickets - any other tickets that must be provided
			;
			(recv (cat "12" "pvno=5" "msg-type=12" 
				(cat "padata-type=1" 
					(cat "pvno=5" "14" 
						(cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" (enc "3" "init" ut-sk usr 
							(hash "2" (ltk tgs as)))))
						(cat (enc "2" "authenticator-vno=5" usr 
							(cat (hash srv n-usr-tgse (hash "6" ut-sk)))
							time-usr-tgse (hash "7" ut-sk))) 
					)
				) 
				(cat srv n-usr-tgse) ))


			; TGS-REP - does not include:
			;			padata - optional in RFC
			;			crealm - usr's realm
			;			ticket (ST) for srv =
			;				realm - srv's realm
			;				enc-part =
			;					Plaintext =
			;						kvno - version of srv's LTK used for encryption
			;					Ciphertext =
			;						flags - assigned options for ticket based on "kdc-options" from TGS-REQ
			;						crealm - usr's realm
			;						transited - realms that ticket passed through (for RTGTs)
			;						authtime, starttime, endtime, renew-till - times for ticket lifetime
			; 														based on KDC policy for STs and TGTs
			;						caddr - IP addresses for where ticket can be used
			;						authorization-data - passing of authorization information about usr
			;			
			;			enc-part (encrypted part of response encrypted under "ut-sk") =
			;				Ciphertext =
			;					last-req - time of last request
			;					key-expiration - left out of TGS-REP (p. 84)
			;					flags - enabled options based on TGS policy and TGS-REQ
			;					authtime, starttime, endtime, renew-till - times in ticket based on TGS-REQ
			;																and KDC policy for STs
			;					srealm - srv's realm
			;					caddr - IP addresses that ST can be used based on TGS-REQ
			;
			(send (cat "13" "pvno=5" "msg-type=13" usr 
				(cat "1" "tkt-vno=5" srv (cat "kvno-srv" (enc "3" us-sk usr 
					(hash "2" (ltk srv tgs))) ))
				(cat (enc "26" us-sk n-usr-tgse srv (hash "8" ut-sk)))
			))

		)
		; User-SRV session key should always be uniquely originating
		(uniq-gen us-sk)
	)


; ********** RFC Kerberos Standard Protocol - Client-Service Exchange (CSE) **********

	;;; User CSE Role
	;
	; Summary: User uses the User-Service session key
	; and ST to authenticate to and use the Service. User sends
	; message containing an authenticator and ST. In response, 
	; Service sends the optional message containing the
	; timestamp from the User's CSE request authenticator. We
	; include the optional message for our purposes later on
	; with RFC Kerberos and RFK.
	
	(defrole user-cse
		(vars (usr as tgs srv name) (n-usr-ase n-usr-tgse time-usr-tgse 
			time-usr-cse text) (st mesg) (us-sk ut-sk skey))
		(trace

			; **********************************************************************************
			; ********* Network message and hash message reception from user-tgse role *********

			; Network message received from previous role
			(recv (cat "13" "pvno=5" "msg-type=13" usr 
				(cat "1" "tkt-vno=5" srv (cat "kvno-srv" st))
				(cat (enc "26" us-sk n-usr-tgse srv (hash "8" ut-sk)))
			))

			; Hash message sent by previous role reception
			; ** THIS MESSAGE IS ADDED BY US FOR BOOKEEPING BETWEEN USER ROLES **
			; REQUIRES key-usage value that is different from all other messages
			; including previous bookeeping message
			(recv (hash "hash from user-tgse to user-cse role" "kvno-usr"
				(enc "hash record" usr as tgs srv n-usr-ase n-usr-tgse time-usr-tgse
					ut-sk us-sk
					(cat "1" "tkt-vno=5" srv (cat "kvno-srv" st)) 
					(hash "1030" (ltk usr as)))))

			; **********************************************
			; *************** Perform CSE ******************

			; AP-REQ - does not include
			;			ap-options - we include "2" as one of the options
			;						 for srv returning the optional message
			;						 AP-REP
			;			ticket (ST) for srv =
			;				realm - srv's realm (same as usr's)
			;				enc-part = (encrypted portion missing some values -
			;							described in "tgs" role below)
			;
			;			authenticator =
			;				crealm - usr's realm
			;				cksum - checksum of application data (none in this case);
			;						optional RFC4120 p.85 (Section 5.5.1)
			;				cusec - usr's local time in microseconds
			;				subkey - sub-session key to use for encryption response
			;						 as chosen by usr; optional in RFC4120 p.85
			;				seq-number - starting sequence number for proceeding messages;
			;							 optional in RFC4120 p.85
			;				authorization-data - additional restrictions for use of ticket
			;									 optional in RFC
			(send (cat "14" "pvno=5" "msg-type=14" "ap-options=2" ; tag "2" means that service should send reply
				(cat "1" "tkt-vno=5" srv (cat "kvno-srv" st))
				(cat (enc "2" "authenticator-vno=5" usr time-usr-cse (hash "11" us-sk)))))
 
			; AP-REP - does not include
			;			enc-part =
			;				cusec - usr's local time in microseconds (acknowledgement)
			;				subkey - sub session key to use for subsequent application
			;						 data transfer; optional in RFC4120 pg. 87
			;				seq-number - next sequence number from seq-number in AP-REQ
			(recv (cat "15" "pvno=5" "msg-type=15" 
				(cat (enc "27" time-usr-cse (hash "12" us-sk)))))

		)
	)

	;;; Srv Role
	;
	; Summary: Srv receives authentication request from User and
	; verifies the authenticator and ST. 
    ;

	(defrole srv
		(vars (usr tgs srv name) (time-usr-cse text) (us-sk skey))
		(trace

			; **************************************************************
			; ***************** Perform CSE Subprotocol ********************

			; AP-REQ - does not include
			;			ap-options - we include "2" as one of the options
			;						 for srv returning the optional message
			;						 AP-REP
			;			ticket (ST) for srv =
			;				realm - srv's realm (same as usr's)
			;				enc-part = 
			;					Plaintext =
			;						kvno - version of srv's LTK used for encryption
			;					Ciphertext =
			;						flags - assigned options for ticket based on "kdc-options" from TGS-REQ
			;						crealm - usr's realm
			;						transited - realms that ticket passed through (for RTGTs)
			;						authtime, starttime, endtime, renew-till - times for ticket lifetime based
			;																	on KDC policy for STs and TGS-REQ
			;						caddr - IP addresses for where ticket can be used
			;						authorization-data - passing of authorization information about usr
			;
			;			authenticator =
			;				crealm - usr's realm
			;				cksum - checksum of application data (none in this case);
			;						optional RFC4120 p.85 (Section 5.5.1)
			;				cusec - usr's local time in microseconds
			;				subkey - sub-session key to use for encryption response
			;						 as chosen by usr; optional in RFC4120 p.85
			;				seq-number - starting sequence number for proceeding messages;
			;							 optional in RFC4120 p.85
			;				authorization-data - additional restrictions for use of ticket
			;									 optional in RFC			
			(recv (cat "14" "pvno=5" "msg-type=14" "ap-options=2" ; tag "2" means that service should send reply
				(cat "1" "tkt-vno=5" srv (cat "kvno-srv" (enc "3" us-sk usr 
					(hash "2" (ltk srv tgs))) ))
				(cat (enc "2" "authenticator-vno=5" usr time-usr-cse (hash "11" us-sk)))))



			; AP-REP - does not include
			;			enc-part =
			;				cusec - usr's local time in microseconds (acknowledgement)
			;				subkey - sub session key to use for subsequent application
			;						 data transfer; optional in RFC4120 pg. 87
			;				seq-number - next sequence number from seq-number in AP-REQ
			(send (cat "15" "pvno=5" "msg-type=15" 
				(cat (enc "27" time-usr-cse (hash "12" us-sk)))))
		)
	)

)




; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;  ANALYSIS QUERIES SHOWING NO PROBLEMATIC SHAPES ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;

(defskeleton rfcspec-kerb-cse
	(vars (tgt st mesg) (n-usr-ase n-usr-tgse time-usr-tgse time-usr-cse text)
		(usr tgs srv as name) (ut-sk us-sk skey))
	(defstrand user-cse 4 (usr usr) (tgs tgs) (srv srv) 
		(as as) (st st) (ut-sk ut-sk) (us-sk us-sk)
		(time-usr-tgse time-usr-tgse) (n-usr-tgse n-usr-tgse) 
		(n-usr-ase n-usr-ase) (time-usr-cse time-usr-cse) 
		)
	(non-orig (ltk usr as) (ltk tgs as) (ltk srv tgs) )
)

(defskeleton rfcspec-kerb-cse
	(vars (n-usr-tgse time-usr-tgse text)
		(usr tgs srv as name) (ut-sk us-sk skey))
	(defstrand tgs 2 (usr usr) (tgs tgs) (srv srv) 
		(as as) (n-usr-tgse n-usr-tgse)
		(time-usr-tgse time-usr-tgse) (ut-sk ut-sk) (us-sk us-sk) )
	(uniq-orig us-sk)
	(non-orig (ltk usr as) (ltk tgs as) (ltk srv tgs) )
)

(defskeleton rfcspec-kerb-cse
	(vars (time-usr-cse time-usr-tgse n-usr-tgse text)
		(usr tgs srv as name) (ut-sk us-sk skey))
	(defstrand srv 2 (usr usr) (srv srv) (tgs tgs)
		(time-usr-cse time-usr-cse) (us-sk us-sk) )
	(defstrand tgs 2 (usr usr) (tgs tgs) (srv srv) (as as)
		(time-usr-tgse time-usr-tgse) (n-usr-tgse n-usr-tgse)
		(ut-sk ut-sk) (us-sk us-sk))
	(uniq-orig us-sk)
	(non-orig (ltk usr as) (ltk tgs as) (ltk srv tgs) )
)
