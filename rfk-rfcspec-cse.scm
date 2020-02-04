; Identity Delegation Protocol (IDP)
;
;	* IDP includes the RFC Kerberos Standard Protocol + IS-ISC Exchange + RFC Kerberos
;	* Administration Protocol
;
; 	** Variable Definitions
;
;		-	Principal variables
; 				usr	= User principal
; 				tgs = TGS principal
;				is = Identity Service
;				isc = Identity Service Client
;				as = AS of Primary Realm
;				sec-as = AS of Secondary Realm
;				sec-kas = KAS of Secondary Realm
;				sec-usr = User Secondary Realm
;
;		-	Tickets
; 				tgt = Ticket Granting Ticket
; 				st = Service Ticket
;				dt = Database Ticket
;
;		-	Session keys
; 				ut-sk = User-TGS session key
; 				ui-sk = User-IS session key
;				ik-sk = ISC-KAS session key
;
;		-	Nonces
; 				n-usr-ase = user chosen nonce for ASE request
; 				n-usr-tgse = user chosen nonce for TGSE request
;				n-is-isc = is chosen nonce for IIE request
;				n-isc-dta = isc chosen nonce for DTA request
;
;		-	Timestamps 
;				time-usr-tgse = user timestamp for TGSE request authenticator
;               time-usr-cse = user timestamp for CSE request authenticator
;				time-is-cse = is chosen timestamp for CSE response
;				time-isc-query = isc timestamp in DBQ authenticator
;				time-kas-query = sec-kas timestamp in DBQ response
;
;		- 	Misc.
;				pwd = password associated with sec-usr


;	** Assumptions
;
;		- Key usage values
;			3 = client's LTK for AS-REP
;			6 = key for checksum in authenticator for TGS-REQ
;			7 = use for authenticator
;			8 = use for session key encrypting TGS-REP
;			10 = key for checksum in authenticator
;			11 = use for authenticator in AP-REQ
;			12 = use for AP-REP encrypted part
;			13 = use for encryption KRB-PRIV messages
;
;			1028 = bookkeeping encryption between user-ase and user-tgse
;			1030 = bookkeeping encryption between user-tgse and user-cse
;			1032 = encryption for IIE-REQ from is to isc
;			1033 = use for IIE-REQ checksum
;			1034 = encryption for IIE-REP from isc to is
;			1035 = use for IIE-REP checksum
;
;		- Tag numbers
;			1 = Ticket
;			2 = Authenticator
;			3 = Encrypted part of Ticket
;			6 = IIE-REQ
;			7 = IIE-REP
;			10 = AS-REQ / DTA-REQ
;			11 = AS-REP / DTA-REP
;			12 = TGS-REQ
;			13 = TGS-REP
;			14 = AP-REQ / DBQ-REQ
;			15 = AP-REP / DBQ-REP
;			19 = IIE-REQ encryption for isc
;			21 = KRB-PRIV
;			23 = IIE-REP encryption for is
;			25 = AS-REP encryption for user
;			26 = TGS-REP encryption for user
;			27 = AP-REP encryption for user
;			28 = KRB-PRIV encryption


(herald rfk-rfcspec-cse (goals-sat) (bound 18) (limit 12000))

(defprotocol rfk-rfcspec-cse basic

; ********** RFC Kerberos Standard Protocol - Authentication Service Exchange (ASE) **********


	;;; User ASE Role
	;
	; Summary: User sends request for TGT to AS
	; and AS responds with session key component
	; encrypted with User's LTK and a TGT.


	(defrole user-ase
		(vars (usr as tgs name) (n-usr-ase text) (tgt mesg) (ut-sk skey))
		(trace

			(send (cat "10" "pvno=5" "msg-type=10" (cat usr tgs n-usr-ase)))

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
		; User's nonce for TGT request should be uniquely originating, i.e., freshly generated
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
			;						flags - assigned options for ticket bdta on "kdc-options" from AS-REQ
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
			;					flags - assigned options for ticket bdta on "kdc-options" from AS-REQ
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
	; session key to request a ST from the TGS for the IS.
	; User receives response message with two components: a User-IS session
	; key encrypted with the User-TGS session key and the ST.

	(defrole user-tgse
		(vars (usr is tgs as name) (n-usr-ase n-usr-tgse 
            time-usr-tgse text) (tgt st mesg) (ut-sk ui-sk skey))
		(trace

			; *********************************************************************************
			; *** Network message reception and hash message reception from user-ase role ***

			; AS-REP message received in previous role of subprotocol
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
							(cat (hash is n-usr-tgse (hash "6" ut-sk)))
							time-usr-tgse (hash "7" ut-sk))) )) 
				(cat is n-usr-tgse) ))


			; TGS-REP - does not include:
			;			padata - optional in RFC
			;			crealm - usr's realm
			;			ticket (ST) for is =
			;				realm - is's realm
			;				enc-part - (encrypted portion missing some values -
			;							described in "tgs" role below)
			;			
			;			enc-part (encrypted part of response encrypted under "ut-sk") =
			;				Ciphertext =
			;					last-req - time of last request
			;					key-expiration - left out of TGS-REP (p. 84)
			;					flags - enabled options bdta on TGS policy and TGS-REQ
			;					authtime, starttime, endtime, renew-till - times in ticket bdta on TGS-REQ
			;																and KDC policy for STs
			;					srealm - is's realm
			;					caddr - IP addresses that ST can be used bdta on TGS-REQ
			;
			(recv (cat "13" "pvno=5" "msg-type=13" usr 
				(cat "1" "tkt-vno=5" is (cat "kvno-is" st))
				(cat (enc "26" ui-sk n-usr-tgse is (hash "8" ut-sk)))
			))

			; ***********************************************************
			; ******* Hash message transmission to user-cse role ********

			; Hash message transmission to next entity role
			; ** THIS MESSAGE IS ADDED BY US FOR BOOKEEPING BETWEEN USER ROLES **
			; REQUIRES key-usage value that is different from all other messages
			; including previous bookeeping message
			(send (hash "hash from user-tgse to user-cse role" "kvno-usr"
				(enc "hash record" usr as tgs is n-usr-ase n-usr-tgse time-usr-tgse
					ut-sk ui-sk 
					(cat "1" "tkt-vno=5" is (cat "kvno-is" st)) 
					(hash "1030" (ltk usr as)))))

		)
		; User's nonce in request for ST must always be uniquely originating
		(uniq-orig n-usr-tgse)
	)

	;;; TGS Role
	;
	; Summary: TGS receives IS principal name, nonce, authenticator
	; and TGT from User and produces a ST for IS.

	(defrole tgs
		(vars (usr is tgs as name) (n-usr-tgse time-usr-tgse 
			 text) (ut-sk ui-sk skey))
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
			;							flags - assigned options for ticket bdta on "kdc-options" from AS-REQ
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
			(recv (cat "12" "pvno=5" "msg-type=12" 
				(cat "padata-type=1" 
					(cat "pvno=5" "14" 
						(cat "1" "tkt-vno=5" tgs (cat "kvno-tgs" (enc "3" "init" ut-sk usr 
							(hash "2" (ltk tgs as)))))
						(cat (enc "2" "authenticator-vno=5" usr 
							(cat (hash is n-usr-tgse (hash "6" ut-sk)))
							time-usr-tgse (hash "7" ut-sk))) 
					)
				) 
				(cat is n-usr-tgse) ))


			; TGS-REP - does not include:
			;			padata - optional in RFC
			;			crealm - usr's realm
			;			ticket (ST) for is =
			;				realm - is's realm
			;				enc-part =
			;					Plaintext =
			;						kvno - version of is's LTK used for encryption
			;					Ciphertext =
			;						flags - assigned options for ticket bdta on "kdc-options" from TGS-REQ
			;						crealm - usr's realm
			;						transited - realms that ticket passed through (for RTGTs)
			;						authtime, starttime, endtime, renew-till - times for ticket lifetime bdta
			;																	on KDC policy for STs and TGS-REQ
			;						caddr - IP addresses for where ticket can be used
			;						authorization-data - passing of authorization information about usr
			;			
			;			enc-part (encrypted part of response encrypted under "ut-sk") =
			;				Ciphertext =
			;					last-req - time of last request
			;					key-expiration - left out of TGS-REP (p. 84)
			;					flags - enabled options bdta on TGS policy and TGS-REQ
			;					authtime, starttime, endtime, renew-till - times in ticket bdta on TGS-REQ
			;																and KDC policy for STs
			;					srealm - is's realm
			;					caddr - IP addresses that ST can be used bdta on TGS-REQ
			;
			(send (cat "13" "pvno=5" "msg-type=13" usr 
				(cat "1" "tkt-vno=5" is (cat "kvno-is" (enc "3" ui-sk usr 
					(hash "2" (ltk is tgs))) ))
				(cat (enc "26" ui-sk n-usr-tgse is (hash "8" ut-sk)))
			))

		)
		; User-IS session key should always be uniquely originating
		(uniq-gen ui-sk)
	)


; ********** RFC Kerberos Standard Protocol - Client-Service Exchange (CSE) **********

	;;; User CSE Role
	;
	; Summary: User uses the User-IS session key
	; and ST to authenticate to and use the IS.
	; In response, IS provides the newly established
	; identity record back to the User. The identity
	; record is sent back using the KRB-PRIV message
	; structure.
	
	(defrole user-cse
		(vars (usr as tgs is sec-usr name) (n-usr-ase n-usr-tgse time-usr-tgse 
			time-usr-cse time-is-cse pwd text) (st mesg) (ui-sk ut-sk skey))
		(trace

			; **********************************************************************************
			; ********* Network message and hash message reception from user-tgse role *********

			; Network message received from previous role
			(recv (cat "13" "pvno=5" "msg-type=13" usr 
				(cat "1" "tkt-vno=5" is (cat "kvno-is" st))
				(cat (enc "26" ui-sk n-usr-tgse is (hash "8" ut-sk)))
			))

			; Hash message sent by previous role reception
			; ** THIS MESSAGE IS ADDED BY US FOR BOOKEEPING BETWEEN USER ROLES **
			; REQUIRES key-usage value that is different from all other messages
			; including previous bookeeping message
			(recv (hash "hash from user-tgse to user-cse role" "kvno-usr"
				(enc "hash record" usr as tgs is n-usr-ase n-usr-tgse time-usr-tgse
					ut-sk ui-sk
					(cat "1" "tkt-vno=5" is (cat "kvno-is" st)) 
					(hash "1030" (ltk usr as)))))

			; **************************************************************
			; *************** Perform CSE Exchange ******************

			; AP-REQ - does not include
			;			ap-options - we include "2" as one of the options
			;						 for is returning the optional message
			;						 AP-REP
			;			ticket (ST) for is =
			;				realm - is's realm (same as usr's)
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
				(cat "1" "tkt-vno=5" is (cat "kvno-is" st))
				(cat (enc "2" "authenticator-vno=5" usr time-usr-cse (hash "11" ui-sk)))))
 
			; AP-REP - does not include
			;			enc-part =
			;				cusec - usr's local time in microseconds (acknowledgement)
			;				subkey - sub session key to use for subsequent application
			;						 data transfer; optional in RFC4120 pg. 87
			;				seq-number - next sequence number from seq-number in AP-REQ
			(recv (cat "15" "pvno=5" "msg-type=15" 
				(cat (enc "27" time-usr-cse (hash "12" ui-sk)))
				(cat "21" "pvno=5" "msg-type=21"
					(enc "28" "success" sec-usr pwd time-is-cse (hash "13" ui-sk)))
				))
		)
	)

	;;; IS Role
	;
	; Summary: IS receives authentication request from User and
	; verifies the authenticator and ST. Then, IS forwards request
	; to ISC counterpart. ISC establishes new identity record and
	; then sends back identity record to IS.

	(defrole is
		(vars (usr tgs is isc sec-usr name) (time-usr-cse n-is-isc pwd 
			time-kas-query time-is-cse text) (ui-sk skey))
		(trace

			; ******************************************************
			; ***************** Receive CSE-Req ********************

			; AP-REQ - does not include
			;			ap-options - we include "2" as one of the options
			;						 for is returning the optional message
			;						 AP-REP
			;			ticket (ST) for is =
			;				realm - is's realm (same as usr's)
			;				enc-part = 
			;					Plaintext =
			;						kvno - version of is's LTK used for encryption
			;					Ciphertext =
			;						flags - assigned options for ticket bdta on "kdc-options" from TGS-REQ
			;						crealm - usr's realm
			;						transited - realms that ticket passed through (for RTGTs)
			;						authtime, starttime, endtime, renew-till - times for ticket lifetime bdta
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
				(cat "1" "tkt-vno=5" is (cat "kvno-is" (enc "3" ui-sk usr 
					(hash "2" (ltk is tgs))) ))
				(cat (enc "2" "authenticator-vno=5" usr time-usr-cse (hash "11" ui-sk)))))


			; **************************************************
			; ***************** Perform IIE ********************
			;
			; Message to "isc" role regarding user's request for identity creation
			; and response message from "isc" role containing the established
			; identity
			;
			; REQUIRES key-usage value that is different from all other messages
			; including previous messages

			(send (cat "6" "pvno=5" "msg-type=6" "kvno-is-isc" 
				(enc "19" usr is time-usr-cse 
					n-is-isc (hash "1032" (ltk is isc)))
				(hash "hash of IIE-REQ"  
					(cat "6" "pvno=5" "msg-type=6" "kvno-is-isc"
					(enc "19" usr is time-usr-cse 
						n-is-isc (hash "1032" (ltk is isc)))) 
					(hash "1033" (ltk is isc)))))

			(recv (cat "7" "pvno=5" "msg-type=7" "kvno-is-isc" 
				(enc "18" usr is sec-usr pwd 
					time-usr-cse time-kas-query n-is-isc (hash "1034" (ltk is isc)))
				(hash "hash of IIE-REP"
					(cat "7" "pvno=5" "msg-type=7" "kvno-is-isc" 
					(enc "18" usr is sec-usr pwd 
						time-usr-cse time-kas-query n-is-isc 
						(hash "1034" (ltk is isc))))
					(hash "1035" (ltk is isc)))
			))

			; ***************************************************
			; ***************** Send CSE-Rep ********************

			; AP-REP - does not include
			;			enc-part =
			;				cusec - usr's local time in microseconds (acknowledgement)
			;				subkey - sub session key to use for subsequent application
			;						 data transfer; optional in RFC4120 pg. 87
			;				seq-number - next sequence number from seq-number in AP-REQ

			(send (cat "15" "pvno=5" "msg-type=15" 
				(cat (enc "27" time-usr-cse (hash "12" ui-sk)))
				(cat "21" "pvno=5" "msg-type=21"
					(enc "28" "success" sec-usr pwd time-is-cse (hash "13" ui-sk)))
				))
	
		)
		(uniq-orig n-is-isc)
		(non-orig (ltk is isc))
	)


	; **** RFC Kerberos Administration Protocol - Database Ticket Acquisition (DTA) ******
	; ****									   and Database Query (DBQ) ******************

    ;;; ISC Role
    ;
    ; Summary: ISC uses its secondary realm identity to perform
	; the RFC Kerberos Administration Protocol to establish an
	; identity record for the user in the Secondary Realm. It
	; first performs the DTA to retrieve a Database Ticket (DT) 
	; for use in authenticating and using the Seconadary Realm
	; KAS. 
	(defrole isc
		(vars (usr is isc sec-as sec-kas sec-usr name) (time-usr-cse n-is-isc 
			n-isc-dta time-isc-query time-kas-query pwd text) (dt mesg) (ik-sk skey))
		(trace

			; ****************************************
			; ********* Receive IIE-Request **********

			(recv (cat "6" "pvno=5" "msg-type=6" "kvno-is-isc" 
				(enc "19" usr is time-usr-cse 
					n-is-isc (hash "1032" (ltk is isc)))
				(hash "hash of IIE-REQ"  
					(cat "6" "pvno=5" "msg-type=6" "kvno-is-isc"
					(enc "19" usr is time-usr-cse 
						n-is-isc (hash "1032" (ltk is isc)))) 
					(hash "1033" (ltk is isc)))))

			; ********************************
			; ********* Perform DTA **********
			;
			; NOTE: This exchange is defined bdta on the little information gathered
			;		from various sources regarding MIT Kerberos. It is a special case
			;		of the ASE. We therefore adopted the RFC-specification techniques- 
			;		to the defined exchange. 

			(send (cat "10" "pvno=5" "msg-type=10" (cat isc sec-kas n-isc-dta)))


			(recv (cat "11" "pvno=5" "msg-type=11" isc 
				(cat "1" "tkt-vno=5" sec-kas (cat "kvno-sec-kas" dt)) 
				(cat "kvno-isc" (enc "25" ik-sk n-isc-dta sec-kas 
					(hash "3" (ltk isc sec-as))
				))))

			; ********************************
			; ********* Perform DBQ **********
			;
			; NOTE: This exchange is defined bdta on the little information gathered
			;		from various sources regarding MIT Kerberos. It is a special case
			;		of the CSE. We adopted the RFC-specification to the exchange. To
			;		carry the query and query response, we use the "KRB-PRIV"
			;		message to send the application data, i.e., the "kadmin" query.			

			(send (cat "14" "pvno=5" "msg-type=14" "ap-options=2" ; tag "2" means that service should send reply
				(cat "1" "tkt-vno=5" sec-kas (cat "kvno-sec-kas" dt)) 
				(cat (enc "2" "authenticator-vno=5" isc
					(hash (cat "21" "pvno=5" "msg-type=21" 
						(enc "28" "kadmin" "addprinc" "-pw" pwd sec-usr time-isc-query (hash "13" ik-sk))) 
							(hash "10" ik-sk)) 
						time-isc-query (hash "11" ik-sk)))
				(cat "21" "pvno=5" "msg-type=21" 
					(enc "28" "kadmin" "addprinc" "-pw" pwd sec-usr time-isc-query (hash "13" ik-sk)))
				))

			(recv (cat "15" "pvno=5" "msg-type=15" 
				(cat (enc "27" time-isc-query (hash "12" ik-sk)))
				(cat "21" "pvno=5" "msg-type=21"
					(enc "28" "kadmin" "addprinc" "success" sec-usr pwd time-kas-query (hash "13" ik-sk)))
				))

			; *********************************
			; ********* Send IIE-Rep **********

			(send (cat "7" "pvno=5" "msg-type=7" "kvno-is-isc" 
				(enc "18" usr is sec-usr pwd 
					time-usr-cse time-kas-query n-is-isc (hash "1034" (ltk is isc)))
				(hash "hash of IIE-REP"
					(cat "7" "pvno=5" "msg-type=7" "kvno-is-isc" 
					(enc "18" usr is sec-usr pwd 
						time-usr-cse time-kas-query n-is-isc 
						(hash "1034" (ltk is isc))))
					(hash "1035" (ltk is isc)))
			))
		)
		(uniq-orig n-isc-dta pwd)
		;(uniq-orig n-isc-dta sec-usr pwd)
		(non-orig (ltk is isc))
	)


    ;;; Sec-AS Role
    ;
    ; Summary: Sec-as receives request from ISC for a Database Ticket (DT)
	; and in response, provides a component with a copy of the contents
	; of the DT as well as the DT.
	(defrole sec-as
		(vars (isc sec-as sec-kas name) (n-isc-dta text) (ik-sk skey))
		(trace

			; ********************************
			; ********* Perform DTA **********
			;
			; NOTE: This exchange is defined bdta on the little information gathered
			;		from various sources regarding MIT Kerberos. It is a special case
			;		of the ASE. We therefore adopted the RFC-specification techniques- 
			;		to the defined exchange. 

			(recv (cat "10" "pvno=5" "msg-type=10" (cat isc sec-kas n-isc-dta)))

			(send (cat "11" "pvno=5" "msg-type=11" isc 
				(cat "1" "tkt-vno=5" sec-kas (cat "kvno-sec-kas" (enc "3" "init" ik-sk isc
					(hash "2" (ltk sec-kas sec-as)))))
				(cat "kvno-isc" (enc "25" ik-sk n-isc-dta sec-kas (hash "3" (ltk isc sec-as))))
			))
		)
		(uniq-gen ik-sk)
	)

    ;;; Sec-KAS Role
    ;
    ; Summary: Sec-KAS receives DBQ request from ISC containing an
	; authenticator, the DT, and the query encrypted under the KRB-PRIV.
	; In response, the KAS sends the response from the query and
	; the authentication response.
	(defrole sec-kas
		(vars (isc sec-as sec-kas sec-usr name) (time-isc-query time-kas-query pwd text) 
			(ik-sk skey))
		(trace

			; ********************************
			; ********* Perform DBQ **********
			;
			; NOTE: This exchange is defined bdta on the little information gathered
			;		from various sources regarding MIT Kerberos. It is a special case
			;		of the CSE. We adopted the RFC-specification to the exchange. To
			;		carry the query and query response, we use the "KRB-PRIV"
			;		message to send the application data, i.e., the "kadmin" query.			

			(recv (cat "14" "pvno=5" "msg-type=14" "ap-options=2" ; tag "2" means that service should send reply
					(cat "1" "tkt-vno=5" sec-kas (cat "kvno-sec-kas" (enc "3" "init" ik-sk isc
						(hash "2" (ltk sec-kas sec-as)))))
				(cat (enc "2" "authenticator-vno=5" isc
					(hash (cat "21" "pvno=5" "msg-type=21" 
						(enc "28" "kadmin" "addprinc" "-pw" pwd sec-usr time-isc-query (hash "13" ik-sk))) 
							(hash "10" ik-sk)) 
						time-isc-query (hash "11" ik-sk)))
				(cat "21" "pvno=5" "msg-type=21" 
					(enc "28" "kadmin" "addprinc" "-pw" pwd sec-usr time-isc-query (hash "13" ik-sk)))
				))


			(send (cat "15" "pvno=5" "msg-type=15" 
				(cat (enc "27" time-isc-query (hash "12" ik-sk)))
				(cat "21" "pvno=5" "msg-type=21"
					(enc "28" "kadmin" "addprinc" "success" sec-usr pwd time-kas-query (hash "13" ik-sk)))
				))
		)
	)

	; Eliminates shapes where multiple pairs of is and isc
	; Each IS shares LTK with exactly one ISC.
	(defrule one-is-isc
		(forall ((z z1 strd) (is isc name))
			(implies
				(and (p "is" z 4)
					(p "is" "is" z is)
					(p "is" "isc" z isc)
					(p "is" z1 4)
					(p "is" "is" z1 is)
					(non (ltk is isc)))
				(= z z1))
		)
	)

	; Eliminate shape where adding same identity record twice
	; Database does not establish duplicate identity records for same name
	(defrule one-identity
		(forall ((z z1 strd) (isc sec-kas sec-as sec-usr name))
			(implies
				(and (p "sec-kas" z 2)
					(p "sec-kas" "sec-usr" z sec-usr)
					(p "sec-kas" "isc" z isc)
					(p "sec-kas" z1 2)
					(p "sec-kas" "isc" z1 isc)
					(non (ltk sec-kas sec-as))
					(non (ltk isc sec-as)))
				(= z z1))
		)
	)

)


; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;  DEFGOALS ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;


	; Security Goal 1
	; Authentication Goal for User 
	(defgoal rfk-rfcspec-cse
		(forall ((usr tgs as is sec-usr name) (n-usr-ase n-usr-tgse time-usr-tgse time-usr-cse 
			pwd text) (ut-sk ui-sk skey) (z0 strd))
			(implies
				(and (p "user-cse" z0 4) (p "user-cse" "usr" z0 usr) (p "user-cse" "tgs" z0 tgs)
					(p "user-cse" "is" z0 is) (p "user-cse" "as" z0 as) 
					(p "user-cse" "sec-usr" z0 sec-usr) (p "user-cse" "n-usr-ase" z0 n-usr-ase) 
					(p "user-cse" "n-usr-tgse" z0 n-usr-tgse)
					(p "user-cse" "time-usr-tgse" z0 time-usr-tgse) 
					(p "user-cse" "time-usr-cse" z0 time-usr-cse)
					;(p "user-cse" "time-is-cse" z0 time-is-cse)
					(p "user-cse" "pwd" z0 pwd) (p "user-cse" "ut-sk" z0 ut-sk) 
					(p "user-cse" "ui-sk" z0 ui-sk)
					(non (ltk usr as)) (non (ltk tgs as)) (non (ltk is tgs)) 
				)
				(exists ((z1 strd))
					(and (p "is" z1 4) (p "is" "usr" z1 usr) (p "is" "tgs" z1 tgs) 
						(p "is" "is" z1 is)
						;(p "is" "time-usr-cse" z1 time-usr-cse) ; removing conclusion makes goal true
						;(p "is" "time-is-cse" z1 time-is-cse)
						(p "is" "sec-usr" z1 sec-usr) (p "is" "pwd" z1 pwd)
						(p "is" "ui-sk" z1 ui-sk)
					)
				)
			)
		)
	)

	; Security Goal 2 - IS and ISC
	; Authentication Goal between IS and ISC
	(defgoal rfk-rfcspec-cse
		(forall (( time-is-cse n-is-isc time-kas-query pwd text) 
			(usr is isc tgs sec-usr name) (z0 strd))
			(implies
				(and (p "is" z0 4) 
					;(p "is" "time-usr-cse" z0 time-usr-cse)
					(p "is" "n-is-isc" z0 n-is-isc) (p "is" "pwd" z0 pwd)
					(p "is" "time-kas-query" z0 time-kas-query)
					(p "is" "time-is-cse" z0 time-is-cse) 
					(p "is" "usr" z0 usr)
					(p "is" "tgs" z0 tgs) (p "is" "is" z0 is)
					(p "is" "isc" z0 isc) (p "is" "sec-usr" z0 sec-usr)
					(non (ltk is isc)))
				(exists ((z2 strd))
					(and (p "isc" z2 6) (p "isc" "usr" z2 usr) 
						(p "isc" "is" z2 is) (p "isc" "isc" z2 isc) (p "isc" "sec-usr" z2 sec-usr) 
						;(p "isc" "time-usr-cse" z2 time-usr-cse) 
						(p "isc" "n-is-isc" z2 n-is-isc)
						(p "isc" "pwd" z2 pwd))
				)
			)
		)
	)


	; Security Goal 3
	; Authentication Goal of ISC and Sec-AS/Sec-KAS
	; Completion of isc strand means completion of sec-as and sec-kas strands

	(defgoal rfk-rfcspec-cse
		(forall ((time-usr-cse n-is-isc n-isc-dta time-isc-query 
			time-kas-query pwd text) (usr is isc sec-usr sec-as sec-kas name) 
			(ik-sk skey) (z1 strd))
			(implies
				(and (p "isc" z1 6) (p "isc" "usr" z1 usr) 
					(p "isc" "is" z1 is) (p "isc" "isc" z1 isc) (p "isc" "sec-usr" z1 sec-usr) 
					(p "isc" "sec-as" z1 sec-as) (p "isc" "sec-kas" z1 sec-kas)
					(p "isc" "n-is-isc" z1 n-is-isc) (p "isc" "n-isc-dta" z1 n-isc-dta)
					(p "isc" "time-usr-cse" z1 time-usr-cse) 
					(p "isc" "time-isc-query" z1 time-isc-query)
					(p "isc" "time-kas-query" z1 time-kas-query) 
					(p "isc" "pwd" z1 pwd) (p "isc" "ik-sk" z1 ik-sk)	
					(non (ltk is isc)) (non (ltk isc sec-as)) (non (ltk sec-kas sec-as))
					(uniq n-isc-dta) (uniq pwd))
				(or 
					(exists ((z2 z3 strd))
						(and (p "sec-as" z2 2) (p "sec-as" "isc" z2 isc) (p "sec-as" "sec-as" z2 sec-as)
						(p "sec-as" "sec-kas" z2 sec-kas) (p "sec-as" "n-isc-dta" z2 n-isc-dta)
						(p "sec-as" "ik-sk" z2 ik-sk)
						;
						(p "sec-kas" z3 2) (p "sec-kas" "sec-as" z3 sec-as)
						(p "sec-kas" "sec-kas" z3 sec-kas) (p "sec-kas" "isc" z3 isc)
						(p "sec-kas" "sec-usr" z3 sec-usr) (p "sec-kas" "pwd" z3 pwd) 
						(p "sec-kas" "time-isc-query" z3 time-isc-query)
						(p "sec-kas" "time-kas-query" z3 time-kas-query)
						(p "sec-kas" "ik-sk" z3 ik-sk))
					)
					(exists ((z2 z3 strd))
						(and (p "as" z2 2) (p "as" "usr" z2 isc) (p "as" "as" z2 sec-as)
							(p "as" "tgs" z2 sec-kas) (p "as" "n-usr-ase" z2 n-isc-dta)
							(p "as" "ut-sk" z2 ik-sk)
							;
							(p "sec-kas" z3 2) (p "sec-kas" "sec-as" z3 sec-as)
							(p "sec-kas" "sec-kas" z3 sec-kas) (p "sec-kas" "isc" z3 isc)
							(p "sec-kas" "sec-usr" z3 sec-usr) (p "sec-kas" "pwd" z3 pwd) 
							(p "sec-kas" "time-isc-query" z3 time-isc-query)
							(p "sec-kas" "time-kas-query" z3 time-kas-query)
							(p "sec-kas" "ik-sk" z3 ik-sk))
					)
				)
			)
		)
	)


	; Security Goal 4
	; Secrecy Goal for user-password
	(defgoal rfk-rfcspec-cse
		(forall ((usr tgs is as isc sec-usr sec-as sec-kas name) (n-usr-ase n-usr-tgse 
			time-usr-tgse time-is-cse n-is-isc n-isc-dta time-isc-query pwd text) 
			(ut-sk ui-sk ik-sk skey) (z0 z1 z2 z3 strd))
			(implies
				(and (p "user-cse" z0 4) (p "user-cse" "usr" z0 usr) (p "user-cse" "tgs" z0 tgs)
					(p "user-cse" "is" z0 is) (p "user-cse" "as" z0 as) 
					(p "user-cse" "sec-usr" z0 sec-usr)	(p "user-cse" "n-usr-ase" z0 n-usr-ase) 
					(p "user-cse" "n-usr-tgse" z0 n-usr-tgse)
					(p "user-cse" "time-usr-tgse" z0 time-usr-tgse) 
					;(p "user-cse" "time-usr-cse" z0 time-usr-cse) 
					(p "user-cse" "pwd" z0 pwd) (p "user-cse" "time-is-cse" z0 time-is-cse)
					(p "user-cse" "ut-sk" z0 ut-sk) (p "user-cse" "ui-sk" z0 ui-sk) 
					;
					(p "is" z1 4) (p "is" "usr" z1 usr) (p "is" "tgs" z1 tgs)
					(p "is" "is" z1 is) (p "is" "isc" z1 isc)
					(p "is" "sec-usr" z1 sec-usr)
					;(p "is" "time-usr-cse" z1 time-usr-cse) 
					(p "is" "n-is-isc" z1 n-is-isc) (p "is" "time-is-cse" z1 time-is-cse)
					(p "is" "pwd" z1 pwd) (p "is" "ui-sk" z1 ui-sk)
					;
					(p "isc" z2 6) (p "isc" "usr" z2 usr)
					(p "isc" "is" z2 is) (p "isc" "isc" z2 isc) (p "isc" "sec-usr" z2 sec-usr) 
					(p "isc" "sec-kas" z2 sec-kas) (p "isc" "sec-as" z2 sec-as) 
					;(p "isc" "time-usr-cse" z2 time-usr-cse) 
					(p "isc" "n-isc-dta" z2 n-isc-dta) 
					(p "isc" "time-isc-query" z2 time-isc-query) (p "isc" "n-is-isc" z2 n-is-isc)
					(p "isc" "pwd" z2 pwd) (p "isc" "ik-sk" z2 ik-sk)
					;
					(p "" z3 1) (p "" "x" z3 pwd)
					(non (ltk usr as)) (non (ltk tgs as)) (non (ltk is tgs)) (non (ltk is isc))
					(non (ltk isc sec-as)) (non (ltk sec-kas sec-as)) (uniq n-is-isc) (uniq n-isc-dta) 
					;(uniq sec-usr) 
					(uniq pwd))
				(false)))
	)

(comment "Old Security Goal 3 - Authentication of ISC with SR-AS / SR-KAS"
	(defgoal rfk-rfcspec-cse
		(forall ((time-usr-cse n-is-isc n-isc-dta time-isc-query 
			time-kas-query pwd text) (usr is isc sec-usr sec-as sec-kas name) 
			(ik-sk skey) (z1 strd))
			(implies
				(and (p "isc" z1 6) (p "isc" "usr" z1 usr) 
					(p "isc" "is" z1 is) (p "isc" "isc" z1 isc) (p "isc" "sec-usr" z1 sec-usr) 
					(p "isc" "sec-as" z1 sec-as) (p "isc" "sec-kas" z1 sec-kas)
					(p "isc" "n-is-isc" z1 n-is-isc) (p "isc" "n-isc-dta" z1 n-isc-dta)
					(p "isc" "time-usr-cse" z1 time-usr-cse) 
					(p "isc" "time-isc-query" z1 time-isc-query)
					(p "isc" "time-kas-query" z1 time-kas-query) 
					(p "isc" "pwd" z1 pwd) (p "isc" "ik-sk" z1 ik-sk)	
					(non (ltk is isc)) (non (ltk isc sec-as)) (non (ltk sec-kas sec-as))
					(uniq n-isc-dta) (uniq pwd))
				(exists ((z2 z3 strd))
					(and (p "sec-as" z2 2) (p "sec-as" "isc" z2 isc) (p "sec-as" "sec-as" z2 sec-as)
					(p "sec-as" "sec-kas" z2 sec-kas) (p "sec-as" "n-isc-dta" z2 n-isc-dta) 
					(p "sec-as" "ik-sk" z2 ik-sk)
					;
					(p "sec-kas" z3 2) (p "sec-kas" "sec-as" z3 sec-as)
					(p "sec-kas" "sec-kas" z3 sec-kas) (p "sec-kas" "isc" z3 isc)
					(p "sec-kas" "sec-usr" z3 sec-usr) (p "sec-kas" "pwd" z3 pwd) 
					(p "sec-kas" "time-isc-query" z3 time-isc-query)
					(p "sec-kas" "time-kas-query" z3 time-kas-query)
					(p "sec-kas" "ik-sk" z3 ik-sk))
				)
			)
		)
	)
)
