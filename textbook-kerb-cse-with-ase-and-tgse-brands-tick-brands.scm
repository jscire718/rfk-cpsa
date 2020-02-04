; Textbook Kerberos Standard Protocol
;	* In this version, we add the "TGT" and "ST" brands to the tickets to the version
;	* containing the ASE and TGSE brands in user's response messages.
;	* This results in the elimination of both the Man-in-the-Middle attacks 
;	* (Problematic Shapes #1 and #2) and the Anomaly (Problematic Shape #3).
;
;
; 	** Variable Definitions
;
;		-	Principal variables
; 				usr	= User principal
; 				tgs = TGS principal
;				as = AS principal
; 				srv = Service principal
;
;		-	Tickets
; 				tgt = Ticket Granting Ticket
; 				st = Service Ticket
;
;		-	Session keys
; 				ut-sk = User-TGS session Key
; 				us-sk = User-SRV session key
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


(herald textbook-kerb-cse-with-ase-and-tgse-brands-tick-brands (bound 20) (limit 8000))

(defprotocol textbook-kerb-cse-with-ase-and-tgse-brands-tick-brands basic

; ********** Textbook Kerberos Standard Protocol - Authentication Service Exchange (ASE) **********


	;;; User ASE Role
	;
	; Summary: User sends request for TGT to AS
	; and AS responds with session key component
	; encrypted with User's LTK and a TGT.

	(defrole user-ase
		(vars (usr tgs as name) (n-usr-ase text) (tgt mesg) (ut-sk skey))
		(trace

			(send (cat usr tgs n-usr-ase))
			(recv (cat (enc "AS to U" tgs n-usr-ase ut-sk (ltk usr as)) tgt))

			; ***********************************************************
			; ******* Hash message transmission to user-tgse role *******
			(send (hash "hash from user-ase to user-tgse" 
				(enc "hash record" usr tgs as n-usr-ase ut-sk tgt (ltk usr as)))) 

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
			; Perform ASE
			(recv (cat usr tgs n-usr-ase))
			(send (cat (enc "AS to U" tgs n-usr-ase ut-sk (ltk usr as)) 
				(enc "TGT" usr ut-sk (ltk tgs as)) ))

		)
		; User-TGS session key should always be uniquely originating
		(uniq-orig ut-sk)
	)

; ********** Textbook Kerberos Standard Protocol - Ticket-Granting Service Exchange (TGSE) **********

	;;; User TGSE Role
	;
	; Summary: User uses received TGT and User-TGS
	; session key to request a ST from the TGS for the SRV.
	; User receives response message with two components: a User-SRV session
	; key encrypted with the User-TGS session key and the ST.

	(defrole user-tgse
		(vars (usr srv tgs as name) (n-usr-ase n-usr-tgse time-usr-tgse text) 
			(tgt st mesg) (ut-sk us-sk skey))
		(trace

			; *********************************************************************************
			; *** Network message reception and hash message reception from user-ase role ***

			; Network message received in previous role 
			(recv (cat (enc "AS to U" tgs n-usr-ase ut-sk (ltk usr as)) tgt))

			; Hash message sent by previous role
			(recv (hash "hash from user-ase to user-tgse" 
				(enc "hash record" usr tgs as n-usr-ase ut-sk tgt (ltk usr as))))   


			; ******************************************
			; ************* Perform TGSE ***************

			(send (cat srv n-usr-tgse (enc usr time-usr-tgse ut-sk) tgt))
			(recv (cat (enc "TGS to U"srv n-usr-tgse us-sk ut-sk) st))


			; ***********************************************************
			; ******* Hash message transmission to user-cse role ********

			; Hash message transmission to next user role
			(send (hash "hash from user-tgse to user-cse role" 
				(enc "hash record" usr tgs as srv n-usr-ase n-usr-tgse time-usr-tgse 
				us-sk ut-sk st (ltk usr as))))

		)
		; User's nonce in TGSE request must always be fresh
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

			; *********************************************
			; *************** Perform TGSE ****************

			(recv (cat srv n-usr-tgse (enc usr time-usr-tgse ut-sk) 
				(enc "TGT" usr ut-sk (ltk tgs as)) ) )
			(send (cat (enc "TGS to U" srv n-usr-tgse us-sk ut-sk) 
				(enc "ST" usr us-sk (ltk srv tgs)) ) )

		)
		; User-SRV session key should always be uniquely originating
		(uniq-orig us-sk)
	)


; ********** Textbook Kerberos Standard Protocol - Client-Service Exchange (CSE) **********

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
		(vars (usr tgs srv as name) (n-usr-ase n-usr-tgse
			time-usr-tgse time-usr-cse text) (st mesg) 
            (us-sk ut-sk skey))
		(trace

			; ********************************************************************************
			; ******** Network message and hash message reception from user-tgse role ********

			; Network message received from previous role
			(recv (cat (enc "TGS to U" srv n-usr-tgse us-sk ut-sk) st))

			; Hash message sent by previous role reception
			(recv (hash "hash from user-tgse to user-cse role" 
				(enc "hash record" usr tgs as srv n-usr-ase n-usr-tgse time-usr-tgse 
				us-sk ut-sk st (ltk usr as))))


			; *********************************************
			; *************** Perform CSE *****************

			; Perform CSE 
			(send (cat (enc usr time-usr-cse us-sk) st))
			(recv (enc time-usr-cse time-usr-cse us-sk))

		)
	)

	;;; Service Role
	;
	; Summary: Service receives authentication request from User and
	; verifies the authenticator and ST. 
    ;
    ; OPTIONAL: Service sends User's timestamp in response. Although
	;			optional, we include this message for our purposes
	;			with RFC Kerberos and RFK.

	(defrole srv
		(vars (usr srv tgs name) (time-usr-cse text) (us-sk skey))
		(trace

			; ********************************************
			; *************** Perform CSE ****************

			; Perform CSE
			(recv (cat (enc usr time-usr-cse us-sk) 
				(enc "ST" usr us-sk (ltk srv tgs)) ))
			(send (enc time-usr-cse time-usr-cse us-sk))
		)
	) 

)




; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;  ANALYSIS QUERIES SHOWING PROBLEMATIC SHAPES ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ;

; First Man-in-the-Middle (Problematic Shape #1) is eliminated and the remaining shapes are not problematic
(defskeleton textbook-kerb-cse-with-ase-and-tgse-brands-tick-brands
	(vars (tgt st mesg) (time-usr-cse n-usr-tgse time-usr-tgse n-usr-ase text)
		(usr tgs srv as name) (ut-sk us-sk skey))
	(defstrand user-cse 4 (usr usr) (tgs tgs) (srv srv) 
		(as as) (st st) (n-usr-tgse n-usr-tgse)
		(n-usr-ase n-usr-ase) (time-usr-cse time-usr-cse) 
		(time-usr-tgse time-usr-tgse) (ut-sk ut-sk) (us-sk us-sk) )
	(non-orig (ltk usr as) (ltk tgs as) (ltk srv tgs) )
)

; NEW - Anomaly shape now eliminated
(defskeleton textbook-kerb-cse-with-ase-and-tgse-brands-tick-brands
	(vars (n-usr-tgse time-usr-tgse text)
		(usr tgs srv as name) (ut-sk us-sk skey))
	(defstrand tgs 2 (usr usr) (tgs tgs) (srv srv) 
		(as as) (n-usr-tgse n-usr-tgse)
		(time-usr-tgse time-usr-tgse) (ut-sk ut-sk) (us-sk us-sk) )
	(uniq-orig us-sk)
	(non-orig (ltk usr as) (ltk tgs as) (ltk srv tgs) )
)

; Second Man-in-the-Middle (Problematic Shape #2) is eliminated
(defskeleton textbook-kerb-cse-with-ase-and-tgse-brands-tick-brands
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