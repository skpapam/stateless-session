/**
 * stateless-session 
 * Secure client stored session management middleware
 * Copyright 2016 Skevos Papamichail
 * Licensed under MIT license
 */


"use strict";

/**
 * Dependencies
 */
var i_encrypt = require('i-encrypt');
var cookieparser = require('cookie');
var compare = require('i-compare-strings');
var onheaders = require('on-headers');
var filter = require('object-filter');
var model = require('./session')
var ie;
/**
 * Module exports a new StatelessSession instance
 */
module.exports = (function () {
	/**
	 * Constructor
	 */
	function StatelessSession() {
		StatelessSession.options = {};
	}

	/**
	 * Middleware function
	 * @param options Object
	 * @returns {Function} Middleware
	 */
	StatelessSession.prototype.middleware = function(options) {
		options = options || {};
		StatelessSession.options.autostart = options.autostart || false;
		StatelessSession.options.c_options = options.c_options || {
			"path":"/"
		};
		StatelessSession.options.prefix = options.prefix || "s_d_";
		ie = i_encrypt({
			key : options.key,
			debug : options.debug || false
		})
		
		return function(req, res, next){
			//Parse cookies into an object
			var sobj = StatelessSession.parseCookies(req);
			
			//Create a new session instance and assign it to req.session
			req.session = new model.Session(sobj);
			
			//Autostart session if needed
			if(StatelessSession.options.autostart){
				req.session.start();
			}
			
			//Listener for headers in order to save the cookies
			onheaders(res, function(){
				StatelessSession.saveCookies(req,res);
			});
			
			//call next middleware in line
			next();
		}
	};
	
	/**
	 * Parses session related cookies ( if any ) from request
	 * @param req Request Object
	 * @returns {JSON} decrypted data
	 */
	StatelessSession.parseCookies = function(req){
		var token;
		var cookies = req.headers['cookie']
	   				? cookieparser.parse(req.headers['cookie'])
	   				: {};
	   	
	   	//Select only session related cookies
	   	cookies = filter(cookies,function(v,k){
	   		return k.indexOf(StatelessSession.options.prefix) === 0
	   	});;

	   	//if no cookies found return null
	   	StatelessSession.cookies_count = Object.keys(cookies).length;
	   	if(!StatelessSession.cookies_count){
	   		return null;
	   	}

	   	//merge cookies' values into a single token string
	   	for(var i=1; i<=StatelessSession.cookies_count; i++){
	   		token = token ? token + cookies[StatelessSession.options.prefix+i] : cookies[StatelessSession.options.prefix+i];
	   	}
	   	
	   	//decrypt token and return the resulted object
	   	return ie.decrypt(token);
	}
	
	/**
	 * Writes session related cookies to response if needed
	 * @param req Request Object
	 * @param res Response Object
	 */
	StatelessSession.saveCookies = function(req, res) {
		var session_obj, 
			token,
	   		token_length,
	   		cookies,
	   		cookies_added=0,
	   		cookie,
	   		delete_options,
	   		chunk = 0,
	   		start = 0;
		
	    //load cookies and exclude the ones related to session
		cookies = res.getHeader('Set-Cookie') || [];
		cookies = cookies.filter(function(c){
			return c.indexOf(StatelessSession.options.prefix) !== 0;
		});
	    		
		//create session related cookies
		if(!!req.session && req.session.hasStarted()){
			//The session data that needs to be saved
			session_obj = req.session.exportObject() || {};
			
			//Create a string with encrypted session data
			token = ie.encrypt(session_obj);
			token_length = !!token?token.length:0;
			
			//Break string into multiple cookies with balanced data load.
			
			while(start<token_length){
				//serialize cookie
				cookie = cookieparser.serialize(
						StatelessSession.options.prefix+(cookies_added+1),
						token.slice(start,chunk?(start+chunk):token_length).toString('utf8'),
						StatelessSession.options.c_options
				);
				
				//if cookie's length is big reduce chunk size
				if(cookie.length>4000){
					chunk = chunk === 0 ? 3900 : chunk - 150; 
					continue;
				}
				
				//push cookie into the array
				cookies.push(cookie);
				cookies_added++;
				start += chunk?chunk:token_length;
			}
		}
		
		//delete old and unused session cookies
		delete_options = JSON.parse(JSON.stringify(StatelessSession.options.c_options));
		delete_options.expires = new Date(1);
		while(cookies_added < StatelessSession.cookies_count){
			cookies.push(cookieparser.serialize(StatelessSession.options.prefix+(cookies_added+1),"",delete_options));
			cookies_added++;
		}
		
		
		res.setHeader('Set-Cookie', cookies)
		
	};
	
	//return StatelessSession instance
	return new StatelessSession;

}());
