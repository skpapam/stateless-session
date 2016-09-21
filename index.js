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
var crypto = require('crypto');
var cookieparser = require('cookie');
var compare = require('scmp');
var onheaders = require('on-headers');
var filter = require('object-filter');
var model = require('./session')

/**
 * Module exports a new StatelessSession instance
 */
module.exports = (function () {
	/**
	 * Constructor
	 */
	function StatelessSession() {
		StatelessSession.server_key = crypto.randomBytes(32);
		StatelessSession.options = {};
	}

	/**
	 * Middleware function
	 * @param options Object
	 * @returns {Function} Middleware
	 */
	StatelessSession.prototype.middleware = function(options) {
		options = options || {};
		StatelessSession.options.key = options.key || StatelessSession.server_key;
		StatelessSession.options.autostart = options.autostart || false;
		StatelessSession.options.c_options = options.c_options || {
			"path":"/"
		};
		StatelessSession.options.prefix = options.prefix || "s_d_";
	  
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
	   	return StatelessSession.decrypt(token);
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
	   		chunk=0,
	   		start = 0,
	   		total = 0;
		
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
			token = StatelessSession.encrypt(session_obj);
			token_length = token.length;
			
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
					chunk = chunk === 0 ? 4000 : chunk - 50; 
					continue;
				}
				
				//push cookie into the array
				cookies.push(cookie);
				total += cookie.length;
				cookies_added++;
				start += chunk?chunk:token_length;
			}
		}
		
		//delete old and unused session cookies
		delete_options = JSON.parse(JSON.stringify(StatelessSession.options.c_options));
		delete_options.expires = new Date(1);
		while(cookies_added < StatelessSession.cookies_count){
			cookies.push(cookieparser.serialize(StatelessSession.options.prefix+(i+1),"",delete_options));
			cookies_added++;
		}
		
		//Save cookies or throw an exception if data exceeds broswer's limitations.
		if(cookies_added > 300){
			throw new Error('stateless-session : Can not write '+cookies_added+' cookies to response. Only 300 allowed.');
		}
		else if(total > 80000){
			throw new Error('stateless-session : Can not write '+Math.ceil(total*100/1024)/100+'KB of cookies to response. Only 80KB are allowed.');
		}
		else{
			res.setHeader('Set-Cookie', cookies)
		}
	   
	};

	/**
	 * Encrypts an object
	 * @param session_obj Object to encrypt
	 * @returns {String} the resulted token
	 */
	StatelessSession.encrypt = function(session_obj){
		//serialize
		var original = JSON.stringify(session_obj);
		
		//initialization vector
		var vector = new Buffer(crypto.randomBytes(16));
		
		//new cipher
		var cipher = crypto.createCipheriv('aes256', StatelessSession.options.key, vector);
		
		//the encrypted text
		var encrypted = cipher.update(original,'utf8','base64') + cipher.final('base64');
		
		//a hash for the combination of encrypted text and initialization vector
		var hash = crypto.createHmac('sha256', StatelessSession.options.key).update(encrypted+vector.toString('base64')).digest('base64');
	   
		//return token ecrypted.vector.hash
		return encrypted + "." + vector.toString('base64') + "." + hash;
	};
   
	/**
	 * Decrypts a token
	 * @param token string
	 * @returns {JSON} object
	 */
	StatelessSession.decrypt = function(token){
		var decipher;
		// split token and save each value (encrypted text,vector,hash)
		var t=token.split(".");
		var encrypted = t[0];
		var vector = new Buffer(t[1], 'base64');
		var hash = t[2];
		
		// calculate hash
		var new_hash = crypto.createHmac('sha256', StatelessSession.options.key).update(encrypted+t[1]).digest('base64');
	   
		//check data integrity by comparing the two hash values 
		if(!compare(hash,new_hash)){
			return null;
		}
		
		//new decipher
		decipher = crypto.createDecipheriv('aes256', StatelessSession.options.key, vector);
	    
		//return the resulted object
		return JSON.parse(decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8'));
	};
	
	StatelessSession.balancedSize = function(){
		var empty_cookie = cookieparser.serialize(
				StatelessSession.options.prefix+'100',
				'a',
				StatelessSession.options.c_options
		);
		return 4000 - new Buffer(empty_cookie,'utf8').length;
	};
	
	//return StatelessSession instance
	return new StatelessSession;

}());
