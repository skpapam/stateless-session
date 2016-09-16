/**
 * stateless-session
 * A stateless session management for node.js
 * Copyright 2016 Skevos Papamichail
 * Licensed under MIT license
 */

"use strict";
/**
 * Dependencies
 */
var crypto = require('crypto');

/**
 * Module exports the Session model
 */
exports.Session = Session;


/**
 * Session model
 * @param obj 
 */
function Session(obj){
	//initiate session variables and user data
	var sesobj = obj || {
		  "timestamp" : new Date().getTime(),
		  "data" : {}
	};
	for (var key in sesobj.data) {
		if (hasOwnProperty.call(sesobj.data, key)){
			this[key] = sesobj.data[key];
		}
	}
	
	Session._timestamp = sesobj.timestamp;
	Session._started = !!sesobj.id;
	Session._id = sesobj.id;
};

/**
 * Prototype function get session id
 * @returns {String} ID or null
 */
Session.prototype.getId = function(){
	return Session._id;
};

/**
 * Prototype function get timestamp of last activity
 * @returns {Timestamp}
 */
Session.prototype.lastActivity = function(){
	return Session._timestamp;
};

/**
 * Prototype function check if session has started
 * @returns {Boolean}
 */
Session.prototype.hasStarted = function(){
	return Session._started;
};

/**
 * Prototype function that returns session's 
 * variables and data as an object
 * @returns {Object}
 */
Session.prototype.exportObject = function(){
	var obj;
	//if session hasn't been started return null
	if(!Session._started){
		return null;
	}
	
	//initialize returned object
	obj = {
			"timestamp" : new Date().getTime(),
			"data" : {},
			"id" : Session._id
	};
	
	//pass user data to the object
	for (var key in this) {
		if (typeof this[key] !== "function"){
			obj.data[key] = this[key];
		}
	}
	
	//return it
	return obj;
};

/**
 * Prototype function that starts the session
 * by setting the flag _started to true and
 * generating a random _id
 */
Session.prototype.start = function(){
	Session._id = crypto.randomBytes(16).toString('base64');
	Session._started = true;
};

/**
 * Prototype function that stops the session
 * By reseting the _id and setting
 * _started flag to false 
 */
Session.prototype.stop = function(){
	Session._started = false;
	Session._id = null;
};

