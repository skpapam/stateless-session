# stateless-session

Secure client stored session management middleware. The module provides session management 
functionality for stateless server applications. This is achieved by encrypting the session
data and storing/reading chunks of it ( depending on data size ) in an appropriate number 
of cookies.

## Installation

```bash
	npm install stateless-session -save
```

## Usage 

It is realy simple to use just type : 
```js
	var stateless-session = require('stateless-session');
	
	app.use(stateless-session.middleware());
```
and you are good to go. This will setup the session for the current request.

You can access the session object and assign data to it later in your application by using
the `req.session` object. 

```js
	var stateless-session = require('stateless-session');
	
	app.use(stateless-session.middleware());
	
	app.get('/login',function(req,res){
		req.session.start();
		req.session.username = "skpapam";
		req.session.email = "contact@skevosp.me";
		res.send("You are now logged in and your session id is "+req.session.getId());
	});
	
	app.get('/hidden',function(req,res){
		if(req.session.hasStarted()){
			res.send("This is your private page "+req.session.username)
		}
		else{
			res.send("This page is private. You have to login first")
		}
	});
	
	app.get('/logout',function(req,res){
		req.session.stop();
		res.send("You are now logged out. Your last activity was at : "+req.session.lastActivity());
	});
```

As you can see in the above example session tracking does not start by default in order
to provide **authorization functionality** to applications.

When the user visits the `/login` we call `req.session.start()` that starts the session 
and assigns a session id in this case our session data will be encrypted and 
passed through a single cookie in our case ( small data size ) to our client.  
If we don t do that there will be no cookies returned to client thus all session variables 
will be lost otherwise 

When the user visits our `/hidden` page we check if the session has started and 
return the appropriate message.

When the user visits the `/logout` page we stop the session tracking which will cause our cookies
to expire thus our data to delete.

You can ignore this feature and provide **guest-like sessions** by setting the **autostart** 
option to **true** ( default is false )

```js
	var stateless-session = require('stateless-session');
	
	app.use(stateless-session.middleware({
		'autostart' : true
	}));
	
	app.use(function(req, res, next) {
		req.session.name = "Skevos";
	});
```	

The options that you can pass to the middleware are the following :
* `key {String}` Overrides the default module key for encryption
* `autostart {Boolean}` switch from authorized sessions ( false ) to guest ones ( true )
default value is false
* `c_options {Object}` Cookie related options for more see [cookie](https://www.npmjs.com/package/cookie). 
By default **path** option is set to **'/'**
		
## Limitations

Even though this module manages to overcome the 4KB cookie size limitation by evenly 
distributing the data to multiple cookies based on its size there is still the overall
size limitation per domain which is 80KB.

## License
MIT
Copyright &copy 2016 Skevos Papamichail &lt;contact@skevosp.me&gt; (www.skevosp.me) 
