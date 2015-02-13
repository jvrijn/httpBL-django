# README

Hi! Thanks for checking out **httpBL-django**, a django app that integrates [http:BL](https://www.projecthoneypot.org/httpbl.php) into your Django project. **http:BL** is a service that identfies comment spammers and content harvesters. By using this app with the service, you have another tool to combat these malicious web users.

Below, I'll first show you how you would use this, followed by installation and configuration.

## How To Use httpBL-django

**httpBL-django** inserts a python dict named httpBL in the request.session object. If you have a view that needs special processing for comment spammers or content harvesters, follow the following steps. 

If you are following along with your project, make sure you go through the installation and configuration steps first, they are further down this page.

###Step 1 - Find the httpBL dict in the session
~~~python
def myview(request):
	...
	httpBL = request.session.get('httpBL', None)
	
	# Check if we have the httpBL data
	if httpBL:
		...
~~~


###Step 2 - Check the httpBL data is valid
Check if the httpBL data is valid by checking the value assigned to the 'error' key in the httpBL dict. Building on the previous example:

~~~python
def myview(request):
	...
	httpBL = request.session.get('httpBL', None)
	
	# Check if we have the httpBL data
	if httpBL:
		
		if not httpBL['error']:
			# No error, so we we can use the rest of the httpBL data
			...
		else:
			# We had an error in retrieving the httpBL data,
			# it is up to you to decide how you want to handle that.
			...
~~~

###Step 3 - Use the httpBL data to control the view
There are 5 keys that can be used to check the status of the visiting IP address:

Key                   | Meaning
--------------------- | -------------
'unknown'             | This is potentially good news, http:BL has not found malicious behavior from this IP address. 
'is\_harvester'       | The IP address belongs to a known content harvester.
'is\_comment\_spammer'| The IP address belongs to a known comment spammer.
'is\_suspicious'      | Suspicious behavior has been observed for this IP address.
'searchengine'        | The IP address is known to belong to a search engine.

The 'is\_harvester', 'is\_comment\_spammer', 'is\_suspicious' keys may all be true at the same time.

The value for 'searchengine' is False if the IP is not deemed to be a search engine or is a string containing the name of the search engine, if it is deemed to be a search engine.

Again, building on the previous example:

~~~python
def myview(request):
	...
	httpBL = request.session.get('httpBL', None)
	
	# Check if we have the httpBL data
	if httpBL:
		
		if not httpBL['error']:
			# No error, so we we can use the rest of the httpBL data
			
			if httpBL['is_harvester']:
				# Redirect the browser to another page
				return HttpResponseRedirect('http://www.google.com')
			elif httpBL['is_comment_spammer']:
				form = MyFormWithCaptcha()
			else:
				form = MyForm()
				
			...
			
		else:
			# We had an error in retrieving the httpBL data,
			# it is up to you to decide how you want to handle that.
			...
~~~


##Installation and Configuration

At this time you cannot install use pip to install **httpBL-django**. So, the easiest way is to download the zip file from the links on the right, or use git clone.

Next move the httpBL folder you'll find in the zip file into the root folder of your django project. So it becomes an app inside your project.

Now **httpBL-django** needs to be configured in your project's settings.py

###1. Add httpBL to INSTALLED_APPS
Because **httpBL-django** uses sessions to store the data, make sure django.contrib.sessions is enabled. If you do not use django.contrib.sessions, you'll need to make sure that there is a dict called 'session' in the HttpRequest (though this has not been tested).

~~~python
INSTALLED_APPS = (
	 ...
    'django.contrib.sessions',
	 ...
    'httpBL',
)
~~~

###2. Add httpBL to MIDDLEWARE_CLASSES

~~~python
MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    ...
    'httpBL.middleware.httpBLMiddleware',
    ...
)
~~~

###3. Mandatory Constants in settings.py
There is only one mandatory setting at this time.

~~~python
HTTPBLKEY = '<your httpBL API key>'
~~~

You can obtain a key by setting up an account on the [http:BL website]((https://www.projecthoneypot.org/httpbl.php))


###4. Optional Constants in settings.py
The following optional constants are available:

####HTTPBL\_IP\_HEADER
Especially when you are in a setup behind a load balancing reverse proxy, you may find that the proxy does not rewrite the REMOTE_ADDR header in the HTTP request. That means that httpBL will be checking the (internal) IP address of your reverse proxy, which is not what you want.

Often, your reverse proxy will include an additional header such as X-FORWARDED-FOR that will list the IP address of the browser requesting the page. Find this header and tell **httpBL-django** about it using the HTTPBL_IP_HEADER constant.

Note that **httpBL-django** expects the ip address as a IPv4 string, like '127.0.0.1'.

Example:

~~~python
HTTPBL_IP_HEADER = 'X-FORWARDED-FOR'
~~~

####HTTPBL\_CACHE\_RESULTS\_SECONDS
To improve performance and reduce load on the http:BL service, results are effectively cached in the session. Every httpBL dict gets stored in it's relevant session and contains a timestamp. On each new request the timestamp is checked to see if the data has expired.

If you do not configure the cache duration, the following defaults will be used:

* if DEBUG == True, default cache duration is 10 seconds.
* if DEBUG == False, default cache duration is 1 week.

You can override the setting as follows:

~~~python
HTTPBL_CACHE_RESULTS_SECONDS = float(<time in seconds>)
~~~


####HTTPBL\_RANDOM\_IP
This setting is meant only for developers on this module. When set to True, **httpBL-django** will generate a random ip address for each request. This setting is ignored when DEBUG == FALSE

##Logging
**httpBL-django** can automatically generate logs for you. It generates INFO and ERROR log messages.

Level | Description
----- | -----------
INFO  | Warning: very verbose. Will tell you httpBL results for every request. Make sure you have enough disk space if you turn this on.
ERROR | Only communicates errors that are the result of malformed ip addresses, connection failures etc.

Below is an example configuration for settings.py that generates both an error log and an info log.

~~~python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'default_log_format': {
            'format': '%(asctime)s - %(message)s',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        },
    },
    'handlers': {
        'httpBL_handler': {
            'level': 'INFO',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'formatter': 'default_log_format',
            'filename': 'httpBL.log',
            'utc': True,
            'when': 'midnight',            
        },
        'error_log_handler': {
            'level': 'ERROR',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'formatter': 'default_log_format',
            'filename': 'error.log',
            'utc': True,
            'when': 'midnight',
        },
    },
    'loggers': {
        'httpBL': {
            'handlers': ['httpBL_handler', 'error_log_handler'],
            'level': 'INFO',
            'propagate': False,
        },
    }
~~~

To stop the info log, just remove or comment out the whole 'httpBL_handler' section. 

In this example ERROR messages are written into the project wide error log. 

Each log entry carries the prefix 'httpBL:'.

##Dependencies
* django >= 1.7.4 - may work in earlier versions, but it has not been tested.
* Python 2.7 - not tested in Python 3.x

I would much appreciate if you let me know if you are using this successfully on different versions of the the above platforms.

##Change history
Feb 12, 2015 Initial commit

