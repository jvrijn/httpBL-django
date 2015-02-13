from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

import logging
import random
import socket
import time

import config

# setup the logger
logger = logging.getLogger('httpBL')




class httpBLMiddleware(object):

    # -------------------------------------------------------------------
    def _get_random_ip(self):
        # create a random IP and return. Can be used in debugging
        ip = ''
        for x in range(0, 3):
            ip = ip + str(random.randint(1,255)) + '.'
        ip = ip + str(random.randint(1,255))
        return ip


    # -------------------------------------------------------------------
    def _get_ip(self, request):
        # Finds the remote IP address of the requesting client.
        # -  This may not be in the normal header if a reverse proxy is configured. Configure the name of the header
        #    with settings.HTTPBL_IP_HEADER = 'xxx' where xxx is the header name
        # -  For debug purposes, we can also produce random IPs with settings.DEBUG = True and settings.HTTPBL_RANDOM_IP = True
        
        # First check if we need a random IP.
        if settings.DEBUG:
            need_random_ip = getattr(settings, 'HTTPBL_RANDOM_IP', False)
            if need_random_ip:
                return self._get_random_ip()
            
        # End of random IP assigment
            
        # If we made it this far, we'll try and figure out the real IP.
        # Check if we need to look at a different header than the default
        ip_header = getattr(settings, 'HTTPBL_IP_HEADER', 'REMOTE_ADDR')
        
        # Attempt to get the IP address from the request meta data
        if ip_header in request.META:
            return request.META[ip_header]
        else:
            return None


    # -------------------------------------------------------------------
    def _valid_cached_data(self, request):
        # Checks if we have cached data in the session and if it is still valid.
        if 'httpBL' in request.session:
            last_state = request.session['httpBL']
        
            # There is a httpBL dict in the session
            # check if last check was successful, if not we'll retry
            if not last_state['error']:
                # check the required cache duration
                cache_duration = getattr(settings, 'HTTPBL_CACHE_RESULTS_SECONDS', config.cache_duration)
                
                # check if the last successful check was less than our refresh rate
                if time.time() - last_state['timestamp'] < cache_duration:
                    return True
                else:
                    # Previous data has expired
                    return False
            else:
                # last time we checked we got an error
                return False
        else:
            # No httpBL dict found
            return False


    # -------------------------------------------------------------------
    def _is_valid_ip_octet(self, s):
        # try to convert string based octet to a number
        try:
            i = int(s)
        except ValueError:
            return False
        
        # return true if the number is between 0 and 255, false otherwise
        return 0 <= i <= 255
    


    # -------------------------------------------------------------------
    def _split_ip(self,ip):
        
        # Try to convert string to list
        try:
            iplist = ip.split('.')
        except:
            # return None in case of error
            return None
        
        # check if every list element is a valid octet
        for ip in iplist:
            if not self._is_valid_ip_octet(ip):
                # if not a valid octet, return None
                return None
        
        # Check the list is the right length
        if len(iplist) == 4:
            # return the list
            return iplist
        else:
            return None


    # -------------------------------------------------------------------
    def _reverse_ip(self, ip):
        # We need to put the IP numbers in reverse order to use the API, 
        # so a.b.c.d becomes d.c.b.a
        
        # First split the ip from a sytring to a tuple
        iplist = self._split_ip(ip)
        if iplist:
            # now reverse the tuple
            iplist.reverse()
            
            # join it back to a string and return
            return ".".join(iplist)
        else:
            return None
        

    # -------------------------------------------------------------------    
    def _contact_httpBL(self, query):
        # Make the query
        # returns error_flag, api_response 

        try:
            httpBL_response = socket.gethostbyname(query)
        except socket.gaierror:
            # We did not get a return value, httpBL does not know this IP
            # We are done in this scenario, so return
            return False, None
        except:
            # catch all other possible errors
            # There was an error in the query, fail silently
            return True, None
        return False, httpBL_response
        
    
    # -------------------------------------------------------------------
    def _analyze_httpBL_result(self, httpBL_response):
        httpBL = {}
        httpBL['response'] = 'none'
        httpBL['unknown'] = True
        httpBL['error'] = False
        httpBL['is_suspicious'] = False
        httpBL['is_harvester'] = False
        httpBL['is_comment_spammer'] = False
        httpBL['threat_score'] = int(0)
        httpBL['last_activity'] = int(0)
        httpBL['searchengine'] = False
        httpBL['timestamp'] = time.time()
        
        # httpBL responds with a 'fake' ip address in which each octet has a meaning.
        resultlist = self._split_ip(httpBL_response)
        
        # Check if we have an error response. If so register the error and fail silently
        if resultlist[0] != '127':
            # We received an error
            httpBL['error'] = True
            httpBL['response'] = 'ERROR'
        else:
            # We have a valid response from httpBL
            # response format can be found here:
            #    http://www.projecthoneypot.org/httpbl_api.php
            # Populate the httpBL dict
            httpBL['response'] = httpBL_response
            httpBL['unknown'] = False
            httpBL['error'] = False
            httpBL['is_suspicious'] = int(resultlist[3]) & 1 == 1
            httpBL['is_harvester'] = int(resultlist[3]) & 2 == 2
            httpBL['is_comment_spammer'] = int(resultlist[3]) & 4 == 4
            httpBL['threat_score'] = int(resultlist[2])
            httpBL['last_activity'] = int(resultlist[1])
            if resultlist[3] == '0':
                # This is a search engine
                if int(resultlist[2]) > len(config.SEARCH_ENGINES)-1:
                    httpBL['searchengine'] = 'unknown search engine'
                else:
                    httpBL['searchengine'] = config.SEARCH_ENGINES[resultlist[2]]
            else:
                httpBL['searchengine'] = False
        return httpBL

    
    
    
    
    # -------------------------------------------------------------------    
    def _query_httpBL_API(self, ip):
        # Gets an opinion from the http:BL API
        # ip is a string representation of an IPV4 addresss
        
        # Initialize a results dict
        # IP addresses are innocent until proven guilty because http:BL does not maintain records for all IP addresses.
        httpBL = {}
        httpBL['error'] = False
        httpBL['timestamp'] = time.time()

        # Reverse the ip address as required by the API
        rev_ip = self._reverse_ip(ip)
        
        if rev_ip:
            # form the query string
            query = settings.HTTPBLKEY + "." + rev_ip + "." + config.HTTPBL_DOMAIN
            
            # get the opininion from the httpBL service
            query_error, httpBL_reponse = self._contact_httpBL(query)
            
            if not query_error:
                if httpBL_reponse:
                    # We received a response from httpBL
                    # This means the IP is known to httpBL
                    # Process the result
                    httpBL = self._analyze_httpBL_result(httpBL_reponse)
                    
                    if not httpBL['error']:
                        
                        # log the results
                        if httpBL['is_suspicious']:
                            logger.info("httpBL: %s is suspicious" % ip)
                            
                        if httpBL['is_harvester']:
                            logger.info("httpBL: %s is a harvester" % ip)
                            
                        if httpBL['is_comment_spammer']:
                            logger.info("httpBL: %s is a comment spammer" % ip)
                            
                        if httpBL['threat_score'] > 0:
                            logger.info("httpBL: %s has a threat score of %s" % (ip, str(httpBL['threat_score'])))
                            
                        if httpBL['searchengine']:
                            logger.info("httpBL: %s is a search engine - %s" % (ip, httpBL['searchengine']))

                    else:
                        # We received an error response from the httpBL API
                        logger.error("httpBL: Received an invalid resonse from the serivce for query: %s" % query)
                        
                else:
                    # httpBL does not have a record for this ip. That is good news.
                    httpBL['unknown'] = True
                    logger.info("httpBL: httpBL does not have a record for %s" % ip)
                    
            else:
                # There was a problem querying the httpBL API
                httpBL['error'] = True
                logger.error("httpBL: an error occured contacting the service at %s" % query)
        else:
            # There was a problem reversing the ip address.
            httpBL['error'] = True
            logger.error("httpBL: Could not reverse the ip address, ip address is likely malformed. Need a regular IPV4 address.")
                       
        return httpBL
    
    
    
    def process_request(self, request):
        
        # First check if we have valid cached data
        if self._valid_cached_data(request):
            # There is cached data in the session and it has not expired, so do nothing
            return None
        else:
            # There is no (valid) cached data, so lets contact httpBL
            #  Extract the requestor's IP address
            ip = self._get_ip(request)
            
            # Query the httpBL API
            httpBL = self._query_httpBL_API(ip)
            
            # Conditionally save the result into the session
            if httpBL['error']:
                # only save if there is no existing httpBL data in the session
                # that way an older valid entry may continue to represent the ip
                request.session['httpBL'] = request.session.get('httpBL', httpBL)
            else:
                # no error, so save the new data
                request.session['httpBL'] = httpBL
        
        return None            
