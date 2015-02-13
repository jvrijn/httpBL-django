
from middleware import httpBLMiddleware
import config
from django.conf import settings
from django.test import TestCase, override_settings
from django.test.client import RequestFactory

from time import sleep


class HttpBLMiddlewareTestCase(TestCase):
    
    def setUp(self):
        self.middleware = httpBLMiddleware()
        self.factory = RequestFactory()
    
    
    def test_random_ip(self):
        # We are looking for an IPV4 style address. That means:
        # - 4 octets
        # - each octet is a decimal number from 0 to 255
        # - octets separated by dots
        
        # since random numbers are generated, we should run this many times.
        for i in range(1000):
            ip = self.middleware._get_random_ip()
            
            try:
                iplist = ip.split('.')
            except:
                pass
            
            self.assertTrue(len(iplist) == 4)
            self.assertTrue(int(iplist[0]) >= 0)
            self.assertTrue(int(iplist[0]) <= 255)
            self.assertTrue(int(iplist[1]) >= 0)
            self.assertTrue(int(iplist[1]) <= 255)
            self.assertTrue(int(iplist[2]) >= 0)
            self.assertTrue(int(iplist[2]) <= 255)
            self.assertTrue(int(iplist[3]) >= 0)
            self.assertTrue(int(iplist[3]) <= 255)
 
    
    def test_get_ip_plain(self):
        # Make sure we are not getting a random IP
        if getattr(settings, 'HTTPBL_RANDOM_IP', False):
            settings.HTTPBL_RANDOM_IP = False
        
        # Test against standard header
        if getattr(settings, 'HTTPBL_IP_HEADER', False):
            del settings.HTTP_RANDOM_IP
            
        # Create the HttpRequest
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Run the request
        ip = self.middleware._get_ip(request)
        self.assertEqual(ip, '127.0.0.1')
        
    
    @override_settings(HTTPBL_RANDOM_IP=False)
    @override_settings(HTTPBL_IP_HEADER='X_FORWARDED_FOR')
    def test_get_ip_different_header(self):            
        # Create the HttpRequest
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        request.META['X_FORWARDED_FOR'] = '127.1.1.1'
        
        # Run the request
        ip = self.middleware._get_ip(request)
        self.assertEqual(ip, '127.1.1.1')
 
 
    @override_settings(HTTPBL_RANDOM_IP=True)
    @override_settings(DEBUG=True)
    def test_get_ip_random(self):
        # Create the HttpRequest
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Run the request
        ip = self.middleware._get_ip(request)
        self.assertNotEqual(ip, '127.0.0.1')    
    
    
    def test_valid_cached_data_no_httpBL(self):
        # test with no httpBL dict in the session
        # happens when this is a new user on the site
        request = self.factory.get('/')
        request.session = {}
        self.assertFalse(self.middleware._valid_cached_data(request))
        
        
    def test_valid_cached_data_httpBL_error(self):
        # test with httpBL dict that has an error in the session
        # happens when this is a new user on the site
        request = self.factory.get('/')
        request.session = {}
        
        # create an error version of the httpBL dict
        httpBL = {}
        httpBL['error'] = True
        
        # stuff the httpBL dict into the session
        request.session['httpBL'] = httpBL
        
        self.assertFalse(self.middleware._valid_cached_data(request))
        
    
   
    def test_is_valid_ip_octet(self):
        # test that all number 0 - 255 pass
        for i in range(0,256):
            self.assertTrue(self.middleware._is_valid_ip_octet(i))
        
        # test that a number greater than 255 fails
        self.assertFalse(self.middleware._is_valid_ip_octet('256'))
        
        # test that a number less than 0 fails
        self.assertFalse(self.middleware._is_valid_ip_octet('-1'))
        
        #test that a combination of letters and numbers fails 
        self.assertFalse(self.middleware._is_valid_ip_octet('2a6'))
        

    def test_spilt_ip(self):
        # test with basic ip address
        self.assertEqual(self.middleware._split_ip('127.0.0.1'), ['127','0','0','1'])
        
        #test with a malformed ip address
        self.assertIsNone(self.middleware._split_ip('127:0:0:1'))
        self.assertIsNone(self.middleware._split_ip('127:0.0.1'))
        
        # test with an invalid octet
        self.assertIsNone(self.middleware._split_ip('256.0.0.1'))
        
        #test with a ip address that is too long
        self.assertIsNone(self.middleware._split_ip('127:0.0.1.1'))

        #test with a ip address that is too short
        self.assertIsNone(self.middleware._split_ip('127:0.0.'))
        
    
    def test_reverse_ip(self):
        # test with a correct ip address
        self.assertEqual(self.middleware._reverse_ip('127.0.0.1'), '1.0.0.127')
        
        # test with an invalid octet
        self.assertIsNone(self.middleware._reverse_ip('256.0.0.1'))
        
    
    def test_contact_httpBL(self):
        # Create a query with a test key
        query = 'abcdefghijkl.1.1.1.127.dnsbl.httpbl.org'
        error, result = self.middleware._contact_httpBL(query)
        self.assertFalse(error)
        self.assertEqual(result, '127.1.1.1')
    
    
    def test_analyze_httpBL_result_bad_result(self):
        # If the first octet is different from 127, we have an error response
        httpBL_result = '128.0.0.1'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertTrue(httpBL['error'])
    
    
    def test_analyze_httpBL_result_searchengine(self):
        httpBL_result = '127.1.1.0'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertFalse(httpBL['is_suspicious'])
        self.assertFalse(httpBL['is_harvester'])
        self.assertFalse(httpBL['is_comment_spammer'])
        self.assertNotEqual(httpBL['searchengine'], False)
    
    
    def test_analyze_httpBL_result_suspicious(self):
        httpBL_result = '127.1.1.1'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertTrue(httpBL['is_suspicious'])
        self.assertFalse(httpBL['is_harvester'])
        self.assertFalse(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])
    
    def test_analyze_httpBL_result_harvester(self):
        httpBL_result = '127.1.1.2'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertFalse(httpBL['is_suspicious'])
        self.assertTrue(httpBL['is_harvester'])
        self.assertFalse(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])
    
    
    def test_analyze_httpBL_result_suspicious_harvester(self):
        httpBL_result = '127.1.1.3'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertTrue(httpBL['is_suspicious'])
        self.assertTrue(httpBL['is_harvester'])
        self.assertFalse(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])
    
    
    def test_analyze_httpBL_result_comment_spammer(self):
        httpBL_result = '127.1.1.4'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertFalse(httpBL['is_suspicious'])
        self.assertFalse(httpBL['is_harvester'])
        self.assertTrue(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])
    
    
    def test_analyze_httpBL_result_suspicious_comment_spammer(self):
        httpBL_result = '127.1.1.5'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertTrue(httpBL['is_suspicious'])
        self.assertFalse(httpBL['is_harvester'])
        self.assertTrue(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])
    
    
    def test_analyze_httpBL_result_harvester_comment_spammer(self):
        httpBL_result = '127.1.1.6'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertFalse(httpBL['is_suspicious'])
        self.assertTrue(httpBL['is_harvester'])
        self.assertTrue(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])
    
    
    def test_analyze_httpBL_result_suspicious_harvester_comment_spammer(self):
        httpBL_result = '127.1.1.7'
        httpBL = self.middleware._analyze_httpBL_result(httpBL_result)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertTrue(httpBL['is_suspicious'])
        self.assertTrue(httpBL['is_harvester'])
        self.assertTrue(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])

   
    def test_query_httpBL_API_numeric_ip(self):
        ip = 4
        httpBL = self.middleware._query_httpBL_API(ip)
        self.assertTrue(httpBL['error'])

        
    def test_query_httpBL_API(self):
        ip = '127.1.1.7'
        httpBL = self.middleware._query_httpBL_API(ip)
        self.assertFalse(httpBL['error'])
        self.assertFalse(httpBL['unknown'])
        self.assertTrue(httpBL['is_suspicious'])
        self.assertTrue(httpBL['is_harvester'])
        self.assertTrue(httpBL['is_comment_spammer'])
        self.assertFalse(httpBL['searchengine'])


    @override_settings(HTTPBL_RANDOM_IP = False)
    @override_settings(HTTPBL_IP_HEADER = 'X_FORWARDED_FOR')
    @override_settings(HTTPBL_CACHE_RESULTS_SECONDS = 1)
    def test_process_request(self):
        # Create the request object
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        request.META['X_FORWARDED_FOR'] = '127.1.1.7'
        
        #create a fake session object for storing the httpBL data
        request.session = {}
        
        # Have the middleware process the request
        self.middleware.process_request(request)
        
        # check if the httpBL dict is in the session of the request.
        httpBL = request.session.get('httpBL', None)
        self.assertNotEqual(httpBL, None)
        
        # Next lets test that the timestamp works.
        # if we run process_request again immediately, nothing should change
        prev_time = httpBL['timestamp']
        
        self.middleware.process_request(request)
        httpBL = request.session.get('httpBL', None)
        
        self.assertEqual(prev_time, httpBL['timestamp'])
        
        # now sleep and try again, we should get a new record
        sleep(settings.HTTPBL_CACHE_RESULTS_SECONDS)
        
        self.middleware.process_request(request)
        httpBL = request.session.get('httpBL', None)
        
        self.assertNotEqual(prev_time, httpBL['timestamp'])
        
        

    
    
    


        