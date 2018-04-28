#!/usr/bin/env python

########################################################################################################
### LICENSE
########################################################################################################
#
# findmyhash.py - v 1.1.2
#
# This script is under GPL v3 License (http://www.gnu.org/licenses/gpl-3.0.html).
#
# Only this source code is under GPL v3 License. Web services used in this script are under
# different licenses. 
#
# If you know some clause in one of these web services which forbids to use it inside this script,
# please contact me to remove the web service as soon as possible.
#
# Developed by JulGor ( http://laxmarcaellugar.blogspot.com/ )
# Mail: bloglaxmarcaellugar AT gmail DOT com
# twitter: @laXmarcaellugar
#

########################################################################################################
### IMPORTS
########################################################################################################

try:
    import sys
    import hashlib
    import urllib2
    import getopt
    import os
    from os import path
    from urllib import urlencode
    from re import search, findall
    from random import seed, randint
    from base64 import decodestring, encodestring
    from cookielib import LWPCookieJar
    import signal
    import requests
    from bs4 import BeautifulSoup as bs
    import re
    from termcolor import colored
except:
    print """
Execution error:

  You required some basic Python libraries. 
  
  This application use: sys, hashlib, urllib, urllib2, os, re, random, getopt, base64, cookielib, signal, requests, bs4, termcolor.
  Please, check if you have all of them installed in your system.

"""
    sys.exit(1)

try:
    from httplib2 import Http
except:
    print """
Execution error:

  The Python library httplib2 is not installed in your system. 
  
  Please, install it before use this application.

"""
    sys.exit(1)

try:
    from libxml2 import parseDoc
except:
    print """
Execution error:

  The Python library libxml2 is not installed in your system. 
  
  Because of that, some plugins aren't going to work correctly.
  
  Please, install it before use this application.

"""



########################################################################################################
### CONSTANTS
########################################################################################################

MD4 	= "md4"
MD5 	= "md5"
SHA1 	= "sha1"
SHA224	= "sha224"
SHA256 	= "sha256"
SHA384	= "sha384"
SHA512 	= "sha512"
RIPEMD	= "rmd160"
LM 	    = "lm"
NTLM	= "ntlm"
MYSQL	= "mysql"
CISCO7	= "cisco7"
JUNIPER = "juniper"
GOST	= "gost"
WHIRLPOOL = "whirlpool"
LDAP_MD5  = "ldap_md5"
LDAP_SHA1 = "ldap_sha1"

HASH_LIST=[MD4,MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD,LM,NTLM,MYSQL,CISCO7,JUNIPER,GOST,WHIRLPOOL,LDAP_MD5,LDAP_SHA1]
COLORS=["red","blue","green","cyan","magenta","yellow","white"]
USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Crazy Browser 1.0.5)",
    "curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
    "Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 Firefox/5.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 Firefox/4.0b8pre",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
    "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
    "Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]

CACHE_FILENAME="passes_found.txt"
write_cache="write"
read_cache="read"
########################################################################################################
### CRACKERS DEFINITION
########################################################################################################


class GROMWEB: 

    name = 		"gromweb"
    url = 		"http://gromweb.com"
    supported_algorithm = [MD5, SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        if alg == MD5:
            url = "http://md5.gromweb.com/?md5=%s" % (hashvalue)
        elif alg == SHA1:
            url="https://sha1.gromweb.com/?hash=%s" %(hashvalue)
        # Make the request
        data = do_HTTP_request ( url ,lib="requests")
        response=data.text
        # Analyze the response
        html = re.search(".*succesfull.*\n<em.*", response).group(0)
        soup = bs(html,"lxml")
        response=soup.find("em").get_text()
        return response


class MY_ADDR:

    name = 		"my-addr"
    url = 		"http://md5.my-addr.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None
        url = 'http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php'


        headers={"Accept-Language": "en-US,en;q=0.5",
                 "Upgrade-Insecure-Requests": 1,
                 "Connection": "close",
                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                 "Host": "md5.my-addr.com", "Referer": "http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php",
                 "y": 15,
                 "x": 9,
                 "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
                 "md5": hashvalue}

        # Make the request
        response = do_HTTP_request ( url, httpheaders=headers,lib="requests",method="post" )
        # Analyze the response
        html = None
        if response is not None:
            html = response.text
        else:
            return None
        html = re.search(".*Hashed string.*", html)
        if html is not None:
            match = re.search(r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", html.group(0))
            return match.group().split('span')[2][3:-6]
        else:
            return None


class MD5DECRYPTION:

    name = 		"md5decryption"
    url = 		"http://md5decryption.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = self.url

        # Build the parameters
        params = { "hash" : hashvalue,
               "submit" : "Decrypt+It!" }

        # Make the request
        response = do_HTTP_request ( url, httpheaders=params,method="post" )

        # Analyze the response
        html = None
        if response:
            html = response.text
        else:
            return None

        match = search (r"Decrypted Text: </b>[^<]*</font>", html)

        if match:
            return match.group().split('b>')[1][:-7]
        else:
            return None


class MD5DECRYPT:

    name = 		"md5decrypt"
    url = 		"http://md5decrypt.net"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None
        hashtype="md5"
        email="wowljjx251m@opayq.com" # Change this
        code="b16ab64cab62f751"       # Change this
        # Build the URL
        url = "http://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=%s&code=%s" \
              % (hashvalue, hashtype, email, code)

        # Make the request
        response = do_HTTP_request ( url ,lib="requests")

        # Analyze the response
        html = None
        if response:
            return response.text
        else:
            return None


class HASHCRACK:

    name = 		"hashcrack"
    url = 		"http://hashcrack.com"
    supported_algorithm = [MD5, SHA1, MYSQL, LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://hashcrack.com/index.php"

        hash2 = None
        if alg in [LM, NTLM] and ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # Delete the possible starting '*'
        if alg == MYSQL and hash2[0] == '*':
            hash2 = hash2[1:]

        # Build the parameters
        params = { "auth" : "8272hgt",
               "hash" : hash2,
               "string" : "",
               "Submit" : "Submit" }

        # Make the request
        response = do_HTTP_request ( url, httpheaders=params,method="post" )
        # Analyze the response
        html = None
        if response:
            html = response.text
        else:
            return None

        match = search (r'<div align=center>"[^"]*" resolves to</div><br><div align=center> <span class=hervorheb2>[^<]*</span></div></TD>', html)
        if match:
            return match.group().split('hervorheb2>')[1][:-18]
        else:
            return None


class OPHCRACK:

    name = 		"ophcrack"
    url = 		"http://www.objectif-securite.ch"
    supported_algorithm = [LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Check if hashvalue has the character ':'


        # Ophcrack doesn't crack NTLM hashes. It needs a valid LM hash and this one is an empty hash.

        import json
        # Build the URL and the headers
        url = "https://www.objectif-securite.ch/en/ophcrack.php"
        headers={
                 "Accept":"application/json, text / javascript, * / *; q = 0.01".strip(),
                 "Connection":"keep-alive",
                 "Referer":"https://www.objectif - securite.ch / en / ophcrack.php".strip(),
                 "User-agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
                 "X-Requested-With":"XMLHttpRequest",
                 "Accept-Encoding":"gzip, deflate, br",
                 "Accept - Language":"en - US, en;q = 0.5",
                 "Content - Type":"application / json",
                 "DNT": 1,
                 "Host":"www.objectif - securite.ch".strip()
        }
        # Make the request
        response=""
        while response is not None:
            #response = do_HTTP_request ( url,method="post",httpheaders=headers )
            response=requests.post(url,data=headers,json=json.dumps({"value":hashvalue}))
            html=response.text
            soup = bs(html, 'lxml')
            res=soup.find("p", {"id": "info_hash"})
            #print(response.status_code)
            #print(res)
            #print(response.content)
            #match=re.search(".*Cracking result:.*",html)
            try:
                response.json()
            except:
                pass
            break
            #if match is not None:
            #    print match.group(0)
            #    break
        # Analyze the response
        '''
        html = None
        if response:
            html = response.text
        else:
            return None
        soup=bs(html,'lxml')
        print soup.find("p",{"id":"info_hash"}).find_next('i')
        match=re.search('<p id="info_hash".*',html)
        if match:
            print match.group(0)
        else:'''
        return None


class CMD5:

    name = 		"cmd5"
    url = 		"http://www.cmd5.org"
    supported_algorithm = [MD5, SHA1, SHA256, SHA512, MYSQL, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        global verbose
        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Look for hidden parameters
        response = do_HTTP_request ( "http://www.cmd5.org/" )
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*" />', html)
        viewstate = None
        if match:
            viewstate = match.group().split('"')[7]
        match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField1" id="ctl00_ContentPlaceHolder1_HiddenField1" value="[^"]*" />', html)
        ContentPlaceHolder1 = ""
        if match:
            ContentPlaceHolder1 = match.group().split('"')[7]

        match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField2" id="ctl00_ContentPlaceHolder1_HiddenField2" value="[^"]*" />', html)
        ContentPlaceHolder2 = ""
        if match:
            ContentPlaceHolder2 = match.group().split('"')[7]

        match = search(r'<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR".*" />',html)
        viewstategenerator = ""
        if match:
            viewstategenerator = match.group().split('"')[7]
        # Build the URL
        url = "http://www.cmd5.org/"

        hash2 = ""
        if alg == MD5:
            hash2 = hashvalue
        else:
            if ':' in hashvalue:
                hash2 = hashvalue.split(':')[1]

        # Build the parameters
        params = { "__EVENTTARGET" : "",
               "__EVENTARGUMENT" : "",
               "__VIEWSTATE" : viewstate,
               "__VIEWSTATEGENERATOR": viewstategenerator,
               "ctl00$ContentPlaceHolder1$TextBoxInput" : hash2,
               "ctl00$ContentPlaceHolder1$InputHashType" : alg,
               "ctl00$ContentPlaceHolder1$Button1" : "decrypt",
               "ctl00$ContentPlaceHolder1$HiddenField1" : ContentPlaceHolder1,
               "ctl00$ContentPlaceHolder1$HiddenField2" : ContentPlaceHolder2
                ,"Referer" : "http://www.cmd5.org/" }

        # Make the request
        response = do_HTTP_request ( url, httpheaders=params ,method="post")
       # print(response.text)
        # Analyze the response
        html = None
        if response:
            html = response.text
        else:
            return None

        match = search (r'<span id=\"ctl00_ContentPlaceHolder1_LabelAnswer\">.*</span>', html)
        if match:
            result=re.search(r">.*<br",match.group(0))
        else:
            return None

        if result:
            if verbose:
                print(result.group(0).split(">")[1].split('<')[0])
            return result.group(0).split(">")[1].split('<')[0]
        else:
            return None


class IBEAST:

    name = 		"ibeast"
    url = 		"http://www.ibeast.com"
    supported_algorithm = [CISCO7]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the headers
        url = "http://ibeast.com/tools/CiscoPassword/decrypt.php?txtPassword=%s&submit1=Submit" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url,lib="requests" )
        # Analyze the response
        html = None
        if response:
            html = response.text
        else:
            return None
        match = search (r'<font size="\+2">Your Password is [^<]*<br>', html)

        if match:
            return match.group().split('is ')[1][:-4]
        else:
            return None


class PASSWORD_DECRYPT:

    name = 		"password-decrypt"
    url = 		"http://password-decrypt.com"
    supported_algorithm = [CISCO7, JUNIPER]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the parameters
        url = ""
        params = None
        if alg == CISCO7:
            url = "http://password-decrypt.com/cisco.cgi"
            params = { "submit" : "Submit",
                "cisco_password" : hashvalue,
                "submit" : "Submit" }
        else:
            url = "http://password-decrypt.com/juniper.cgi"
            params = { "submit" : "Submit",
                "juniper_password" : hashvalue,
                "submit" : "Submit" }


        # Make the request
        response = do_HTTP_request ( url, method="post",httpheaders=params )

        # Analyze the response
        html = None
        if response:
            html = response.text
        else:
            return None

        match = search (r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', html)

        if match:
            return match.group().split('B>')[1][:-2]
        else:
            return None


class SANS:

    name = 		"sans"
    url = 		"http://isc.sans.edu"
    supported_algorithm = [MD5, SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""
        cookies = LWPCookieJar()
        handlers = [
            urllib2.HTTPHandler(),
            urllib2.HTTPSHandler(),
            urllib2.HTTPCookieProcessor(cookies)
            ]
        opener = urllib2.build_opener(*handlers)
        url = 'https://isc.sans.edu/tools/reversehash.html'

        httpheaders= { "User-Agent" : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0' }

        request = urllib2.Request(url,headers=httpheaders)

        response = opener.open(url)
        html = response.read()
        findtok= search(r'name="token" value="[a-f0-9]+" />',html)
        token= findtok.group().split('"')[3].split(' ')[0].strip()
        params= {
                "token" : token,
                "text" : hashvalue
                }
        data = urlencode(params)
        httpheaders["Referer"] = "http://isc.sans.edu/tools/reversehash.html"
        request = urllib2.Request(url,data,headers=httpheaders)

        response = opener.open(request)
        cookiefile="/tmp/cookies"
        try:
                cookies.save(cookiefile)
        except:
                print "Cookies not saved!?"

        html = response.read()
        match = search(r'.*=.*</p>',html)
        if match:
                #print match.group(0)[:-5].split('=')[1].strip()
                return match.group(0)[:-5].split('=')[1].strip()
        else:
            return None


class GOOG_LI:

    name = 		"goog.li"
    url = 		"http://goog.li"
    supported_algorithm = [MD5, MYSQL, SHA1, SHA224, SHA384, SHA256, SHA512, RIPEMD, NTLM, GOST, WHIRLPOOL, LDAP_MD5, LDAP_SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        hash2 = None
        if alg in [NTLM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # Confirm the initial '*' character
        if alg == MYSQL and hash2[0] != '*':
            hash2 = '*' + hash2

        # Build the URL
        url = "http://goog.li/?q=%s" % (hash2)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<br />cleartext[^:]*: [^<]*<br />', html)

        if match:
            return match.group().split(':')[1].strip()[:-6]
        else:
            return None


########################################################################################################
### GLOABAL VARIABLES
########################################################################################################

CRAKERS = [
        GROMWEB,         #0
        MY_ADDR,         #1
        MD5DECRYPTION,   #2
        MD5DECRYPT,      #3
        HASHCRACK,       #4
        CMD5,            #5
        IBEAST,          #6
        PASSWORD_DECRYPT,#7
        SANS,            #8
        OPHCRACK         #9
       # GOOG_LI,
        ]


verbose=False
sigterm=False
signals=dict((k, v) for v, k in reversed(sorted(signal.__dict__.items()))
    if v.startswith('SIG') and not v.startswith('SIG_'))

########################################################################################################
### GENERAL METHODS
########################################################################################################

def signal_handler(signum, frame):
    # CTRL-C gracefull shutdown handler
    global sigterm
    global signals
    print('Received '+signals[signum])
    # Term signals
    if signum in [1,2,9,10,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,30,31]:
        sigterm=True
    sys.exit(0)


def configureCookieProcessor (cookiefile='/tmp/searchmyhash.cookie'):
    '''Set a Cookie Handler to accept cookies from the different Web sites.

    @param cookiefile Path of the cookie store.'''

    cookieHandler = LWPCookieJar()
    if cookieHandler is not None:
        if path.isfile (cookiefile):
            cookieHandler.load (cookiefile)

        opener = urllib2.build_opener ( urllib2.HTTPCookieProcessor(cookieHandler) )
        urllib2.install_opener (opener)


def do_HTTP_request (url, method="get",lib="urllib2",params={}, httpheaders={}):
    '''
    Send a GET or POST HTTP Request.
    @return: HTTP Response
    '''
    global USER_AGENTS
    httpheaders["user-agent"] = USER_AGENTS[randint(0, len(USER_AGENTS) - 1)]
    # If there is parameters, they are been encoded
    if method == "post":
        response = requests.post(url, data=httpheaders)
    else:
        if lib == "urllib2":
            data = {}
            request = None
            if params:
                data = urlencode(params)

                request = urllib2.Request ( url, data, headers=httpheaders )
            else:
                request = urllib2.Request ( url, headers=httpheaders )

            # Send the request
            try:
                response = urllib2.urlopen (request)
            except:
                return ""
        # Use the Requests library
        elif lib=="requests":
            # Choose random user agent
            response=requests.get(url,headers=httpheaders)

    return response


def printSyntax ():
    """Print application syntax."""

    print """%s 1.1.2 ( http://code.google.com/p/findmyhash/ )

Usage: 
------

  python %s <algorithm> OPTIONS


Accepted algorithms are:
------------------------

  MD4       - RFC 1320
  MD5       - RFC 1321
  SHA1      - RFC 3174 (FIPS 180-3)
  SHA224    - RFC 3874 (FIPS 180-3)
  SHA256    - FIPS 180-3
  SHA384    - FIPS 180-3
  SHA512    - FIPS 180-3
  RMD160    - RFC 2857
  GOST      - RFC 5831
  WHIRLPOOL - ISO/IEC 10118-3:2004
  LM        - Microsoft Windows hash
  NTLM      - Microsoft Windows hash
  MYSQL     - MySQL 3, 4, 5 hash
  CISCO7    - Cisco IOS type 7 encrypted passwords
  JUNIPER   - Juniper Networks $9$ encrypted passwords
  LDAP_MD5  - MD5 Base64 encoded
  LDAP_SHA1 - SHA1 Base64 encoded
 
  NOTE: for LM / NTLM it is recommended to introduce both values with this format:
         python %s LM   -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
         python %s NTLM -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7


Valid OPTIONS are:
------------------

  -h <hash_value>  If you only want to crack one hash, specify its value with this option.

  -f <file>        If you have several hashes, you can specify a file with one hash per line.
                   NOTE: All of them have to be the same type.
                   
  -g               If your hash cannot be cracked, search it in Google and show all the results.
                   NOTE: This option ONLY works with -h (one hash input) option.
                   
  -v               If you want verbose output.If not given you have to wait for output only until cracking of ALL hashes has been completed
  
  -l               List resources used by this script ordered by hash algorithm  

Examples:
---------

  -> Try to crack only one hash.
     python %s MD5 -h 098f6bcd4621d373cade4e832627b4f6
     
  -> Try to crack a JUNIPER encrypted password escaping special characters.
     python %s JUNIPER -h "\$9\$LbHX-wg4Z"
  
  -> If the hash cannot be cracked, it will be searched in Google.
     python %s LDAP_SHA1 -h "{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=" -g
   
  -> Try to crack multiple hashes using a file (one hash per line).
     python %s MYSQL -f mysqlhashesfile.txt
     
  -> List reversing resources based on hash algorithm
     python %s SHA1 -l
     
     
Contact:
--------

[Web]           http://laxmarcaellugar.blogspot.com/
[Mail/Google+]  bloglaxmarcaellugar@gmail.com
[twitter]       @laXmarcaellugar
""" % ( (sys.argv[0],) * 9 )


def crackHash (algorithm, hashvalue=None, hashfile=None,verbose=False):
    """Crack a hash or all the hashes of a file.

    @param alg Algorithm of the hash (MD5, SHA1...).
    @param hashvalue Hash value to be cracked.
    @param hashfile Path of the hash file.
    @return If the hash has been cracked or not."""

    global CRAKERS
    global sigterm
    # Cracked hashes will be stored here
    crackedhashes = []


    # Only one of the two possible inputs can be setted.
    if (not hashvalue and not hashfile) or (hashvalue and hashfile):
        return False

    # hashestocrack depends on the input value
    hashestocrack = None




    if hashvalue:
        hashestocrack = [ hashvalue ]
    else:
        try:
            hashestocrack = open (hashfile, "r")
        except:
            print "\nIt is not possible to read input file (%s)\n" % (hashfile)
            return cracked


    # Try to crack all the hashes...

    for activehash in hashestocrack:
        # SIG
        if sigterm:
            break
        hashresults = []

        # Standarize the hash
        activehash = activehash.strip()

        if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
            activehash = activehash.lower()

        # Is the hash cracked?
        cracked = False

        # If hash already cracked in previous sessions retrieve it from cache file and dont try online crackers at all
        cached=False
        result = manageCached(activehash, read_cache, None)
        if result != activehash and result is not None:
            cracked = True
            cached = True

        # Initial message
        if verbose:
            print colored("Cracking hash: ",'yellow')+\
                  colored("%s\n" % (activehash),'yellow',None,['bold'])
        else:
            print colored("Cracking hash: ",'yellow')+ \
                  colored("%s" % (activehash), 'white', None, ['bold']),
        if not verbose:
            print colored(' --> ', 'yellow'),
        # Each loop starts for a different start point to try to avoid IP filtered
        begin = randint(0, len(CRAKERS)-1)
        #test_func_idx=CRAKERS.index(SANS)
        #i=begin
        for i in range(len(CRAKERS)):
        #while i==test_func_idx:
            # Select the cracker
            cr = CRAKERS[ (i+begin)%len(CRAKERS) ]()
            #cr=CRAKERS[test_func_idx]()
            #i+=1
            # Check if the cracker support the algorithm
            if not cr.isSupported ( algorithm ):
                continue

            # Analyze the hash
            if verbose and not cached:
                print colored("Analyzing with %s "%cr.name,'yellow')+colored("(%s)"% cr.url,'blue')
            # Crack the hash
            # If hash not already in cached cracked hashes use online resources
            if not cracked:
                result = None
                try:
                    result = cr.crack ( activehash, algorithm )
                # If it was some trouble, exit
                except:
                    if verbose:
                        print "\nSomething was wrong. Please, contact with us to report the bug:\n\nbloglaxmarcaellugar@gmail.com\n"
                    if hashfile:
                        try:
                            hashestocrack.close()
                        except:
                            pass
                    return False

                # If there is any result...
                cracked=False

            if result:

                # If it is a hashlib supported algorithm...
                if algorithm in [MD4, MD5, SHA1,  SHA224, SHA384, SHA256, SHA512, RIPEMD]:
                    # Hash value is calculated to compare with cracker result
                    h = hashlib.new (algorithm)
                    h.update (result)

                    # If the calculated hash is the same to cracker result, the result is correct (finish!)
                    if h.hexdigest() == activehash:
                        hashresults.append (result)
                        cracked = True

                # If it is a half-supported hashlib algorithm
                elif algorithm in [LDAP_MD5, LDAP_SHA1]:
                    alg = algorithm.split('_')[1]
                    ahash =  decodestring ( activehash.split('}')[1] )

                    # Hash value is calculated to compare with cracker result
                    h = hashlib.new (alg)
                    h.update (result)

                    # If the calculated hash is the same to cracker result, the result is correct (finish!)
                    if h.digest() == ahash:
                        hashresults.append (result)
                        cracked = True

                # If it is a NTLM hash
                elif algorithm == NTLM or (algorithm == LM and ':' in activehash):
                    # NTLM Hash value is calculated to compare with cracker result
                    candidate = hashlib.new('md4', result.split()[-1].encode('utf-16le')).hexdigest()

                    # It's a LM:NTLM combination or a single NTLM hash
                    if (':' in activehash and candidate == activehash.split(':')[1]) or (':' not in activehash and candidate == activehash):
                        hashresults.append (result)
                        cracked = True

                # If it is another algorithm, we search in all the crackers
               # else:
                #    hashresults.append (result)
                 #   cracked = 1

            # Had the hash cracked?

            if verbose:
                if cracked:
                    print colored("***** HASH CRACKED!! *****\n",'yellow')
                    print colored("The original string is: ",'yellow')+\
                                  colored("%s" % (result),'white',None,['bold']),
                    if not cached:
                        manageCached(activehash,write_cache,result)
                        print "\n"
                    else:
                        print colored("[Cached]\n",'green')
                    # If result was verified, break
                    #if cracked == 2:
                    #    break
                else:
                    print "... hash not found in %s\n" % (cr.name)
            else:
                if cracked:
                    print colored("[ %s ]"% result,'white',None,['bold']),
                    if not cached:
                        manageCached(activehash,write_cache,result)
                        print "\n"
                    else:
                        print colored("[Cached]\n",'green')
            if cracked:
                break
        if not cracked and not verbose:
            print colored("[ NOT FOUND ]", 'red', None, ['bold'])
        # Store the result/s for later...
        if hashresults:

            # With some hash types, it is possible to have more than one result,
            # Repited results are deleted and a single string is constructed.
            resultlist = []
            for r in hashresults:
                if r not in resultlist:
                    resultlist.append (r)

            finalresult = ""
            if len(resultlist) > 1:
                finalresult = ', '.join (resultlist)
            else:
                finalresult = resultlist[0]

            # Valid results are stored
            crackedhashes.append ( (activehash, finalresult) )


    # Loop is finished. File can need to be closed
    if hashfile:
        try:
            hashestocrack.close ()
        except:
            pass

    # Show a resume of all the cracked hashes
    if verbose:
        print colored("The following hashes were cracked:\n----------------------------------\n",'yellow')
        str=crackedhashes and "\n".join ("%s -> %s" % (hashvalue, result.strip()) for hashvalue, result in crackedhashes) or "NO HASH WAS CRACKED."
        print colored(str,'white',None,['bold'])

    return cracked


def searchHash (hashvalue):
    '''Google the hash value looking for any result which could give some clue...

    @param hashvalue The hash is been looking for.'''

    start = 0
    finished = False
    results = []

    sys.stdout.write("\nThe hash wasn't found in any database. Maybe Google has any idea...\nLooking for results...")
    sys.stdout.flush()

    while not finished:

        sys.stdout.write('.')
        sys.stdout.flush()

        # Build the URL
        url = "http://www.google.com/search?hl=en&q=%s&filter=0" % (hashvalue)
        if start:
            url += "&start=%d" % (start)

        # Build the Headers with a random User-Agent
        headers = { "User-Agent" : USER_AGENTS[randint(0, len(USER_AGENTS))-1] }

        # Send the request
        response = do_HTTP_request ( url, httpheaders=headers )

        # Extract the results ...
        html = None
        if response:
            html = response.read()
        else:
            continue

        resultlist = findall (r'<a href="[^"]*?" class=l', html)

        # ... saving only new ones
        new = False
        for r in resultlist:
            url_r = r.split('"')[1]

            if not url_r in results:
                results.append (url_r)
                new = True

        start += len(resultlist)

        # If there is no a new result, finish
        if not new:
            finished = True


    # Show the results
    if results:
        print "\n\nGoogle has some results. Maybe you would like to check them manually:\n"

        results.sort()
        for r in results:
            print "  *> %s" % (r)
        print

    else:
        print "\n\nGoogle doesn't have any result. Sorry!\n"


def list_per_hash(algorithm):
    if not algorithm:
        return 1
    algorithm=algorithm.lower()
    if algorithm == "all":
        for h in HASH_LIST:
            resources=[]
            for cr in CRAKERS:
                if h in cr.supported_algorithm:
                    resources.append(cr.name)
            print colored("\n%s\tTotal %d" %(h.upper(),len(resources)),'white',None,['bold'])
            for res in resources:
                print colored(res+"  ",COLORS[randint(0,len(COLORS)-2)],None,['bold']),
            print
        return 0
    elif algorithm in HASH_LIST:
        resources = []
        for cr in CRAKERS:
            if algorithm in cr.supported_algorithm:
                resources.append(cr.name)
        print colored("\n%s\tTotal %d" % (algorithm.upper(), len(resources)), 'white', None, ['bold'])
        for res in resources:
            print colored(res + "  ", COLORS[randint(0, len(COLORS) - 2)], None, ['bold']),
        print
        return 0
    return 1


def manageCached(hashvalue,manage,result):
    # If cacvhe file does not exist, create it!
    try:
        open(CACHE_FILENAME,"r").close()
    except IOError as e:
        #print "I/O error({0}): {1} -> {2}".format(e.errno, e.strerror,CACHE_FILENAME)
        try:
            if e.errno==2:
                open(CACHE_FILENAME,"w").close()
                if verbose:
                    print colored("Cache file created: {0}/{1} ".format(os.getcwd(), CACHE_FILENAME), 'blue')
        except IOError as io:
            print colored("Error creating cache file: {0}/{1}".format(os.getcwd(),CACHE_FILENAME),'red')
            print colored("I/O error({0}): {1}".format(io.errno,io.strerror),'red')
            return None
    hashvalue=hashvalue.strip()
    if manage==read_cache:
        with open(CACHE_FILENAME,"r") as cache:
            for line in cache:
                if hashvalue in line.split(' -> ')[0].strip():
                    result=line.split(' -> ')[1].strip()
                    return result
    elif manage==write_cache and result is not None:
        with open(CACHE_FILENAME,"a") as cache:
            cache.write("\n"+hashvalue+' -> '+result)
        cache.close()
        return hashvalue

    return None

def clearCached(self):
    open(CACHE_FILENAME,"w").close()


########################################################################################################
### MAIN CODE
########################################################################################################

def main():
    """Main method."""
    ##################################################
    # Signal handling
    signal.signal(signal.SIGINT, signal_handler)

    ###################################################
    # Syntax check
    if len (sys.argv) < 4:
        if len(sys.argv)==3 and sys.argv[2] == '-l':
            if list_per_hash(sys.argv[1]):
                printSyntax()
                sys.exit(1)
            else:
                sys.exit(0)
        printSyntax()
        sys.exit(1)

    else:
        try:
            opts, args = getopt.getopt (sys.argv[2:], "gvh:f:")
        except:
            printSyntax()
            sys.exit(1)


    ###################################################
    # Load input parameters
    algorithm = sys.argv[1].lower()
    global verbose
    hashvalue = None
    hashfile  = None
    googlesearch = False

    for opt, arg in opts:
        if opt == '-h':
            hashvalue = arg
        elif opt == '-f':
            hashfile = arg
        elif opt== '-v':
            verbose=True
        else:
            googlesearch = True


    ###################################################
    # Configure the Cookie Handler
    configureCookieProcessor()

    # Initialize PRNG seed
    seed()

    #cracked = 0
    ###################################################
    # Crack the hash/es
    # cracked =

    crackHash (algorithm, hashvalue, hashfile,verbose)


    ###################################################
    # Look for the hash in Google if it was not cracked
   # if not cracked and googlesearch and not hashfile:
   #     searchHash (hashvalue)



    # App is finished
    sys.exit()



if __name__ == "__main__":
    main()


