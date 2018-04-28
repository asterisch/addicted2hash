# addicted2hash

				Hashcat Bash Scripts by HR

These are a few scripts I whipped up in order to make better use of my time when trying to prep and attack large bulk hash lists. They are based on my understanding of the Hashcat wiki pages and some very basic analysis done with PACK tool kit, but in no way affiliated with hashcat team, company or products (mad respect for them though). Anyway, I find it to be fairly effective so decided to share it with others in hopes you might find it as helpful as I do, and perhaps even gets a few ideas or suggestions on ways to improve and make them even better.

Whats included?
## addicted2hash.sh  
### Description 
An automated hash cracking script which cycles through your wordlist directory running various attacks both straight up and with hybrid approach, then shifts over to a somewhat strategic mask attack. The results are then combined and run through a few rounds of the combinator attack and finally it is sent into a raw bruteforce mode at the end to kill off anything we may have missed somehow along the way. You the user can hit 'q' at any time to skip the current task being hanldled and moved to the next in line. Hitting CTRL+C will also stop it but not cleanly, although i did set things up so everything cracked to that point is dumped into a dump file so you dont loose anything. You may choose to comment out certain sections of mask or bruteforce attacks based on your targeted hash list and system capabilities. Running a single Nvidia GeForce GTX card it takes ~24-48hrs to run through to bruteforce mode. On a capable system you may find it running at much more reasonable time speeds or you may aso want to uncomment or even add in a few additional mask attacks that might otherwise be unfeasable for the average joe. 

## finger-crack.sh  
### Description 
My take on the hashcat wiki pages write up on the fingerprint attack. Again, another long running script (typically). It runs a standard mask attack againt a provided base hashlist and then uses the found passes to then perform the combination attack with a little help from the Expander tool in between runs to keep things going. The idea is you will continue to crack new and fresh passowrds and as more time allows the complexity of cracked passwords will also increase creating a cyclical nature of hash crcaking which runs as long as you let it (actually its set to 100 loops but this should be more than sufficient in most cases i think).


# Extras:  

## dict2hash.sh
### Description 
Again this is my take on the often referenced dict2hash.pl from the Hashcat forums and wiki pages but by me and written in bash. I used OpenSSL to allow this to work and then combined with GNU Parallel tool to really make things speed up to allow some comparison to the faster dict2hash.pl when handling larger wordlists. My script is capable of performing a wider array of hashing formats though :)

## crack-monitor.sh  
### Description
A simple script which watches a file and grabs the base count and compares it and set intervals. Handy for monitoring cracked count. Again this one is handy for me and how I typically run things in terminator but threw in case anyone else may find it useful...

## cryptochk.py
### Description
A really handy script I found on PacketStorm. I'm including as I find it helpful and goes with the overall theme. It was written by Francisco da Gama Tabanez Ribeiro. Don't know how to contact him so will take down if he asks me to, but until then it will be included. It is handy for easily identifying crypto/hash type for given string.

## findmyhash.py  `[UPDATED]`

##### [UPDATE]: This script was so old that many sites used to reverse hashes no longer exist, so I removed them and fixed all that are currently working and also added a few more.  Currently it works fine providing a pretty output.  

I also added some features:  

  - Listing option (-l).Lists reversing resources per hash type (e.g. MD5) or all.
  	  - ./findmyhash.py MD5 -l
  	  - ./findmuhash.py all -l
  - "Requests" library option in function do_HTTP_request(lib="requests").By default urllib2 is used though.
  - Method option in do_HTTP_request() function and "post" method support for HTTP requests via "requests" library.
  	- "Post" request via "requests" lib: do_HTTP_request(method="post")
  	- "Get" request via either "requests" or "urllib2" lib:
  		- do_HTTP_request(lib="requests",method="get")
  		- do_HTTP_request(lib="urllib2",method="get") [default]
  - Graceful script termination given a signal (like SIGTERM or CTRL-C)
  - Colorized output
  - Verbose option (-v)
  - "Cache file" in order to store cracked hashes with their corresponding passwords for future use. 
### Description
  Another handy script for dealing with hashes that I found on Google code pages here: http://code.google.com/p/findmyhash/. Uses the internet and many available hash lookup sites to check if you hashes have been previously cracked by others and posted. Helpful to have around.
  
  Highly supported hashes: MD5, SHA1
  Also supported hashes: SHA224, SHA256 , SHA384, SHA512, RIPEMD, LM, NTLM, MYSQL, CISCO7, JUNIPER, GOST, WHIRLPOOL, LDAP_MD5, LDAP_SHA1  


# Bonus: 
### dict/
A base collection of wordlists you can use for cracking which have been collected or made by me.


Hope someone finds this set of scripts useful. If you have questions, suggestions, or general feedback feel free to contact me to let me know (hood3drob1n@gmail).

Until next time, Enjoy!

Later,
H.R.
