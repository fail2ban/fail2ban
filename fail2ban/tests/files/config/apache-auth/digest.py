#!/usr/bin/python
import requests

try:
    import hashlib
    md5sum = hashlib.md5
except ImportError: # pragma: no cover
    # hashlib was introduced in Python 2.5.  For compatibility with those
    # elderly Pythons, import from md5
    import md5
    md5sum = md5.new


def auth(v):

    ha1 = md5sum(username + ':' + realm + ':' + password).hexdigest()
    ha2 = md5sum("GET:" + url).hexdigest()
    
    #response = md5sum(ha1 + ':' + v['nonce'][1:-1] + ':' + v['nc'] + ':' + v['cnonce'][1:-1]
    #                  + ':' + v['qop'][1:-1] + ':' + ha2).hexdigest()
    
    nonce = v['nonce'][1:-1]
    nc=v.get('nc') or ''
    cnonce = v.get('cnonce') or ''
    #opaque = v.get('opaque') or ''
    qop = v['qop'][1:-1]
    algorithm = v['algorithm']
    response = md5sum(ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2).hexdigest()
    
    p = requests.Request('GET', host + url).prepare()
    #p.headers['Authentication-Info'] = response 
    p.headers['Authorization'] = """
        Digest username="%s",
        algorithm="%s",
        realm="%s",
        uri="%s",
        nonce="%s",
        cnonce="",
        nc="",
        qop=%s,
        response="%s"
    """ % ( username, algorithm, realm, url, nonce, qop, response )
#        opaque="%s",
    print(p.method, p.url, p.headers)
    s =  requests.Session()
    return s.send(p)


def preauth():
    r = requests.get(host + url)
    print(r)
    r.headers['www-authenticate'].split(', ')
    return dict([ a.split('=',1) for a in r.headers['www-authenticate'].split(', ') ])


url='/digest/'
host = 'http://localhost:801'

v = preauth()

username="username"
password = "password"
print(v)

realm = 'so far away'
r = auth(v)

realm = v['Digest realm'][1:-1]

# [Sun Jul 28 21:27:56.549667 2013] [auth_digest:error] [pid 24835:tid 139895297222400] [client 127.0.0.1:57052] AH01788: realm mismatch - got `so far away' but expected `digest private area'


algorithm = v['algorithm']
v['algorithm'] = 'super funky chicken'
r = auth(v)

# [Sun Jul 28 21:41:20 2013] [error] [client 127.0.0.1] Digest: unknown algorithm `super funky chicken' received: /digest/

print(r.status_code,r.headers, r.text)
v['algorithm'] = algorithm


r = auth(v)
print(r.status_code,r.headers, r.text)

nonce = v['nonce']
v['nonce']=v['nonce'][5:-5]

r = auth(v)
print(r.status_code,r.headers, r.text)

# [Sun Jul 28 21:05:31.178340 2013] [auth_digest:error] [pid 24224:tid 139895539455744] [client 127.0.0.1:56906] AH01793: invalid qop `auth' received: /digest/qop_none/


v['nonce']=nonce[0:11] + 'ZZZ' + nonce[14:]

r = auth(v)
print(r.status_code,r.headers, r.text)

#[Sun Jul 28 21:18:11.769228 2013] [auth_digest:error] [pid 24752:tid 139895505884928] [client 127.0.0.1:56964] AH01776: invalid nonce b9YAiJDiBAZZZ1b1abe02d20063ea3b16b544ea1b0d981c1bafe received - hash is not d42d824dee7aaf50c3ba0a7c6290bd453e3dd35b


url='/digest_time/'
v=preauth()

import time
time.sleep(1)

r = auth(v)
print(r.status_code,r.headers, r.text)

# Obtained by putting the following code in modules/aaa/mod_auth_digest.c
# in the function initialize_secret
#    {
#       const char *hex = "0123456789abcdef";
#       char secbuff[SECRET_LEN * 4];
#       char *hash = secbuff;
#       int idx;

#       for (idx=0; idx<sizeof(secret); idx++) {
#       *hash++ = hex[secret[idx] >> 4];
#       *hash++ = hex[secret[idx] & 0xF];
#       }
#       *hash = '\0';
#       /* remove comment makings in below for apache-2.4+ */
#       ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, /*  APLOGNO(11759) */ "secret: %s", secbuff);
#   }


import sha
import binascii
import base64
import struct

apachesecret = binascii.unhexlify('497d8894adafa5ec7c8c981ddf9c8457da7a90ac')
s = sha.sha(apachesecret)

v=preauth()

print(v['nonce'])
realm = v['Digest realm'][1:-1]

(t,) = struct.unpack('l',base64.b64decode(v['nonce'][1:13]))

# whee, time travel
t = t + 5540

timepac = base64.b64encode(struct.pack('l',t))

s.update(realm)
s.update(timepac)

v['nonce'] =  v['nonce'][0] + timepac + s.hexdigest() + v['nonce'][-1]

print(v)

r = auth(v)
#[Mon Jul 29 02:12:55.539813 2013] [auth_digest:error] [pid 9647:tid 139895522670336] [client 127.0.0.1:58474] AH01777: invalid nonce 59QJppTiBAA=b08983fd166ade9840407df1b0f75b9e6e07d88d received - user attempted time travel
print(r.status_code,r.headers, r.text)

url='/digest_onetime/'
v=preauth()

# Need opaque header handling in auth
r = auth(v)
print(r.status_code,r.headers, r.text)
r = auth(v)
print(r.status_code,r.headers, r.text)
