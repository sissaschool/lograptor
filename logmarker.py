"""
EXAMPLES FOR TIMESTAMPS

    >>> import rfc3161
    >>> certificate = file('data/certum_certificate.crt').read()
    >>> rt = rfc3161.RemoteTimestamper('http://time.certum.pl', certificate=certificate)
    >>> tst = rt.timestamp(data='John Doe')
    >>> tst
    ('...', '')
    >>> rt.check(tst[0], data='John Doe')
    (True, '')
    >>> rfc3161.get_timestamp(tst[0])
    datetime.datetime(2014, 4, 25, 9, 34, 16)



import httplib, urllib
import hashlib

h = hashlib.sha1("dupa").hexdigest()
print "sha=", h
params = urllib.urlencode({'sha1' : h, })
headers = {}
conn = httplib.HTTPConnection('time.certum.pl')
conn.request("POST", "/", params, headers)
response = conn.getresponse()

print response.status, response.reason
data = response.read()
conn.close()

print "tsp=", data.encode('hex')

f = open('response.tsp', 'w')
f.write(data)
f.close()
"""