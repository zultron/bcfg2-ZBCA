#!/bin/bash

DIR=ZBCA/CA/int2

# trash emacs shit
find ZBCA -name \*~ -exec rm '{}' \;

rm -f $DIR/index.xml
rm -f $DIR/SSLCert/*
rm -f $DIR/SSLKey/*


exit



# init things
./clean.sh
bcfg2-info debug
from lxml import etree
from pprint import pprint

# case 3:  build a combo cert+key PEM-format client cert with
# hostname appended to the OU
metadata = self.build_metadata('infra0.zultron.com')
entry=etree.Element('Path', type='file', name='/etc/kojid/cert.pem')
self.Bind(entry,metadata)
self.Bind(entry,metadata)
print self.plugins['ZBCA'].cas['int2'].index.tostring()

##################################################

# case 1:  build just a key; do it twice and check index
metadata = self.build_metadata('infra0.zultron.com')
entry=etree.Element('Path', type='file', 
			    name='/etc/pki/tls/private/localhost.key')
self.Bind(entry,metadata)
self.Bind(entry,metadata)
print self.plugins['ZBCA'].cas['int2'].index.tostring()


# case 2:  build the cert first; be sure the key is generated; check index
metadata = self.build_metadata('db0.zultron.com')
entry=etree.Element('Path', type='file', 
			    name='/etc/pki/tls/certs/localhost.crt')
self.Bind(entry,metadata)
self.Bind(entry,metadata)
print self.plugins['ZBCA'].cas['int2'].index.tostring()

# case 3:  build a combo cert+key PEM-format client cert
metadata = self.build_metadata('infra0.zultron.com')
entry=etree.Element('Path', type='file', name='/etc/kojira/cert.pem')
self.Bind(entry,metadata)
self.Bind(entry,metadata)
print self.plugins['ZBCA'].cas['int2'].index.tostring()

# case 3:  build a combo cert+key PEM-format client cert with
# hostname appended to the OU
metadata = self.build_metadata('infra0.zultron.com')
entry=etree.Element('Path', type='file', name='/etc/kojid/cert.pem')
self.Bind(entry,metadata)
self.Bind(entry,metadata)
print self.plugins['ZBCA'].cas['int2'].index.tostring()

# case 5:  CA cert chain
metadata = self.build_metadata('infra0.zultron.com')
entry=etree.Element('Path', type='file', name='/etc/pki/tls/certs/cacert.crt')
self.Bind(entry,metadata)
self.Bind(entry,metadata)
print self.plugins['ZBCA'].cas['int2'].index.tostring()


##################################################

pprint(self.plugins['ZBCA'].get_attrs(entry,metadata))


print(etree.tostring(entry))

pprint(self.plugins['ZBCA'].cas['int2'].__dict__)


print(etree.tostring(self.plugins['ZBCA'].cas['int2'].index))


index=etree.parse('/v/bcfg2/ZBCA/CA/int2/index.xml')
pprint(index.xpath('//SSLKey[@name="/etc/pki/tls/private/localhost.key"]'))

print(etree.tostring(index.xpath('//SSLKey[@name="/etc/pki/tls/private/localhost.key"][@file="00:bloh:blinet:"]')[0]))


pprint(self.plugins['ZBCA'].config.cas['int2'].index.xpath('//SSLKey[@name="/etc/pki/tls/private/localhost.key"][@host="infra0.zultron.com"]'))

##################################################


Problems:
* no extensions
* sha1 digest, not sha512
* serial
* data version 1???
* SSLKeys generated from genCert arent saved in index
* Stop saving SSLReqs
* SGenshi or some way to put hostname in DN field **HACK**
* Cert and key in same file
* CAChain entries
* Extensions specification
- PKCS12?

