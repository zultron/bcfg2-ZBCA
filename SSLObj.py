import logging
from lxml import etree
import os
from OpenSSL import crypto
import uuid
from pprint import pformat

logger = logging.getLogger(__name__)

class SSLObjException(Exception):
    pass

class SSLObj(object):
    '''
    An object representing an abstract SSL object; the SSLKey,
    SSLCert, etc. classes inherit from this class

    The 'elt' attribute contains an XML structure with tagname
    'SSLKey', 'SSLCert', etc.  It contains information about how it
    was created (e.g. key bits, cert subject) and where its PEM-format
    text is stored.
    '''
    # map 'type="..."' attributes to subclasses, filled in by subclasses
    typedict = {}

    def __init__(self,ca,elt_or_attrs,metadata,**kwargs):
        '''
        Create an object with supplied attributes 

        If 'elt_or_attrs' is an element, assume it came from the
        index; Read PEM representation from files and done

        If 'elt_or_attrs' is a attr dict, assume it's a new object and
        create the element, generate the crypto objects, and save the
        PEM data to disk

        If an attribute map is supplied in kwargs, build a new attrs
        dict from the old based on the map; this is useful when the
        cert and key are in the same spec
        '''
        self.ca = ca
        self.metadata = metadata
        if not hasattr(self,'store'):  # subclasses can override
            self.store = True

        if type(elt_or_attrs) == etree._Element:
            # we were given an element; fill out object attributes
            self.elt = elt_or_attrs
            self.text = self.readText()

        else:
            # we were given an attrs dict; generate a new SSL object
            attrs = elt_or_attrs
            # process the attribute map
            if kwargs:
                newattrs = {}
                for key, val in map:
                    newattrs[key] = attrs[val]
                attrs = newattrs

            # build index element from attrs and create object
            print(pformat(attrs))
            self.elt = etree.Element(attrs['type'],**attrs)
            del(self.elt.attrib['type'])

            # generate crypto
            self.genCrypto()

            # save the PEM text to a file
            if self.store:
                self.writeText()


    @classmethod
    def init(cls,ca,elt_or_attrs,metadata):
        '''
        Init a new SSLObj: determine intended type and call
        appropriate __init__() routine
        '''
        # determine class
        if type(elt_or_attrs) == dict:
            ssltype = elt_or_attrs['type']
        else:
            ssltype = elt_or_attrs.tag

        # return result of appropriate class's constructor function
        return cls.typedict[ssltype](ca,elt_or_attrs,metadata)

    def attrib(self,attrname,setval=None,default=None):
        '''
        Convenience function:  return value of self.elt.attrname;
        if setval is supplied, set the element attribute first
        '''
        if setval is not None:
            self.elt.set(attrname,setval)
        return self.elt.get(attrname,default)

    def extensionValueParse(self,name,val,cert,cacert):
        '''
        Parse X509v3 extensions from config; usually used by SSLCert,
        but could be used by SSLReq

        Set critical flag
        Add key IDs for complex extensions
        Return an OpenSSL.crypto.X509Extension object

        Example format for config file inserts a 'X509v3 Subject Key
        Identifier' extension with the cert's pubkey digest and sets
        the 'critical' flag:
        subjectKeyIdentifier = hash;subject=cert;critical
        '''
        # init variables
        crit = False
        kwargs = {}

        # a function that fills out subject/issuer= arguments
        def subject_issuer(arg):
            args = arg.partition('=')
            if args[2] == 'cert':
                kwargs[args[0]] = cert
            elif args[2] == 'ca':
                kwargs[args[0]] = cacert
            else:
                logger.error('unknown argument in extension: "%s=%s"' %
                             (args[0],args[2]))
                raise SSLObjException

        # value is in format 'name[;arg1[;arg2]]'; split name & process args
        args = val.split(';')
        val = args.pop(0)
        for arg in args:
            arg=arg.lower().strip()
            if arg == 'critical':
                crit = True
            elif (arg.partition('=')[1]):
                subject_issuer(arg)

        # generate extension object & return it
        extension = crypto.X509Extension(name, crit, val, **kwargs)
        return extension

    def myAttrs(self):
        '''Convenience function copies attrs from self.elt'''
        return dict(self.elt.attrib.items() + [('type',self.elt.tag)])
    
    def bind(self,entry):
        '''
        Bind Path entry with file metadata and PEM text

        Text is somewhat complex:
        - Simple keys and certs are straight-forward
        - Certs may be combined with keys in the same file
        '''
        for k in ('owner','group','perms'):
            entry.attrib[k] = self.attrib(k)

        entry.text = self.text

    def textFname(self):
        '''
        Compute the crypto text file name
        E.g. /var/lib/bcfg2/ZBCA/CA/myca/SSLKey
        '''
        return '%s/%s/%s.pem' % (self.ca.basepath,
                                 self.ssltype(),self.attrib('uuid'))

    def writeText(self):
        '''
        Write the PEM text to a file
        Create w/perms go-rwx to keep key data safe
        '''
        with os.fdopen(
            os.open(self.textFname(), 
                    os.O_CREAT|os.O_RDWR, 0600),
            'w') as f:
            f.write(self.text)
        
    def readText(self):
        '''
        Read PEM text from a file
        '''
        with open(self.textFname(), 'r') as f:
            return f.read()

    def tostring(self):
        '''
        Create a string serializing important attributes for debugging
        '''
        return '%s\n%s' % \
            (etree.tostring(self.elt,pretty_print=True),
             self.text)

    def ssltype(self):
        '''Convenience function to return object SSL type'''
        return self.__class__.__name__

    def __str__(self):
        return '%s %s' % (type(self), self.ssltype())


class SSLKey(SSLObj):
    '''
    An object representing an SSLKey

    SSLKey spec should look like this:

    <Path type='SSLKey' name='/etc/pki/tls/private/localhost.key'
    algorithm='rsa' bits='2048'
    owner='root' group='root' perms='0600'
    />

    The 'rsa' and 'bits' attributes may be put in a 'type="SSLCert"'
    spec with the 'key' attribute value the same as 'name'; the
    resulting key PEM text will be put in the same file as the cert's.
    '''
    def genCrypto(self):
        '''
        Generate new SSL key PEM data from metadata
        '''
        # fill out metadata defaults
        defaults = {
            'ca'        : self.ca.name,
            'bits'      : self.ca.key_default_bits,
            'algorithm' : self.ca.key_default_algorithm,
            'owner'     : 'root',
            'group'     : 'root',
            'perms'     : '0600',
            'uuid'      : str(uuid.uuid4())
            }
        # Element.attrib has no 'setdefault' method, so...
        defaults.update(self.elt.attrib)
        self.elt.attrib.update(defaults)

        # generate the key
        key = crypto.PKey()
        key.generate_key(self.keyAlgo(), int(self.attrib('bits')))
        self.text = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    def keyAlgo(self):
        '''Convenience function to calculate key crypto algorithm'''
        if self.attrib('algorithm') == 'rsa':
            return crypto.TYPE_RSA
        elif self.attrib('algorithm') == 'dsa':
            return crypto.TYPE_DSA
        else:
            logger.error ('key algorthim not set for key "%s", host "%s"' %
                          (self.attrib('name'),self.attrib('host')))

    def cryptoObj(self):
        return crypto.load_privatekey(crypto.FILETYPE_PEM, self.text)


class SSLReq(SSLObj):
    '''
    An object representing an SSL certificate request

    These are not put in spec, and not stored anywhere (they could be
    if there's ever a use for that), and are only used in the
    generation of SSLCert objects.
    '''

    def __init__(self,ca,elt,metadata):
        '''SSLReq objects aren't indexed or stored'''
        self.store = False
        SSLObj.__init__(self,ca,elt,metadata)

    def genCrypto(self):
        '''
        Generate new SSL certificate request PEM data from metadata
        '''
        # fill out defaults 
        defaults = dict([(f,None) for f in self.ca.dn_fields])
        defaults.update(self.ca.dn_defaults)
        defaults.update({
                'ca'        : self.ca.name,
                'md_algo'   : self.ca.req_default_md,
                'owner'     : 'root',
                'group'     : 'root',
                'perms'     : '0644',
                'uuid'      : str(uuid.uuid4()),
                'cn'        : self.metadata.hostname,
                })
        # Element.attrib has no 'setdefault' method, so...
        defaults.update(self.elt.attrib)
        self.elt.attrib.update(defaults)

        # generate the req
        req = crypto.X509Req()
        req.set_version(2) # X509v3 = 2
        subject = req.get_subject()
        # fill in subject
        for f in self.ca.dn_fields:
            try:
                setattr(subject,f.upper(),defaults[f])
            except AttributeError as e:
                logger.error(
                    'Attribute "%s" of cert request "%s", host "%s": %s' %
                    (f,self.attrib('name'),self.attrib('host'),e.args[0]))
                raise SSLObjException

        # retrieve key
        keyattrs = {'name' : self.attrib('key'),
                    'host' : self.metadata.hostname,
                    'type' : 'SSLKey'}
        if keyattrs['name'] is None \
                and self.attrib('append_key',default=False):
            # key and cert in same file; no key specified; assume
            # key name is the same
            keyattrs['name'] = self.attrib('name')
        key = self.ca.initSSLObj(keyattrs, self.metadata).cryptoObj()

        # add key text to req; sign req
        req.set_pubkey(key)
        req.sign(key, self.attrib('md_algo'))

        # put PEM text of req in object
        self.text = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def cryptoObj(self):
        '''Return a X509Req object'''
        return crypto.load_certificate_request(
            crypto.FILETYPE_PEM, self.text)

class SSLCert(SSLObj):
    '''
    An object representing an SSL certificate
    '''

    def genCrypto(self):
        '''
        Generate new SSL cert PEM data

        By default, the CN will be the hostname, unless overridden in
        the spec
        '''
        # fill out defaults
        defaults = {
            'ca'         : self.ca.name,
            'days'       : self.ca.cert_default_days,
            'extensions' : self.ca.cert_default_extensions,
            'owner'      : 'root',
            'group'      : 'root',
            'perms'      : '0600',
            'uuid'       : str(uuid.uuid4())
            }
        # Element.attrib has no 'setdefault' method, so...
        defaults.update(self.elt.attrib)
        self.elt.attrib.update(defaults)

        # If the 'ou_append_hostname' attribute is 'true', do it
        # (This is for client certs to auth to the same user but from
        # different machines; kojid wants this for some mad reason)
        print('ou_append_hostname:  %s' % self.attrib('ou_append_hostname'))
        if self.attrib('ou_append_hostname').lower() == 'true':
            self.attrib('ou', self.attrib('ou') + self.metadata.hostname)

        # generate the X509Req object
        reqattrs = self.myAttrs()
        reqattrs.update({'type':'SSLReq'})
        reqobj = SSLObj.init(self.ca, reqattrs, self.metadata)
        req = reqobj.cryptoObj()

        # load the CA key+cert
        cacert = SSLCACert(self.ca).cryptoObj()
        cakey = SSLCAKey(self.ca).cryptoObj()

        # generate cert and fill out basic attributes
        cert = crypto.X509()
        cert.set_version(2) # X509v3 = 2
        cert.set_subject(req.get_subject())
        cert.set_serial_number(self.ca.newSerial())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(int(self.attrib('days')) * 24 * 60 * 60)
        cert.set_issuer(cacert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        # build extensions from config and add to cert
        extensions = []
        for (name,val) in self.ca.extensions[self.attrib('extensions')].items():
            extensions.append(self.extensionValueParse(name,val,cert,cacert))
        cert.add_extensions(extensions)

        # sign cert
        cert.sign(cakey, "sha1")

        # add cert text to object
        self.text = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        # append key text if they're destined for the same file
        if self.attrib('key') == self.attrib('name') or \
                self.attrib('append_key').lower() == 'true':
            print ('Found combined cert')
            self.text = '\n'.join((self.text,reqobj.text))


class SSLCAObj(SSLObj):
    '''
    An object representing an SSL CA object:  cert, key or chain
    '''
    def __init__(self,ca,elt=None,metadata=None):
        '''
        For the moment, the CA objects are given to us, not generated.
        '''
        elt = etree.Element(self.ssltype())
        self.store = False
        SSLObj.__init__(self,ca,elt,metadata)
        
        # fill out defaults
        defaults = {
            'ca'         : self.ca.name,
            'owner'      : 'root',
            'group'      : 'root',
            'perms'      : '0644',
            'uuid'       : str(uuid.uuid4())
            }
        if self.ssltype() == 'SSLCACert':
            defaults['perms'] = '0600'
        # Element.attrib has no 'setdefault' method, so...
        defaults.update(self.elt.attrib)
        self.elt.attrib.update(defaults)


    def textFname(self):
        '''
        Compute the crypto text file name for the CA Cert
        '''
        return '%s/SSLCA/%s.pem' % (self.ca.basepath,self.ssltype())


class SSLCACert(SSLCAObj):
    '''
    An object representing an SSL CA certificate
    '''
    def cryptoObj(self):
        return crypto.load_certificate(crypto.FILETYPE_PEM,
                                       self.text)


class SSLCAKey(SSLCAObj):
    '''
    An object representing an SSL CA key
    '''
    def cryptoObj(self):
        return crypto.load_privatekey(crypto.FILETYPE_PEM,
                                      self.text)


class SSLCAChain(SSLCAObj):
    '''
    An object representing an SSL CA chain
    '''
    # We don't use any of the crypto routines for this; just need the
    # PEM text
    pass


# register typedict entries
SSLObj.typedict.update({
        'SSLKey'        : SSLKey,
        'SSLCert'       : SSLCert,
        'SSLReq'        : SSLReq,
        'SSLCACert'     : SSLCACert,
        'SSLCAKey'      : SSLCAKey,
        'SSLCAChain'    : SSLCAChain,
        })
