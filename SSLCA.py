import logging
from SSLObj import SSLObj
from SSLObjIndex import SSLObjIndex
from pprint import pformat

logger = logging.getLogger(__name__)

class SSLCAException(Exception):
    pass

class SSLCA(object):
    """
    An object representing a CA

    The CA maintains configuration for generating SSL objects, and
    contains an object index to look up existing and store new objects
    """
    def __init__(self,name,config):
        self.name = name

        # set config defaults
        self.key_default_bits = '2048'
        self.key_default_algorithm = 'rsa'
        self.req_default_md = 'sha512'
        self.cert_default_days = '365'
        self.cert_default_extensions = None
        self.ca_days = '1096'
        self.dn_fields = [ 'C', 'ST', 'L', 'O', 'OU', 'CN' ]
        self.dn_defaults = {}
        self.extensions = {}
        self.basepath = '%s/CA/%s' % (config.basepath,self.name)
        self.config = config

        # read configuration file
        self.readBasicConfig(config)
        self.readDNDefaultConfig(config)
        self.readExtensionsConfig(config)

        # initialize object index & make methods available
        self.index = SSLObjIndex(self)

    def readBasicConfig(self,config):
        '''
        Process the config file section for this CA [<self.name>]
        '''
        for opt, val in config.items(self.name):
            if opt == 'dn_fields':
                val = [s.strip().lower() for s in val.split(',')]
            setattr(self,opt,val)

    def defaultExtensions(self):
        '''
        Convenience function returns default extensions dict
        '''
        return self.extensions.get(self.cert_default_extensions,None)

    def readDNDefaultConfig(self,config):
        '''
        Process the config file dn-defaults section for this CA
        [<self.name>-dn-defaults]
        '''
        sect = self.name+'-dn-defaults'
        for opt, val in config.items(sect):
            self.dn_defaults[opt.lower()] = val
        
    def readExtensionsConfig(self,config):
        '''
        Process the config file extensions-foo for this CA
        [<self.name>-extensions-foo]
        '''
        prefix = '%s-extensions-' % (self.name)
        for sect in [s for s in config.sections() if s.startswith(prefix)]:
            suffix = sect[len(prefix):]
            self.extensions[suffix] = {}
            for opt, val in config.items(sect):
                self.extensions[suffix][opt] = val

    def initSSLObj(self, attrs, metadata):
        '''
        Retrieve an existing SSL object from the object index,
        or if none exists, generate a new one
        '''
        elt = self.index.searchAttrs(attrs)
        if elt is not None:
            # object exists in index, so build the object from the
            # element passed back by the exception
            obj = SSLObj.init(self,elt,metadata)
        else:
            # generate new object from attrs
            obj = SSLObj.init(self, attrs, metadata)

            # store object in index and save the index
            if obj.store:
                self.index.store(obj)
                self.index.write()

        return obj


    def newSerial(self):
        '''
        Retrieve the CA State 'serial' variable, increment the value,
        save the variable, and return the value

        We don't save the index yet; the index should be together with the
        cert for consistency
        '''
        serial = self.index.getCAState('serial',default=0,coerce=int)+1
        self.index.setCAState('serial',serial)

        return serial

    def tostring(self):
        '''Return a string representation of the CA object'''
        return pformat (self.__dict__)
