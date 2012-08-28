import logging
from lxml import etree
import posixpath

logger = logging.getLogger(__name__)

class SSLObjIndexException(Exception):
    pass

class SSLObjIndex(object):
    '''
    An object representing an XML index of SSL object elements

    Index has top-level container elements SSLKeys, SSLCerts, etc. 
    under which SSLKey, SSLCert, etc. objects are stored

    Retrieve object elements using keys 'ssltype' ('SSLCert', 
    'SSLKey', etc.), 'name' (filename) and 'host' attributes
    with the search() method

    Store object elements with the store() method

    There is also an interface to store/retrieve CA state
    '''
    # Map SSL object types to parent element containers in index
    setnamelist = {
        'SSLKey'        : 'SSLKeys',
        'SSLCert'       : 'SSLCerts',
        'SSLCAState'    : 'SSLCAState',
        }

    def __init__(self,ca):
        '''
        Init the index object:
        Read the index file; create it if necessary
        '''
        self.ca = ca
        self.index = self._read()

    def _read(self):
        '''
        Read XML object index from file, or create one

        Check that <SSLKeys/>, <SSLCerts/>, etc. container elements
        exist in index; create anything missing
        '''
        if not posixpath.exists(self.indexFilePath()):
            elt = etree.Element('ZBCAIndex').getroottree()
        else:            
            elt = etree.parse(self.indexFilePath())

        for tag in self.setnamelist.values():
            if elt.find(tag) is None:
                elt.getroot().append(etree.Element(tag))

        return elt

    def write(self):
        '''
        Save the object index to disk
        '''
        self.index.write(self.indexFilePath(),pretty_print=True)

    def indexFilePath(self):
        '''
        Convenience function returns name of index file
        '''
        return '%s/index.xml' % self.ca.basepath

    def search(self,ssltype,name,hostname):
        '''
        Search the object index for an SSL object (SSLKey, SSLCert, etc.)
        Return a single element if found, or None
        '''
        xpath = '//%s[@host="%s"][@name="%s"]' % \
            (ssltype,hostname,name)
        results = self.index.xpath(xpath)

        # check for #results != 1
        if not results:
            return None
        elif len(results) > 1:
            logger.error('Found multiple entries for type %s, name %s, host %s' %
                         (ssltype,name,hostname))
            raise SSLObjIndexException

        return results[0]

    def searchAttrs(self,attrs,ssltype='type',name='name',host='host'):
        '''
        Search the object index using an attrs dict and
        optionally custom keys from the dict

        Return a single element if found, or None
        '''
        return self.search(attrs[ssltype],attrs[name],attrs[host])

    def store(self,obj):
        '''
        Store the object in the index
        '''
        self.index.find(self.setnamelist[obj.ssltype()]).append(obj.elt)


    def getCAState(self,key,default=None,coerce=None):
        '''
        Retrieve a state variable from the SSLCAState container element;
        optionally set a default for or coerce return value
        '''
        xpath = '/SSLCAState/State[@name="%s"]' % key
        elt = self.index.find(xpath)
        if elt is None:
            return default
        elif coerce is None:
            return elt.get('value')
        else:
            return coerce(elt.get('value'))

    def setCAState(self,key,val):
        '''
        Set a state variable from the SSLCAState container element
        Create state variable element if it doesn't already exist
        '''
        # get existing or create new State element
        elt = self.index.find('/SSLCAState/State[@name="%s"]' % key)
        if elt is None:
            # Put a new State element in the index
            elt = etree.Element('State',name=key)
            self.index.find('/SSLCAState').append(elt)
        # set variable
        elt.set('value',str(val))

    def tostring(self):
        '''Return a string with XML representation of index'''
        return etree.tostring(self.index, pretty_print=True)

