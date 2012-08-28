import logging
from Bcfg2.Server import Plugin
from SSLCA import SSLCA
from lxml import etree   # for debugging

logger = logging.getLogger(__name__)

class ZBCAConfig(Plugin.SimpleConfig):
    '''
    A class representing the ZBCA plugin's zbca.conf config file
    '''

    def __init__(self, plugin):
        Plugin.SimpleConfig.__init__(self,plugin)
        # keep case sensitivity of attributes for X509 cert extensions
        self.optionxform = str
        self.basepath = plugin.data

    def Index(self):
        '''
        Read the config file as usual
        Attach CA objects to the plugin
        '''
        Plugin.SimpleConfig.Index(self)

        for caname in self.get('global','cas').split(','):
            self.plugin.cas[caname] = SSLCA(caname,self)

        # choose a default CA; pick one at random if none specified
        try:
            self.plugin.default_ca = self.get('global','default_ca')
        except:
            logger.warn('Config file ought to specify "default_ca" in the '
                        '[global] section; picking default CA at random')
            self.plugin.default_ca = self.plugin.cas.keys()[0]


class ZBCA(Plugin.PrioDir):
    """
    The ZBCA generator handles the creation and
    (someday) management of ssl certificates and their keys.
    """
    name = 'ZBCA'
    __version__ = '$Id:$'
    __author__ = 'John Morris <jman@zultron.com>'
    experimental = True

    def __init__(self, core, datastore):
        Plugin.PrioDir.__init__(self, core, datastore)
        self.config = ZBCAConfig(self)
        self.cas = {}
        self.default_ca = None

    def HandleEvent(self, event=None):
        '''
        Let the PrioDir HandleEvent function handle everything but the 
        'CA' directory
        '''
        if event.filename == 'CA':
            return

        Plugin.PrioDir.HandleEvent(self, event)

    def getCA(self,attrs):
        '''
        Convenience function returns CA object specified in attrs, or default
        '''
        return self.cas[attrs.get('ca',self.default_ca)]

    def BindEntry(self, entry, metadata):
        '''
        Generate bound Path from abstract entry and metadata
        '''
        attrs = self.get_attrs(entry,metadata)
        attrs['host'] = metadata.hostname

        # retrieve CA and SSL objects and bind the entry
        ca = self.getCA(attrs)
        obj = ca.initSSLObj(attrs,metadata)
        print(obj.tostring())
        obj.bind(entry)

        print(etree.tostring(entry))

