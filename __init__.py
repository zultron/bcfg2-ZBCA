from Bcfg2.Server import Plugin
from Bcfg2.Server.Plugin import PluginInitError
from SSLCA import SSLCA
import logging

logger = logging.getLogger(__name__)

class ZBCA(Plugin.PrioDir):
    """
    The ZBCA generator handles the creation and
    (someday) management of ssl certificates and their keys.
    """
    name = 'ZBCA'
    __author__ = 'John Morris <jman@zultron.com>'
    experimental = True

    def __init__(self, core, datastore):
        Plugin.PrioDir.__init__(self, core, datastore)
        self.cfp = self.core.setup.cfp
        self.cas = {}
        self.default_ca = None

        # set up dict of SSLCA objects from config
        if True:
            for caname in self.cfp.get(
                self.name.lower(), "cas").split(','):
                self.cas[caname] = SSLCA(caname,self)
        try:
            pass
        except Exception as e:
            logger.error('ZBCA plugin exception searching for "cas" '
                         'option in config')
            raise PluginInitError()

        # choose a default CA; pick one at random if none specified
        try:
            self.default_ca = self.cfp.get(
                self.name.lower(),'default_ca')
        except:
            logger.warn('Config file ought to specify "default_ca" in the '
                        '[global] section; picking default CA at random')
            self.default_ca = self.cas.keys()[0]

    def config(self,caname,subsect=None,isprefix=False):
        '''
        Convenience function:  get config file section;
        If subsect==None, return [zbca:caname]
        Elif not isprefix, return [zbca:caname-subsect]
        Else return { foo : [zbca:caname-subsect-foo], ... }
        '''
        basename = ':'.join((self.name.lower(),caname))
        if not subsect:
            return self.cfp.items(basename)
        elif not isprefix:
            return self.cfp.items('-'.join((basename,subsect)))
        else:
            prefix = '-'.join((basename,subsect,''))
            sections = [k for k in self.cfp.sections()
                        if k.startswith(prefix)]
            sectiondict = [(s[len(prefix):], self.cfp.items(s))
                           for s in sections]
            return sectiondict

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
        obj.bind(entry)
