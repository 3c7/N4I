#!/usr/bin/env python
from cortexutils.analyzer import Analyzer
from censys.ipv4 import CensysIPv4
from censys.certificates import CensysCertificates
from censys.websites import CensysWebsites
from typing import Union


def censys_query(api: Union[CensysIPv4, CensysCertificates, CensysWebsites], query: str, fields=None):
    if fields is None:
        fields = []
    return list(api.search(
        query,
        fields=fields
    ))


class CensysQuery(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self._api_id = self.get_param('config.api_id', None, 'Censys api_id not given!')
        self._api_secret = self.get_param('config.api_secret', None, 'Censys api_secret not given!')

    def error(self, message, ensure_ascii=False):
        # Remove sensible data from error output
        if 'api_id' in self._input['config'].keys():
            self._input['config']['api_id'] = ''
        if 'api_secret' in self._input['config'].keys():
            self._input['config']['api_secret'] = ''
        super(Analyzer, self).error(message, ensure_ascii)

    def query(self):
        if self.data_type == 'censys-ipv4-query':
            censys_class = CensysIPv4
        elif self.data_type == 'censys-certificate-query':
            censys_class = CensysCertificates
        elif self.data_type == 'censys-website-query':
            censys_class = CensysWebsites
        else:
            self.error('Somehow this analyzer was called using a not implemented daty type.')

        c = censys_class(
            api_id=self._api_id,
            api_secret=self._api_secret
        )
        return censys_query(
            c,
            self.get_data(),
            self.get_param('config.fields', None, 'No fields given!'),
        )

    def run(self):
        self.report(self.query())


if __name__ == '__main__':
    CensysQuery().run()
