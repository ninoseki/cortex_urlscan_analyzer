#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from urlscan import Urlscan, UrlscanException


class UrlscanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def search(self, indicator):
        """
        Searches for a website using the indicator
        :param indicator: domain, ip, url
        :type indicator: str
        :return: dict
        """
        res = Urlscan(indicator).search()
        return res

    def run(self):
        try:
            if self.get_data() != None and self.data_type in ['ip', 'domain', 'url']:
                self.report({
                    'indicator': self.search(self.get_data())
                })
        except UrlscanException as err:
            self.error(str(err))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "urlscan.io"
        predicate = "Search"

        total = raw["indicator"]["total"]
        if total <= 1:
            value = "\"{} result\"".format(total)
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))
        else:
            value = "\"{} results\"".format(total)
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    UrlscanAnalyzer().run()
