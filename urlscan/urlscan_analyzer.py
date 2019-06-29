#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from urlscan import Urlscan, UrlscanException


class UrlscanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api = Urlscan()

    def search(self, indicator):
        """
        Searches for a website using the indicator
        :param indicator: domain, ip, hash, url
        :type indicator: str
        :return: dict
        """
        search_result = self.api.search(indicator)
        results = search_result.get("results", [])
        for result in results:
            uuid = result.get("_id", "")
            _result = self.api.result(uuid)
            result["verdicts"] = _result.get("verdicts", {})

        search_result["result"] = result
        return search_result

    def run(self):
        targets = ['ip', 'domain', 'hash', 'url']
        if self.data_type == 'url':
            query = '"{}"'.format(self.get_data())
        else:
            query = self.get_data()

        try:
            if self.data_type in targets:
                self.report({
                    'type': self.data_type,
                    'query': query,
                    'indicator': self.search(query)
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
            level = 'suspicious' if total == 1 else 'info'
            value = "{} result".format(total)
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))
        else:
            level = 'suspicious'
            value = "{} results".format(total)
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    UrlscanAnalyzer().run()
