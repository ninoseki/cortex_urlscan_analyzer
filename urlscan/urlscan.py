import requests
import json


class UrlscanException(Exception):
    pass


class Urlscan:
    def __init__(self):
        self.base_url = "https://urlscan.io/api/"
        self.version = "v1"

    def search(self, query):
        assert len(query) > 0, "Qeury must be defined"

        payload = {"q": query}
        url = self.url_for("/search/")
        r = requests.get(url, params=payload)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns %s" % r.status_code)

    def result(self, uuid):
        assert len(uuid) > 0, "UUID must be defined"

        url = self.url_for("/result/{}/".format(uuid))
        r = requests.get(url)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns %s" % r.status_code)

    def url_for(self, path):
        return "{}{}{}".format(self.base_url, self.version, path)
