import unittest

from tornado.testing import AsyncTestCase, gen_test
from tornadowhois import AsyncWhoisClient


class TornadoWhoisTest(AsyncTestCase):

    @gen_test
    def test_lookup(self):
        results = yield AsyncWhoisClient().lookup(AsyncWhoisClient.default_server)

        self.assertEqual(len(results), 2)

        for result in results:
            self.assertEqual(len(result), 2)

        servers = ["whois.iana.org", "whois.pir.org"]

        self.assertEqual(servers[0], results[0][0])
        self.assertEqual(servers[1], results[1][0])

    @gen_test
    def test_whois_query(self):
        server = AsyncWhoisClient.default_server
        result = yield AsyncWhoisClient().whois_query(server, server)

        self.assertGreater(len(result), 1)


if __name__ == "__main__":
    unittest.main()
