import socket
import re
import logging
import datetime
from functools import partial

from tornado import gen, iostream, ioloop, netutil, stack_context

logger = logging.getLogger(__name__)
loop = ioloop.IOLoop.instance()


class AsyncWhoisClient(object):

    default_server = "whois.iana.org"
    timeout = 3
    whois_port = 43
    resolver = None

    def __init__(self, resolver=None):
        if not resolver:
            logging.warn("Async resolver was not set")
        self.resolver = resolver

    @gen.coroutine
    def lookup(self, address):

        results = []
        timeout = loop.add_timeout(datetime.timedelta(seconds=self.timeout),
                                   partial(self.on_timeout, address))
        try:
            yield self.find_records(address, self.default_server, results)
        finally:
            loop.remove_timeout(timeout)

        raise gen.Return(results)

    @gen.coroutine
    def find_records(self, name, server, results):
        record = yield self.whois_query(name, server)
        results.append((server, record,))

        next_server = self._read_next_server_name(record)
        prev_server = None

        while next_server and next_server != prev_server:
            record = yield self.whois_query(name, next_server)
            results.append((next_server, record,))
            #
            prev_server = next_server
            next_server = self._read_next_server_name(record)

        raise gen.Return(record)

    @gen.coroutine
    def whois_query(self, name, server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = iostream.IOStream(sock)

        logging.debug("Requesting {} whois for {}".format(server, name))

        if self.resolver and not netutil.is_valid_ip(server):
            server = yield self._get_ip_by_name(server)
            logging.debug("Solver ")

        yield stream.connect((server, self.whois_port))

        yield stream.write("{}\r\n".format(name))
        data = yield stream.read_until_close()

        raise gen.Return(data)

    @gen.coroutine
    def _get_ip_by_name(self, address):
        data = yield self.resolver.resolve(address, None, socket.AF_INET)
        # [(2, ('<ip_address>', None))]
        for v in data:
            num, adr = v
            raise gen.Return(adr[0])
        raise gen.Return(None)

    def _read_next_server_name(self, data):
        lines = data.split("\n")
        for line in lines:
            match = re.match(re.compile(
                r"^(whois|whois\s+server):\s+([A-z0-9\-\.]{0,255})", re.IGNORECASE), line.strip())
            if match:
                return match.group(2)

        return None

    def on_timeout(self, address):
        raise Exception("AsyncWhoisClient timeout error while receiving {}".format(address))
