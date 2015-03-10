Tornado-Whois
===============

Asynchronous Whois client for tornado framework

Example
~~~~~~~

::

    from tornado import ioloop, gen
    from tornadowhois import AsyncWhoisClient


    @gen.coroutine
    def main():

        data = yield AsyncWhoisClient().lookup("example.com")
        print data

    ioloop.IOLoop.current().run_sync(main)


Example with non-blocking resolver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from tornado import ioloop, gen
    from tornado.platform.caresresolver import CaresResolver
    from tornadowhois import AsyncWhoisClient

    resolver = CaresResolver()


    @gen.coroutine
    def main():

        data = yield AsyncWhoisClient(resolver).lookup("example.com")
        print data

    ioloop.IOLoop.current().run_sync(main)

