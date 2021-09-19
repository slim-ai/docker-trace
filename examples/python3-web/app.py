#!/usr/bin/env python3
import logging
import tornado.ioloop
import web
import ssl
import subprocess

check_call = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash', stderr=subprocess.STDOUT)

logging.basicConfig(level='INFO')

async def handler(request: web.Request) -> web.Response:
    token = request['kwargs']['token']
    return {'code': 200, 'body': f'{token}'}

async def fallback_handler(request: web.Request) -> web.Response:
    route = request['args'][0]
    return {'code': 200, 'body': f'no such route: /{route}, try: /hello/XYZ'}

options = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
options.load_cert_chain('ssl.crt', 'ssl.key')

routes = [('/hello/:token', {'get': handler}),
          ('/(.*)',         {'get': fallback_handler})]

app = web.app(routes)
server = tornado.httpserver.HTTPServer(app, ssl_options=options)
server.bind(8080)
server.start(0)
tornado.ioloop.IOLoop.current().start()
