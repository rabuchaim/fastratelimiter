#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fastratelimiter import FastRateLimiter
import asyncio, tornado

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        if rate_limiter(self.request.remote_ip):
            print(f">>> Rate limit exceeded for IP {self.request.remote_ip}")
            self.send_error(429,reason=f"Calm down boy! Too many requests from IP {self.request.remote_ip}")
        else:
            print(f">>> Access granted to the IP {self.request.remote_ip}")
            # continue with your API code
            self.write("Hello, world")
            
def make_app():
    return tornado.web.Application([(r"/", MainHandler),])

async def main():
    app = make_app()
    app.listen(8888)
    await asyncio.Event().wait()

if __name__ == "__main__":
    rate_limiter = FastRateLimiter(rate_limit=5, per=2, block_time=5, with_stats=True, no_limit_list=['10.0.0.0/8'])
    asyncio.run(main())
