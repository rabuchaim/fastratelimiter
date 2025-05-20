#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fastratelimiter import FastRateLimiter
from fastapi import FastAPI, Request, HTTPException, status

app = FastAPI()

rate_limiter = FastRateLimiter(rate_limit=5, per=2, block_time=5, with_stats=True, no_limit_list=['10.0.0.0/8'])

@app.get("/")
async def root(request: Request):
    
    if rate_limiter(request.client.host):
        print(f">>> Rate limit exceeded for IP {request.client.host}")
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Calm down boy! Too many requests from IP {request.client.host}")
    else:
        print(f">>> Access granted to the IP {request.client.host}")
        # continue with your API code
        return {"Hello": "World"}
    
    if returned_network := accessLimiter(request.client.host): # The walrus operator (:=) works only in python > 3.8
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for network {returned_network}")
    else:
        return {"Hello": "World"}
