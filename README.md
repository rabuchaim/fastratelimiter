# FastRateLimiter v1.0.0

`FastRateLimiter` is a high-performance and decorator-free rate limit class for Python. Features:

- You can use it in any web framework like FastAPI, Django, Flask, Tornado, Bottle, etc;

- The decision whether access can be granted or not is made in less than 0.00001 second and can handle over [50,000 calls per second](#speed-test);

- Accepts IPv4 and IPv6 simultaneously with the same response time;

- It works with a rate limit per second or in an advanced mode where you define the evaluation time and the blocking time, for example: 10 accesses in 5 seconds, receives a 5-second block;

- It has the NoLimitList, a list of IPs or network blocks (CIDR) where the listed IPs will not suffer limits. The average response time of this list is 0.000005 second regardless of the list size;

- Can generate statistics on how many times a given IP has been blocked;

- You can evaluate the list of currently blocked IPs and the time at which each of the blocked IPs will be released;

- Precise `block_time` based on milliseconds. If the `block_time` is for 5 seconds and the REMOTE_HOST_IP reached the limit at second 12.123456, the release will only occur after second 17.123456 ([See below](#block-time-precision));

- Extremely easy to use:

```python
from fastratelimiter import FastRateLimiter
# PER SECOND MODE: More than 5 hits in a 1 second period receives a block until the end of the current second
rate_limiter = FastRateLimiter(rate_limit=5) 
# ADVANCED MODE: More than 5 hits in a 5 second period receives a 2 second block
rate_limiter = FastRateLimiter(rate_limit=5,per=5,block_time=2) 
if rate_limiter(remote_host_ip):
    print(f">>> Rate limit exceeded for IP {remote_host_ip}")
    # return your 429 Too Many Requests error
else:
    print(f">>> Access granted to the IP {remote_host_ip}")
    # continue with your API code
```

- A verbose mode for debugging problems. Just export the environment variable `export FASTRATELIMITER_DEBUG=1` or create the object with parameter `debug=True` for Windows aplications;

- Works on Linux, MacOS and Windows;

- No external dependencies, is Pure Python!

<!-- ```
What's new in v1.0.1 - xx/xxx/2025
- xxxxxxx
``` -->

---

## 🚀 Installation

```bash
pip install fastratelimiter
```

---

## 🔧 Requirements

- Python 3.10+ and nothing more!

---

## 🖉 `FastRateLimiter` Class Parameters

For most uses, you do not need to change any class parameters.

| Parameter                             | Type          | Default Value               | Description                              |
| ------------------------------------- | ------------- | --------------------------- | ---------------------------------------- |
| `rate_limit`                          | `int`         | (required)                  | Maximum number of allowed requests per time window |
| `per`                                 | `int`         | `1`                         | Time window in seconds for applying the rate limit |
| `block_time`                          | `int`         | `0`                         | Duration (in seconds) to block a client after exceeding the limit (0 = blocking until the end of the current second) |
| `no_limit_list`                       | `List[str]`   | `[]`                        | List of IPs or Networks CIDR that are exempt from rate limiting |
| `with_stats`                          | `bool`        | `False`                     | Enables usage statistics tracking |
| `cache_cleanup_interval`              | `int`         | `3`                         | Interval in seconds to automatically clean up stale cache entries |
| `lru_cache_maxsize`                   | `int`         | `512`                       | Maximum size of the LRU cache used to store cache for some functions (IP access check is never cached) |
| `debug`                               | `bool`        | `False`                     | Enable the debug messages. When enabled, this parameter overrides the checking of the FASTRATELIMITER_DEBUG environment variable. |

For debugging, export the environment variable like below:

```export FASTRATELIMITER_DEBUG=1```

### Class Parameters Instructions

- `rate_limit`: Enter the maximum number of requests that will be allowed within the window defined in the `per` parameter. **You can change this value at any time without having to recreate the object.**

- `per`: Enter the time window where the `rate_limit` parameter will be evaluated. **You can change this value at any time without having to recreate the object.**

- `block_time`: Specify the blocking time if an IP reaches the number specified in the `rate_limit` parameter within the time window specified in the `per` parameter. If you specify 0, the IP will be released as soon as the current second changes. **You can change this value at any time without having to recreate the object.**

- `no_limit_list`: Here you can enter the IPs or network blocks (CIDR) that will be exempt from the rate limit check, that is, you can make as many calls as you want without being blocked and they will not be included in the statistics. **You can add or remove IPs from this list at runtime.** Ex: `['1.1.1.1','2.2.2.2/32','3.3.3.0/24','10.0.0.0/8']`. 

    >> Attention: `10.0.0.10/8` is AN INVALID CIDR - `10.0.0.0/8` is A VALID CIDR - `10.0.0.10/32` is A VALID CIDR.

    - **NoLimitList Management**: The `FastRateLimiter.no_limit_list` is a list-type object to manage the list of allowed networks and perform quick searches. **You can add or remove IPs from this list at runtime.**

        - `last_discarted_ips`: It is a property that is fed whenever an invalid IP or CIDR is found, either by the `set_list` or `add_ip` or `add_ips` methods.
    
        - `def set_list(self,items:List[str])`: Set a new list
    
        - `def get_list(self)->List[str]`: Get the current no limit list
    
        - `def add_ip(self,ipaddr:str)`: Add an ip address or CIDR to no limit list
    
        - `def add_ips(self,ipaddr_list:List[str])`: Add a list of ip addressess or CIDRs to no limit list
    
        - `def remove_ip(self,ipaddr:str)`: Remove an ip address or a CIDR from no limit list
    
        - `def remove_ips(self,ipaddr_list:List[str])`: Remove a list of ip addressess or a CIDRs from no limit list
    
        - `def check_ipaddr(self,ipaddr:str)->bool`: Check if an IP address is in the no limit list. Returns a tuple with the search response (True or False) and if True, it also returns the network that the IP fits into, otherwise it returns None. (Elapsed average time: 0.000006).
    
        - `def check_iplong(self,iplong:int)->tuple`: Check if an "IP address as integer (iplong)" is in the no limit list. Returns a tuple with the search response (True or False) and if True, it also returns the network that the IP fits into, otherwise it returns None. (Elapsed average time: 0.000002)
    
            ```python
                # This is the code for the __call__ function of FastRateLimiter, you don't need to worry about checking the NoLimitList
                rate_limiter = FastRateLimiter(no_limit_list=['1.1.1.1','2.2.2.2/32','3.3.3.0/24','10.0.0.0/8','10.10.10.10/8','a.b.c.d','9.9.9.9/XX'])
                print(f"Invalid IPs/CIDR found in no_limit_list: {rate_limiter.no_limit_list.last_discarted_ips}")
                print(f"Current no_limit_list: {rate_limiter.no_limit_list}")
                start_time = time.monotonic()
                no_limit_result, no_limit_network = rate_limiter.no_limit_list.check_ipaddr(ipaddr)
                # no_limit_result, no_limit_network = rate_limiter.no_limit_list.check_iplong(iplong)
                if no_limit_result:
                    rate_limiter.__debug(f"IP address {ipaddr} is in the no limit list - network {no_limit_network} [{'%.9f'%(time.monotonic()-start_time)}]")
                    return False
                else:
                    return rate_limiter.__call_rate_limit(iplong,ipaddr)
            ```
            `no_limit_result` can be True or False and `no_limit_network` can be a network CIDR or None.

- `with_stats`: Enables access statistics, where it is recorded how many times a given IP is blocked. It is not the number of times that access is denied, a single occurrence is recorded per IP, per block and per period. **If statistics are enabled and the rate limiting feature is used heavily, it is a good idea to clear the statistics from time to time. You can use the `get_stats(reset_stats=True)` function to reset the statistics after collecting them.**

    - `FastRateLimiter.get_stats(top_items:int=10,reset_stats:bool=False)`: Returns a dictionary with the IP and the number of times blocked.

        ```{'10.0.0.10': 6, 'bf06:d2b3:c8e:fc7d:3839:9130:8c89:738e': 5}```

    - `FastRateLimiter.reset_stats()`: Clear all statistics data.

- `cache_cleanup_interval`: When an IP is checked and does not reach the limit within the established period, if it no longer passes through the application, the data remains in memory, and it is necessary to clean it so that it does not grow indefinitely. This value is used for automatic cache cleaning for PER SECOND mode. For ADVANCED mode, the recurrence is automatic and occurs every 0.1 second with no possibility of change.

    - `FastRateLimiter.cache_info()`: Returns a named tuple with the number of items and the size in kbytes of the __rate_limit_cache variable and also the memory consumption (Rss).

        ```CacheInfo(items=2, size_in_kb=0.21, memory_in_mb=12.93)```

    - `FastRateLimiter.cache_clear()`: Clear all rate limit cache.

- `lru_cache_maxsize`: Some functions are repetitive and are subject to caching to improve application performance. The `lru_cache_maxsize` parameter controls the amount of memory used to maintain this cache. Only functions that handle IP to integer conversion are cached.

## Example using Tornado:

```python
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
    rate_limiter = FastRateLimiter(rate_limit=5, per=2, block_time=5, with_stats=True, no_limit_list=['10.0.0.0/8'], debug=True)
    asyncio.run(main())
```
```bash
$ ./tornado_example.py
>>> Access granted to the IP 127.0.0.1
>>> Access granted to the IP 127.0.0.1
>>> Access granted to the IP 127.0.0.1
>>> Access granted to the IP 127.0.0.1
>>> Access granted to the IP 127.0.0.1
>>> Rate limit exceeded for IP 127.0.0.1
429 GET / (127.0.0.1) 0.35ms
25/05/20 08:18:30.298263 [FASTRATELIMITER_DEBUG] IP 127.0.0.1 blocked until 2025-05-20 08:18:35.293630 [0.000040126]
>>> Rate limit exceeded for IP 127.0.0.1
429 GET / (127.0.0.1) 0.76ms
25/05/20 08:18:30.303110 [FASTRATELIMITER_DEBUG] IP 127.0.0.1 blocked until 2025-05-20 08:18:35.293630 [0.000012463]
>>> Rate limit exceeded for IP 127.0.0.1
429 GET / (127.0.0.1) 0.44ms
25/05/20 08:18:30.307074 [FASTRATELIMITER_DEBUG] IP 127.0.0.1 blocked until 2025-05-20 08:18:35.293630 [0.000006696]
>>> Rate limit exceeded for IP 127.0.0.1
429 GET / (127.0.0.1) 0.29ms
```

```bash
$ while true; do curl -v http://127.0.0.1:8888/; sleep 0.1; done
*   Trying 127.0.0.1:8888...
* Connected to 127.0.0.1 (127.0.0.1) port 8888
> GET / HTTP/1.1
> Host: 127.0.0.1:8888
> User-Agent: curl/8.6.0
> Accept: */*
>
< HTTP/1.1 429 Calm down boy! Too many requests from IP 127.0.0.1
< Server: TornadoServer/6.4.1
< Content-Type: text/html; charset=UTF-8
< Date: Tue, 20 May 2025 11:19:47 GMT
< Content-Length: 151
```

## Example using FastAPI:

```python 
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
```
```bash
# uvicorn test_fastapi:app
INFO:     Started server process [29573]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

## Block Time Precision

As we can see in the first screenshot below, 1 IPv4 and 1 IPv6 with a FastRateLimiter object created with the parameters `rate_limit=5,per=5,block_time=2,with_stats=True`, were blocked at `06:32:07.793020 (ipv4)` and `06:32:07.7930047 (ipv6)`. 

<img src="https://raw.githubusercontent.com/rabuchaim/fastratelimiter/refs/heads/main/fastratelimiter_02.png" width="800" />

In the second screenshot we see that they were released 2 seconds later and only had access after `06:32:09.793058 (ipv4)` and `06:32:09.793137 (ipv6)`. 

>>*Note that in these 2 seconds more than 226,770 requests were denied*

<img src="https://raw.githubusercontent.com/rabuchaim/fastratelimiter/refs/heads/main/fastratelimiter_03.png" width="800" />

>> **There may be a difference of up to 0.1 seconds due to the cache_cleanup_interval of Advanced mode being 0.1 second.**

## Speed Test

Create the FastRateLimiter object and call the function below:

```python
>>> from fastratelimiter import FastRateLimiter
>>> rate_limiter = FastRateLimiter(rate_limit=5,per=5,block_time=2,with_stats=False)
>>> rate_limiter.speed_test(max_ips=500000)
```

<img src="https://raw.githubusercontent.com/rabuchaim/fastratelimiter/refs/heads/main/fastratelimiter_01.png" width="800" />

---

## 🌐 Links

- **GitHub**: [github.com/rabuchaim/fastratelimiter](https://github.com/rabuchaim/fastratelimiter)
- **PyPI**: [pypi.org/project/fastratelimiter](https://pypi.org/project/fastratelimiter)
- **Bugs / Issues**: [issues page](https://github.com/rabuchaim/fastratelimiter/issues)

---

## ⚖️ License

MIT License

---

## 🙌 Author

Ricardo Abuchaim ([ricardoabuchaim@gmail.com](mailto\:ricardoabuchaim@gmail.com)) - [github.com/rabuchaim](https://github.com/rabuchaim)

---

Contributions, testing, ideas, or feedback are very welcome! 🌟
