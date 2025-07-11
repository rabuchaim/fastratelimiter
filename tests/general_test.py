#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fastratelimiter import FastRateLimiter
from datetime import datetime as dt
import socket, struct, time, random
import tracemalloc

random.seed(42)  # For reproducibility

#################################################################################################################################
#################################################################################################################################

def cError(msg): return '\033[91m'+str(msg)+'\033[0m'

def int2ip(iplong):
    return socket.inet_ntoa(struct.pack('>L', iplong))
def ip2int(ipaddr):
    if ipaddr.find(":") < 0:
        return struct.unpack("!L",socket.inet_aton(ipaddr))[0]
    else:
        return int.from_bytes(socket.inet_pton(socket.AF_INET6,ipaddr),byteorder='big')
def randomipv4():
    return int2ip(random.randint(16777216,3758096383))        
def randomipv6():
    return ':'.join([f'{random.randint(0, 0xffff):04x}' for _ in range(8)])

def print_event(ipaddr,start_time):
    def cEven(msg):
        return '\033[38;2;64;224;208m'+msg+'\033[0m'
    def cOdd(msg):
        return '\033[38;2;238;130;238m'+msg+'\033[0m'
    if int(dt.now().second) % 2 == 0:
        print(f"[{cEven(dt.now().strftime('%H:%M:%S.%f'))}] Accepted request #{str(counter).zfill(4)} from {ipaddr} [{'%.9f'%(time.monotonic()-start_time)}]")
    else:
        print(f"[{cOdd(dt.now().strftime('%H:%M:%S.%f'))}] Accepted request #{str(counter).zfill(4)} from {ipaddr} [{'%.9f'%(time.monotonic()-start_time)}]")
    pass

if __name__ == '__main__':
    # tracemalloc.start()
    counter = 0
    a_list = []

    ip_list_v4 = [randomipv4() for i in range(1000)]
    # for I in range(2000000):
    #     ip = ip_list_v4[random.randint(0,len(ip_list_v4)-1)]
    #     oct = ip.split(".")
    #     a_list.append(f"{oct[0]}.{oct[1]}.{oct[2]}.0/24")

    ip_list_v6 = [randomipv6() for i in range(1000)]
    # for I in range(2500):
    #     ip = ip_list_v6[random.randint(0,len(ip_list_v6)-1)]
    #     a_list.append(ip)

    ip_list = [*ip_list_v4,*ip_list_v6]
    a_list = ['1.2.3.4','1.1.1.1/24','1.2.3.a','10.0.0.0/8']
    # a_list = ['174.77.160.0/24','10.0.0.0/8']
    # a_list = []
    # rateLimit = FastRateLimiter(rate_limit=5,per=2,block_time=0,no_limit_list=['a.b.c.d','1.0.0.1','10.10.10.10/24','10.0.0.10/32'],with_stats=True)
    # rateLimit = FastRateLimiter(rate_limit=2,per=3,block_time=2,no_limit_list=a_list,with_stats=False,debug=False)
    rateLimit = FastRateLimiter(rate_limit=5,per=1,block_time=1,no_limit_list=a_list,with_stats=True,debug=True,normalize_invalid_cidr=True)
    
    # print(rateLimit.no_limit_list.add_ip('1.2.3.0/24'))
    # print(rateLimit.no_limit_list.last_discarted_ips)
    # print(rateLimit.no_limit_list.add_ip('15.25.15.15/24'))
    # print(rateLimit.no_limit_list)

    # rateLimit.speed_test(100000)
    # quit()

    # current, peak = tracemalloc.get_traced_memory()
    # print(f"Memória atual usada: {current / 1024:.1f} KB")
    # print(f"Pico de memória: {peak / 1024:.1f} KB")
    # tracemalloc.stop()  # Para o rastreamento
    # quit()
    # a_list2 = [randomipv4() for i in range(1000)]
    # a_list2.extend([randomipv6() for i in range(1000)])
    # rateLimit.no_limit_list.set_list(a_list2)
    # rateLimit.no_limit_list.add_ips([randomipv4() for i in range(1000)])
    # rateLimit.no_limit_list.add_ips([randomipv6() for i in range(1000)])
    # print(rateLimit.no_limit_list)
    # rateLimit.no_limit_list.add_ip('1.2.3.4/32')
    # # rateLimit.no_limit_list.add_ip('10.0.0.10')
    # print(rateLimit.no_limit_list)
    # print(rateLimit.no_limit_list.get_list())
    # rateLimit.no_limit_list = ['1.1.1.1','2.2.2.2','3.3.3.3','8.8.8.8','9.9.9.9']
    # print(rateLimit.no_limit_list_discarted_ips)
    
    # rateLimit.gc_enable(interval=60)
    # ip_list = [randomipv4() for i in range(5000)]
    # ip_list.extend(randomipv6() for i in range(5000))
    
    # ip_list = [randomipv4() for i in range(10)]

    # rand_ipv6 = randomipv6()
    
    # ip = '1.1.1.1'
    # ip = 16843009
    # ip = 16909060
    # # ip = 4294967295
    # print(rateLimit.no_limit_list)
    # print(rateLimit.no_limit_list(ip))
    # result = rateLimit(ip)
    # if result:
    #     print(f"[{dt.now().strftime('%H:%M:%S.%f')}] denied request #{str(counter).zfill(4)} from IP {ip}")
    # else:
    #     print(f"[{dt.now().strftime('%H:%M:%S.%f')}] accepted request #{str(counter).zfill(4)} from IP {ip}")
    # quit()
    
    # print(rateLimit.no_limit_list.is_valid_ipaddr('fea7:0919:348d:ce8f:d31e:1258:0016:2e89'))
    # print(rateLimit.no_limit_list.is_valid_ipaddr('fea7:919:348d:ce8f:d31e:1258:0016:2e89'))
    # print(rateLimit.no_limit_list.is_valid_ipaddr('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit.no_limit_list.is_valid_cidr('fea7:919:348d:ce8f::/64'))
    # # print(rateLimit.no_limit_list.add_ip('fea7:919:348d:ce8f::/64'))
    # # print(rateLimit.no_limit_list('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:16:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:0016:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:0016:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:0016:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:0016:2e89'))
    # print(rateLimit('fea7:919:348d:ce8f:d31e:1258:0016:2e89'))
    # quit()
    
    for I in range(100000):
        ip = ip_list[random.randint(0,len(ip_list)-1)]
        # ip = a_list[random.randint(0,len(a_list)-1)]
        start_time = time.monotonic()
        # ip = random.choice(['174.77.160.10','10.0.0.10','1.2.3.4','1.1.1.1','2.2.2.2','3.3.3.3'])
        # ip = '10.0.0.10'
        # ip = randomipv4()
        # ip = random.choice(['1.1.1.1','2.2.2.2','3.3.3.3','8.8.8.8','9.9.9.9'])
        # ip = random.choice(['1.1.1.1','9.9.9.9'])
        counter += 1
        
        # if counter == 5000:
        #     quit()
        # if counter == 200:
        #     rateLimit.block_time = 5
        # if counter == 500:
        #     rateLimit.block_time = 0
        
        # if counter % 200 == 0:
        #     print(f"FastRateLimiter Blocked IPs: {rateLimit.get_blocked_ips()}")
            
        # if counter % 100 == 0:
        #     print(f"FastRateLimiter Stats: {rateLimit.get_stats(top_items=30)}")
            # time.sleep(5)

        # if counter % 5 == 0:
        #     print(f"FastRateLimiter CacheInfo: {rateLimit.cache_info()}")
            
        if rateLimit(ip):
            print(cError(f"[{dt.now().strftime('%H:%M:%S.%f')}] Denied request #{str(counter).zfill(4)} from IP {ip} - Rate limit exceeded [{'%.9f'%(time.monotonic()-start_time)}]"))
            # time.sleep(0.1)
            continue
        
        # if counter == 1000000:
        #     print("CacheInfo: decreasing ip_list")
        #     ip_list = ip_list[:50000]
        #     rateLimit.__rate_limit_cache.clear()
        #     print(rateLimit.cache_info())
        # if counter == 2000000:
        #     print("CacheInfo: increasing ip_list")
        #     ip_list.extend([randomipv4() for i in range(150000)])
        #     rateLimit.__rate_limit_cache.clear()
        #     print(rateLimit.cache_info())
        
        print_event(ip,start_time)
        # time.sleep(0.01)

    # print(f"FastRateLimiter Blocked IPs: {rateLimit.get_blocked_ips()}")
    print(f"FastRateLimiter Blocked IPs: {rateLimit.get_stats(top_items=1000)}")
    
    # current, peak = tracemalloc.get_traced_memory()
    # print(f"Memória atual usada: {current / 1024:.1f} KB")
    # print(f"Pico de memória: {peak / 1024:.1f} KB")

    # tracemalloc.stop()  # Para o rastreamento
        