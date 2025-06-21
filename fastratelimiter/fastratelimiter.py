#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""FastRateLimiter v1.0.3 - A fast and efficient rate limiter for Python."""
"""
 ______        _     _____       _         _      _           _ _
|  ____|      | |   |  __ \     | |       | |    (_)         (_) |
| |__ __ _ ___| |_  | |__) |__ _| |_ ___  | |     _ _ __ ___  _| |_ ___ _ __
|  __/ _` / __| __| |  _  // _` | __/ _ \ | |    | | '_ ` _ \| | __/ _ \ '__|
| | | (_| \__ \ |_  | | \ \ (_| | ||  __/ | |____| | | | | | | | ||  __/ |
|_|  \__,_|___/\__| |_|  \_\__,_|\__\___| |______|_|_| |_| |_|_|\__\___|_|

    Author.: Ricardo Abuchaim - ricardoabuchaim@gmail.com
    License: MIT
    Github.: https://github.com/rabuchaim/fastratelimiter
    Issues.: https://github.com/rabuchaim/fastratelimiter/issues
    PyPI...: https://pypi.org/project/fastratelimiter/  ( pip install fastratelimiter )

"""
__appname__ = 'FastRateLimiter'
__version__ = '1.0.3'
__release__ = '22/Jun/2025'

import os, sys, threading, random, functools, bisect, ipaddress, time, socket, struct, math
from typing import List, Dict, Iterator
from collections import namedtuple
from datetime import datetime as dt

__all__ = ['FastRateLimiter']

class NoLimitList:
    """A list-type object to manage the list of allowed networks and perform quick searches using bisect and working with IPs as integers. 
    A list with 10000 IP/CIDR (IPv4 and IPv6) took 0.03 to be processed. The verification is around 0.000005 regardless of the list size.
       
       by Ricardo Abuchaim - ricardoabuchaim@gmail.com"""
    def __init__(self,no_limit_list:List[str],lru_cache_maxsize:int=0,debug:bool=False):
        self.last_discarted_ips = []
        self.__debug = debug
        self.__list_chunks, self.__first_ip_chunks, self.__last_ip_chunks, self.__list_index = [], [], [], []
        self.__lru_cache_maxsize = lru_cache_maxsize
        if self.__lru_cache_maxsize > 0:
            self.check_iplong = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.check_iplong)
            self.check_ipaddr = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.check_ipaddr)
            self.is_valid_ipaddr = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.is_valid_ipaddr)
            self.is_valid_iplong = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.is_valid_iplong)
            self.is_valid_cidr =  functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.is_valid_cidr)
            self.__get_cidr = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.__get_cidr)
            self.__ip2int =  functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.__ip2int)
            self.__int2ip =  functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.__int2ip)
        self.__data:List[str] = self.__process_list(no_limit_list)
    def debug(self,msg:str):
        """Debug method to print messages. If debug is True, it will print the message."""
        print(msg,flush=True) if self.__debug else None
    def __getitem__(self,index:int) -> str:
        return self.__data[index]
    def __iter__(self)->Iterator[str]:
        return iter(self.__data)
    def __len__(self)->int:
        return len(self.__data)
    def __contains__(self,item:str)->bool:
        return item.strip() in self.__data
    def __repr__(self):
        return repr(self.__data)
    def __clear_check_ip_cache(self):
        try:
            if self.__lru_cache_maxsize > 0:
                self.check_iplong.cache_clear()
                self.check_ipaddr.cache_clear()
        except Exception:
            pass
    def is_valid_ipaddr(self,ipaddr:str)->bool:
        """Check if an IP address is valid. Accepts IPv4, IPv6 or any CIDR. (Elapsed average time: 0.000001)"""
        return self.__ip2int(ipaddr) != 0
    def is_valid_iplong(self,iplong:int)->bool:
        """Check if an integer is a valid IPv4/IPv6 address. (Elapsed average time: 0.000001)"""
        return self.__int2ip(iplong) is not None
    def is_valid_cidr(self,cidr:str):
        """Check if a CIDR is valid. (Elapsed average time: 0.000007)
        
        Ex: 10.0.0.10/8 is INVALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID
        c1a5:9ba4:8d92:636e:60fd:8756:430b:0000/64 is INVALID, c1a5:9ba4:8d92:636e::/64 is VALID"""
        try: 
            ipaddress.ip_network(cidr.strip(),strict=True)
            return True
        except Exception:
            return False
    def __ip2int(self,ipaddr:str)->int:
        """Converts an IPv4/IPv6 address to an integer. (Elapsed average time: 0.000001)"""
        try:
            return struct.unpack("!L",socket.inet_aton(ipaddr.strip()))[0]
        except Exception:
            try:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6,ipaddr.strip()),byteorder='big')
            except Exception:
                pass
        return 0
    def __int2ip(self,iplong:int)->str:
        """Convert an integer to IP Address (IPv4 or IPv6). For IPv6, returns the full expanded zero-padded form. """
        try:
            if iplong < 2**32:  # MAX IPv4
                return socket.inet_ntoa(struct.pack('>L',iplong))
            else:
                ip_bytes = iplong.to_bytes(16,byteorder='big')
                hextets = [f"{(ip_bytes[i] << 8 | ip_bytes[i+1]):04x}" for i in range(0,16,2)]
                return ':'.join(hextets)
        except Exception:
            return None
    def __get_cidr(self,ipaddr:str):
        """Converts an IP address to CIDR format. Add /32 to the IPv4 address if it is not present or add /128 to the IPv6 address if it is not present. (Elapsed average time 0.0000006)"""
        ip = ipaddr.strip()
        return str(ip)+"/32" if (ip.find(":") < 0 and ip.find("/") < 0) else str(ip)+"/128" if (ip.find("/") < 0) else ip
    def __split_list(self,a_list,n):
        """Split a_list in chunks defined by n"""
        sliced_lists = []
        for i in range(0, len(a_list), n):
            sliced_lists.append(a_list[i:i + n])
        return sliced_lists
    def __find_balanced_chunk_size(self,list_size,min_chunk_size:int=100,max_chunk_size:int=5000):
        """Finds a balanced chunk size for splitting a list of size n into chunks,
           such that the difference between the number of chunks and the chunk size is minimized."""
        if list_size <= min_chunk_size:
            return min_chunk_size  # if the list is smaller than the minimum chunk size, return the list size
        best_chunk_size = 1
        best_diff = float('inf')
        for chunk_size in range(1,max_chunk_size+1):
            q = math.ceil(list_size/chunk_size)
            diff = abs(chunk_size-q)
            if diff <= 1:  # we find the best value!
                return chunk_size
            elif diff < best_diff:
                best_diff = diff
                best_chunk_size = chunk_size
        return best_chunk_size
    def __process_list(self,no_limit_list:List[str])->List[str]:
        """Process the no_limit_list"""
        self.last_discarted_ips.clear()
        new_list = list(set(no_limit_list)) # remove duplicates
        if len(new_list) == 0:
            return []
        try:
            # normalize the list of IPs in cidr format and test if the IP is valid
            new_list = [self.__get_cidr(item) for item in new_list]
            # remove invalid CIDRs from the list (ex: 10.0.0.10/8 is INVALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID)
            self.last_discarted_ips = [cidr for cidr in new_list if not self.is_valid_cidr(cidr)]
            new_list = list(set(new_list) - set(self.last_discarted_ips))
            # sort the list of IPs in ascending order of IP, remove duplicates and blank items
            if len(new_list) == 0:
                return []
            new_list = sorted(list(filter(None,sorted(list(dict.fromkeys(new_list))))),key=lambda ip:self.__ip2int(ip.split("/")[0]))
            chunk_size = self.__find_balanced_chunk_size(len(new_list))
            # get the first and last IP of the CIDR and convert them to integer. Keep 2 lists: one with the first IP and another with the last IP
            self.__list_chunks = self.__split_list(new_list,chunk_size)
            self.__first_ip_chunks = self.__split_list([self.__ip2int(item.split("/")[0]) for item in new_list],chunk_size)
            self.__last_ip_chunks = self.__split_list([int(ipaddress.ip_network(item,strict=False)[-1]) for item in new_list],chunk_size)
            self.__list_index.clear()
            for item in self.__first_ip_chunks:
                self.__list_index.append(item[0])
        except Exception as ERR: 
            self.debug(f"Exception at NoLimitList.__process_list: {str(ERR)}")
            return []
        self.__clear_check_ip_cache()
        return new_list
    def set_list(self,items:List[str]):
        """Set a new list"""
        self.__data = self.__process_list(items)
    def get_list(self)->List[str]:
        """Get the current no limit list"""
        return list(self.__data)  # retorna cópia
    def add_ip(self,ipaddr:str)->bool:
        """Add an ip address or CIDR to no limit list"""
        try:
            ip = ipaddr.strip()
            if ip and ip not in self.__data:
                self.__data.append(ip)
                self.__data = self.__process_list(self.__data)
                return True
        except Exception as ERR: 
            self.debug(f"Exception at NoLimitList.add_ip: {str(ERR)}")
        return False
    def add_ips(self,ipaddr_list:List[str])->bool:
        """Add a list of ip addressess or CIDRs to no limit list"""
        try:
            for ip in ipaddr_list:
                ip = ip.strip()
                if ip and ip not in self.__data:
                    self.__data.append(ip)
            self.__data = self.__process_list(self.__data)
            return True
        except Exception as ERR: 
            self.debug(f"Exception at NoLimitList.add_ips: {str(ERR)}")
        return False
    def remove_ip(self,ipaddr:str)->bool:
        """Remove an ip address or a CIDR from no limit list"""
        try:
            ip = ipaddr.strip()
            if ip and ip in self.__data:
                self.__data.remove(ip)
                self.__data = self.__process_list(self.__data)
                return True
        except Exception as ERR: 
            self.debug(f"Exception at NoLimitList.remove_ip: {str(ERR)}")
        return False
    def remove_ips(self,ipaddr_list:List[str])->bool:
        """Remove a list of ip addressess or a CIDRs from no limit list"""
        try:
            for ip in ipaddr_list:
                ip = ip.strip()
                if ip and ip in self.__data:
                    try: 
                        self.__data.remove(ip)
                    except Exception:
                        pass
            self.__data = self.__process_list(self.__data)
            return True
        except Exception as ERR: 
            self.debug(f"Exception at NoLimitList.remove_ips: {str(ERR)}")
        return False
    def check_ipaddr(self,ipaddr:str)->bool:
        """Check if an IP address is in the no limit list. Returns a tuple with the search response (True or False) and if True, 
           it also returns the network that the IP fits into, otherwise it returns None. (Elapsed average time: 0.000006)
           
           Ex:
           
            no_limit_result,no_limit_network = self.no_limit_list.check_ipaddr('1.2.3.4')
            
           `no_limit_result` can be True or False and `no_limit_network` can be a network CIDR or None
           """
        return self.check_iplong(self.__ip2int(ipaddr))
    def check_iplong(self,iplong:int)->tuple:
        """Check if an "IP address as integer (iplong)" is in the no limit list. Returns a tuple with the search response (True or False) and if True, 
           it also returns the network that the IP fits into, otherwise it returns None. (Elapsed average time: 0.000002)
           
           Ex:
           
            no_limit_result,no_limit_network = self.no_limit_list.check_iplong(123456789)
            
           `no_limit_result` can be True or False and `no_limit_network` can be a network CIDR or None
           """
        if self.__data == []:
            return False, None
        try:
            match_root_index = bisect.bisect_right(self.__list_index,iplong)-1
            match_list_index = bisect.bisect_right(self.__first_ip_chunks[match_root_index],iplong)-1
            try:
                network = self.__list_chunks[match_root_index][match_list_index]
            except Exception:
                network = None
            inside_network = (iplong >= self.__first_ip_chunks[match_root_index][match_list_index]) and (iplong <= self.__last_ip_chunks[match_root_index][match_list_index])
            network = None if inside_network is False else network
            return inside_network, network
        except Exception as ERR:
            self.debug(f"Failed at NoLimitList.check_iplong({iplong}): {str(ERR)}")
        return False, None

class FastRateLimiter():
    def __init__(self,rate_limit:int,per:int=1,block_time:int=0,no_limit_list:List[str]=[],with_stats:bool=False,cache_cleanup_interval:int=3,lru_cache_maxsize:int=512,debug:bool=False):
        """Initializes a FastRateLimiter object. To initialize a "per second" rate limiter, use `per=1` and `block_time=0`.

        Parameters
        
            - rate_limit (int): Maximum number of allowed requests per time window.
            - per (int): Time window in seconds for applying the rate limit (default: 1).
            - block_time (int): Duration (in seconds) to block a client after exceeding the limit (0 = blocking until the end of the current second).
            - no_limit_list (List[str]): List of IPs or Networks CIDR that are exempt from rate limiting.
            - with_stats (bool): If True, enables usage statistics tracking.
            - cache_cleanup_interval (int): Interval in seconds to automatically clean up stale cache entries. Valid values between 2 and 60. (default: 3 seconds).
            - lru_cache_maxsize (int): Maximum size of the LRU cache used to store access records (default: 512). Use 0 to disable.
            - debug: display debug messages. When enabled, it overrides the checking of the FASTRATELIMITER_DEBUG environment variable.

        For Debug :
        
            export FASTRATELIMITER_DEBUG=1    
        """
        if debug is True or os.environ.get("FASTRATELIMITER_DEBUG","") == "1":
            self.__debug = self.__debug_enabled
        
        if cache_cleanup_interval < 2:
            raise ValueError("The cache cleanup interval must be equal or greater than 2 seconds.") from None
        elif cache_cleanup_interval > 60:
            raise ValueError("The cache cleanup interval must be equal to or less than 60 seconds. Frequently cleaning this cache is very important to avoid high memory consumption.") from None
        self.cache_cleanup_interval = cache_cleanup_interval
        
        self.__lru_cache_maxsize = lru_cache_maxsize
        if self.__lru_cache_maxsize > 0:
            self.__int2ip = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.__int2ip)
            self.__ip2int = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.__ip2int)
            self.__ip2int_raise_exception = functools.lru_cache(maxsize=self.__lru_cache_maxsize)(self.__ip2int_raise_exception)
        
        self.__lock = threading.RLock()

        self.__rate_limit = rate_limit
        self.__per = per
        self.__block_time = block_time
        self.no_limit_list = NoLimitList(no_limit_list=no_limit_list,lru_cache_maxsize=lru_cache_maxsize,debug=debug)
        if len(self.no_limit_list.last_discarted_ips):
            self.__debug(f"NoLimitList discarted IPs/CIDRs: {self.no_limit_list.last_discarted_ips}")
        self.__debug(f"NoLimitList valid IPs/CIDRs: {self.no_limit_list}")
        
        self.__rate_limit_cache = {}
        self.__rate_limit_blocked_last_seen: Dict[int, int] = {}  # iplong:timestamp -> last_block_second:int

        self.__with_stats = with_stats
        self.__rate_limit_stats = {}
        if self.__with_stats:
            if self.__per == 1 and self.__block_time == 0:
                self.__save_stat = self.__save_stat_enabled_per_second
            else:
                self.__save_stat = self.__save_stat_enabled_advanced
        if self.__per == 1 and self.__block_time == 0:
            self.__call_rate_limit = self.__call_rate_limit_per_second
            threading.Thread(target=self.__worker_cache_cleanup_per_second, daemon=True).start()
        else:
            self.__call_rate_limit = self.__call_rate_limit_advanced
            threading.Thread(target=self.__worker_cache_cleanup_advanced, daemon=True).start()

    def __debug(self, msg:str):...
    def __debug_enabled(self, msg:str):
        print(f"\033[38;2;0;255;0m{dt.now().strftime('%y/%m/%d %H:%M:%S.%f')} [FASTRATELIMITER_DEBUG] {str(msg)}\033[0m")
       
    def __ip2int_raise_exception(self,ipaddr:str)->int:
        """Converts an IPv4/IPv6 address to an integer. (Elapsed average time: 0.000001)"""
        try:
            return struct.unpack("!L",socket.inet_aton(ipaddr.strip()))[0]
        except Exception:
            try:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6,ipaddr.strip()),byteorder='big')
            except Exception as ERR:
                raise Exception(f"{str(ERR)}") from None
            
    def __ip2int(self,ipaddr:str)->int:
        """Converts an IPv4/IPv6 address to an integer."""
        try:
            return self.__ip2int_raise_exception(ipaddr)
        except Exception:
            return 0

    def __int2ip(self,iplong:int)->str:
        """Convert an integer to IP Address (IPv4 or IPv6). For IPv6, returns the full expanded zero-padded form. """
        try:
            if iplong < 2**32:  # MAX IPv4
                return socket.inet_ntoa(struct.pack('>L',iplong))
            else:  # IPv6
                # Converte int em 16 bytes
                ip_bytes = iplong.to_bytes(16,byteorder='big')
                # Quebra os 16 bytes em 8 blocos de 2 bytes (16 bits cada)
                hextets = [f"{(ip_bytes[i] << 8 | ip_bytes[i+1]):04x}" for i in range(0,16,2)]
                return ':'.join(hextets)
        except Exception:
            return None

    @property
    def rate_limit(self)->int:
        """Returns the rate limit."""
        return self.__rate_limit
    
    @rate_limit.setter
    def rate_limit(self,new_rate_limit:int):
        if new_rate_limit < 1:
            raise ValueError("The rate limit must be greater than 1.") from None
        self.__rate_limit = new_rate_limit
        self.cache_clear()

    @property
    def per(self)->int:
        """Returns the rate limit period in seconds."""
        return self.__per
    
    @per.setter
    def per(self,new_per:int):
        if new_per < 1:
            raise ValueError("The rate limit period must be equal or greater than 1 second.") from None
        self.__per = new_per
        if self.__per == 1 and self.__block_time == 0:
            self.__call_rate_limit = self.__call_rate_limit_per_second
            if self.__with_stats:
                self.reset_stats()
                self.__save_stat = self.__save_stat_enabled_per_second
        else:
            self.__call_rate_limit = self.__call_rate_limit_advanced
            if self.__with_stats:
                self.reset_stats()
                self.__save_stat = self.__save_stat_enabled_advanced
        self.cache_clear()
    
    @property
    def block_time(self)->int:
        """Returns the block time in seconds."""
        return self.__block_time

    @block_time.setter
    def block_time(self,new_block_time:int):
        if new_block_time < 0:
            raise ValueError("The block time must be equal or greater than 0 second.") from None
        self.__block_time = new_block_time
        if self.__block_time == 0 and self.__per == 1:
            self.__call_rate_limit = self.__call_rate_limit_per_second
            if self.__with_stats:
                self.reset_stats()
                self.__save_stat = self.__save_stat_enabled_per_second
        else:
            self.__call_rate_limit = self.__call_rate_limit_advanced
            if self.__with_stats:
                self.reset_stats()
                self.__save_stat = self.__save_stat_enabled_advanced
        self.cache_clear()
    
    def cache_info(self)->namedtuple:
        """Returns a named tuple with rate limit cache information. 
        
        - cache_length: length of the IP rate limit cache
        - cache_size: the size (in bytes) of the IP rate limit cache 
        - memory_in_use: the total memory used by your application in MiB (on linux and macOS only)
        
        Example 
        
        ```python
            rate_limiter = FastRateLimiter(rate_limit=100)
            cache_info = rate_limiter.cache_info()
            print(f"Cache size: {cache_info.cache_size} bytes")
            print(f"Cache length: {cache_info.cache_length} items")
            print(f"Current Memory in Use: {cache_info.memory_in_use} MiB")
        ```
        """
        def get_mem_in_use()->float: # MIB
            """Returns the memory used by the application in MiB. Works on Linux and macOS only."""
            try:
                mem_in_use = next(int(line.split()[1])/1024 for line in open(f'/proc/{os.getpid()}/status','r') if line.startswith("VmRSS:"))
                return math.trunc((mem_in_use)*100)/100
            except Exception:
                return 0.0
        CacheInfo = namedtuple("CacheInfo", ["items", "size_in_kb", "memory_in_mb"])
        return CacheInfo(len(self.__rate_limit_cache), math.trunc((sys.getsizeof(self.__rate_limit_cache)/1024)*100)/100, get_mem_in_use())

    def cache_clear(self):
        """Clears the IP rate limit cache."""
        with self.__lock:
            self.__rate_limit_cache.clear()
            self.__rate_limit_blocked_last_seen.clear()
        return True
        
    def __save_stat(self,ip:int):...
    def __save_stat_disabled(self,ip:int):...
    
    def __save_stat_enabled_per_second(self,ip:int):
        current_second = int(time.time())
        last_blocked = self.__rate_limit_blocked_last_seen.get(ip,None)
        if last_blocked == current_second: # A block for the current second has already been counted
            return
        self.__rate_limit_blocked_last_seen[ip] = current_second
        if ip in self.__rate_limit_stats:
            self.__rate_limit_stats[ip] += 1
        else:
            self.__rate_limit_stats[ip] = 1

    def __save_stat_enabled_advanced(self,ip:int):
        with self.__lock:
            if ip in self.__rate_limit_stats:
                self.__rate_limit_stats[ip] += 1
            else:
                self.__rate_limit_stats[ip] = 1
            
    def get_stats(self,top_items:int=10,reset_stats:bool=False)->Dict:
        """Returns a dictionary with the top {top_items} IPs that exceeded the rate limit.
        
        - top_items: The number of top IPs to be returned. Default is 10. Maximum is 100.
        
        - reset_stats: Reset all stats after return the top IPs 
        """
        def int_to_ipv4(iplong):
            return socket.inet_ntoa(struct.pack('>L', iplong))
        def int_to_ipv6(iplong):
            ip_bytes = iplong.to_bytes(16,byteorder='big')
            hextets = [f"{(ip_bytes[i] << 8 | ip_bytes[i+1]):04x}" for i in range(0,16,2)]
            return ':'.join(hextets)
        top_items = 100 if top_items > 100 else top_items
        MAX_IPv4 = 4294967295
        try:
            return {(int_to_ipv6(key) if key>MAX_IPv4 else int_to_ipv4(key)):val for key,val in dict(sorted(self.__rate_limit_stats.items(), key=lambda item: item[1], reverse=True)[:top_items]).items()}
        finally:
            if reset_stats:
                self.reset_stats()
        
    def reset_stats(self):
        """Reset the rate limit statistics."""
        with self.__lock:
            self.__rate_limit_blocked_last_seen.clear()
            self.__rate_limit_stats.clear()
        return True 
            
    def get_blocked_ips(self)->dict:
        """Returns a dict with the IPs and the end date of the block. This function only works with the advanced rate limit, that is, per>1 and block_time>1. 
           It does not work with the per second rate limit because everything is very fast, in less than 1 second the IP will be unblocked.
           
           Format: `{ipaddress as string: timestamp as float}`
           """
        start_time = time.monotonic()
        if self.__per == 1 and self.__block_time == 0:
            self.__debug(f"Returned get_blocked_ips empty due to PER SECOND mode {'%.9f'%(time.monotonic()-start_time)} seconds")
            return {}
        try:
            with self.__lock:
                current = dict(sorted({k:v[1] for k,v in self.__rate_limit_cache.items() if v[0] == -1}.items(), key=lambda item: item[0], reverse=False))
                current = {self.__int2ip(ip):until for ip,until in current.items()}
            return current
        except Exception as ERR:
            self.__debug(f"Failed at get_blocked_ips: {str(ERR)}")
            return {}
        finally:
            self.__debug(f"Returned get_blocked_ips in {'%.9f'%(time.monotonic()-start_time)} seconds with {len(current)} IPs")

    def __call__(self,ipaddr:str)->bool:
        """Returns True if the rate limit is exceeded, False otherwise. Raises an Exception if ipaddr is invalid."""
        try:
            iplong = self.__ip2int_raise_exception(ipaddr)
            start_time = time.monotonic()
            no_limit_result,no_limit_network = self.no_limit_list.check_iplong(iplong)
            if no_limit_result:
                self.__debug(f"IP address {ipaddr} is in the no limit list - network {no_limit_network} [{'%.9f'%(time.monotonic()-start_time)}]")
                return False
            else:
                return self.__call_rate_limit(iplong,ipaddr)
        except Exception as ERR:
            raise Exception(f"Exception at {self.__class__.__name__}('{ipaddr}') call: {str(ERR)}")

    def __call_rate_limit(self,iplong:int,ipaddr:str)->bool:...
    
    def __worker_cache_cleanup_per_second(self):
        """Worker that cleans up the cache every {self.cleanup_interval} seconds."""
        while True:
            time.sleep(self.cache_cleanup_interval)
            try:
                with self.__lock:
                    initial_length = len(self.__rate_limit_cache)
                    self.__rate_limit_cache = {key:value for key, value in self.__rate_limit_cache.items() if value[1] > (int(time.time())-(self.block_time+2))}.copy()
                    self.__rate_limit_blocked_last_seen = {
                        ip:second_blocked for ip,second_blocked in self.__rate_limit_blocked_last_seen.items()
                        if second_blocked > (int(time.time())-(self.__block_time+2))
                    }
                self.__debug(f"Cache cleanup: from {initial_length} to {len(self.__rate_limit_cache)} items")
            except Exception as ERR:
                print(f"Failed at __worker_cleanup: {str(ERR)}")

    def __call_rate_limit_per_second(self,iplong:int,ipaddr:str) -> bool:
        """Returns True if the rate limit is exceeded, False otherwise."""
        start_time = time.monotonic()
        now = int(time.time())
        current_rate,eval_time = self.__rate_limit_cache.get(iplong,[0,0])
        try:
            if current_rate >= self.rate_limit and eval_time == now:
                self.__debug(f"\033[91mIP {ipaddr} blocked until {dt.fromtimestamp(now+1)} [{'%.9f'%(time.monotonic()-start_time)}]\033[0m")
                with self.__lock:
                    self.__save_stat(iplong)
                return True
            elif eval_time != now:
                with self.__lock:
                    self.__rate_limit_cache[iplong] = [1,now]
                return False
            else:
                with self.__lock:
                    self.__rate_limit_cache[iplong][0] = current_rate+1
                return False
        except Exception as ERR:
            self.__debug(f"Exception at __call_rate_limit_per_second(ipaddr:{ipaddr}): {str(ERR)}")
            return False

    def __worker_cache_cleanup_advanced(self):
        """Worker that cleans up the cache every 0.1 seconds."""
        while True:
            time.sleep(0.1)
            with self.__lock:
                self.__rate_limit_cache = {k:v for k,v in self.__rate_limit_cache.items() if v[1] >= time.time()}

    def __call_rate_limit_advanced(self,iplong:int,ipaddr:str)->bool:
        start_time = time.monotonic()
        now = time.time()
        current_rate, eval_time = self.__rate_limit_cache.get(iplong,[0,0])
        if current_rate == -1 and eval_time > now:
            self.__debug(f"\033[91mIP {ipaddr} blocked until {dt.fromtimestamp(eval_time)} [{'%.9f'%(time.monotonic()-start_time)}]\033[0m")
            return True
        try:
            if eval_time > now:
                # If the evaluation time is greater than the current time, it means that the IP is still being evaluated.
                # If the current rate is already equal to the rate limit, it means that the IP has exceeded the rate limit.
                # In this case, we save the IP statistics, update the rate limit cache with a block status (-1), and return True.
                # Otherwise, we increment the current rate by 1.
                if current_rate >= self.rate_limit:
                    with self.__lock:
                        self.__rate_limit_cache[iplong] = [-1,time.time()+self.__block_time]
                        self.__save_stat(iplong)
                    return True
                else:
                    with self.__lock:
                        self.__rate_limit_cache[iplong] = [current_rate+1,eval_time]
                    return False
            else:
                # If the current rate and evaluation time are both 0, it means that the IP is not in the rate limit cache.
                # In this case, we add the IP to the cache with an initial rate of 1 and an evaluation time of now + per.
                # If the evaluation time is less than or equal to the current time, it means that the IP evaluation has expired.
                # In this case, we reset the rate limit cache for the IP with an initial rate of 1 and an evaluation time of now + per.
                with self.__lock:
                    self.__rate_limit_cache[iplong] = [1,time.time()+self.__per]
                return False
        except Exception as ERR:
            self.__debug(f"Exception at __call_rate_limit_advanced (ipaddr:{ipaddr}): {str(ERR)}") 
        return False
    
    def speed_test(self,max_ips:int=500000):
        def randomipv4():
            return self.__int2ip(random.randint(16777216,3758096383))        
        def randomipv6():
            return ':'.join([f'{random.randint(0, 0xffff):04x}' for _ in range(8)])
        if max_ips < 10:
            raise ValueError("The maximum number of IPs must be greater than or equal to 10.") from None    
        self.__save_stat = self.__save_stat_disabled
        start_time = time.monotonic()
        print(f">>> Creating an IP addresses list with {'{:,d}'.format(max_ips).replace(',','.')} randomic IPv4/IPv6 addressess...",end="")
        ipaddr_list = [random.choice([randomipv4(),randomipv6()]) for _ in range(int(max_ips/10))]
        ipaddr_list = ipaddr_list * 10
        print(f"\r>>> IP addresses list with {'{:,d}'.format(max_ips).replace(',','.')} randomic IPv4/IPv6 addressess done in {'%.2f'%(time.monotonic()-start_time)} seconds")
        ##──── FIRST TEST SHOWING RESULT OUTPUT ──────────────────────────────────────────────────────────────────────────────────────────
        self.cache_clear()
        start_time = time.monotonic()
        print(f">>> First Test with {'{:,d}'.format(max_ips).replace(',','.')} randomic IPv4/IPv6 (with output, stats disabled, debug disabled)")
        for num,ipaddr in enumerate(ipaddr_list,1):
            result = self.__call__(ipaddr)
            print(f"\rTesting {num}/{max_ips}... {result}",end="")
        total_time_spent = time.monotonic() - start_time
        current_lookups_per_second = max_ips / total_time_spent
        print("\r  > Current speed: %.2f calls per second (%s IPs with an average of %.9f seconds per call) "
              "[%.5f sec]"%(current_lookups_per_second,'{:,d}'.format(max_ips).replace(',','.'),total_time_spent / max_ips,time.monotonic()-start_time))
        ##──── SECOND TEST WITH NO OUTPUT ────────────────────────────────────────────────────────────────────────────────────────────────
        self.cache_clear()
        start_time = time.monotonic()
        print(f">>> Second Test with {'{:,d}'.format(max_ips).replace(',','.')} randomic IPv4/IPv6 (no output, stats disabled, debug disabled)")
        for ipaddr in ipaddr_list:
            result = self.__call__(ipaddr)
        total_time_spent = time.monotonic() - start_time
        current_lookups_per_second = max_ips / total_time_spent
        print("\r  > Current speed: %.2f calls per second (%s IPs with an average of %.9f seconds per call) "
              "[%.5f sec]"%(current_lookups_per_second,'{:,d}'.format(max_ips).replace(',','.'),total_time_spent / max_ips,time.monotonic()-start_time))
        if self.__with_stats:
            if self.__per == 1 and self.__block_time == 0:
                self.__save_stat = self.__save_stat_enabled_per_second
            else:
                self.__save_stat = self.__save_stat_enabled_advanced
        