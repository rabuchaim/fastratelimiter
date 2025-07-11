#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""FastRateLimiter v1.1.0 - A fast and efficient rate limiter for Python."""
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
__version__ = '1.1.0'
__release__ = '11/July/2025'

import os, sys, threading, random, functools, bisect, typing, time, socket, struct, math
from typing import List, Dict, Iterator
from collections import namedtuple
from datetime import datetime as dt

__all__ = ['FastRateLimiter']

##──── A reduced and modified version of Unlimited IP List - pip install unlimitediplist ────────────────────────────────────────────────────
class NoLimitList:
    """A list-type object to manage the list of IPv4/IPv6 networks and perform quick searches using bisect and working with IPs as integers.
    A list with 10000 IP/CIDR (IPv4 and IPv6) took 0.05 to be processed. The verification is around 0.000005 regardless of the list size.
    """
    def __init__(self, ip_networks_list: typing.List[str], normalize_invalid_cidr: bool = False, debug: bool = False):
        self._log_debug = self._log_debug if debug else lambda msg: None
        self._lock = threading.RLock()
        self.__normalize_invalid_cidr = normalize_invalid_cidr
        self.last_discarted_ips = []
        self.__list_chunks, self.__list_index = [], []
        self.__first_ip_chunks, self.__last_ip_chunks = [], []
        self._cidrs: typing.List[str] = []
        self.__process_list(ip_networks_list)
    def __getitem__(self, index: int) -> str:
        return self._cidrs[index]
    def __iter__(self) -> Iterator[str]:
        return iter(self._cidrs)
    def __len__(self) -> int:
        return len(self._cidrs)
    def __contains__(self, item: str) -> bool:
        return item.strip() in self._cidrs
    def __repr__(self):
        return repr(self._cidrs)
    def _log_debug(self, msg: str):
        """Log debug messages if debug mode is enabled"""
        print(f"\x1b[38;2;0;255;0m{dt.now().strftime('%y/%m/%d %H:%M:%S.%f')} [NO_LIMIT_LIST_DEBUG] {str(msg)}\x1b[0m")
    def is_valid_ipaddr(self, ipaddr: str) -> bool:
        """Check if an IP address is valid. Accepts IPv4 or IPv6. (Elapsed average time: 0.000001)"""
        return self.ip_to_int(ipaddr.strip()) is not None
    def is_valid_iplong(self, iplong: int) -> bool:
        """Check if an integer is a valid IPv4/IPv6 address. (Elapsed average time: 0.000001)"""
        return self.int_to_ip(iplong) is not None
    def is_valid_cidr(self, cidr: str, strict: bool = True) -> bool:
        """Check if an IPv4/IPv6 CIDR is valid in pure Python.
          
           Accepts ONLY CIDR with the network address, not the host address.
        
        with strict=True, it checks if the bits outside the mask are zero.
            Ex: 10.0.0.10/8 is INVALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID
            c1a5:9ba4:8d92:636e:60fd:8756:430b:0000/64 is INVALID, c1a5:9ba4:8d92:636e::/64 is VALID
        
        with strict=False, it only checks if the CIDR is well-formed.
            Ex: 10.0.0.10/8 is VALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID
            c1a5:9ba4:8d92:636e:60fd:8756:430b:0000/64 is VALID, c1a5:9ba4:8d92:636e::/64 is VALID
        """
        try:
            cidr = cidr.strip()
            if '/' not in cidr:
                if strict:
                    return False  # sem prefixo é inválido como CIDR
                else:
                    cidr = self._normalize_cidr_suffix(cidr)  # adiciona /32 para IPv4 ou /128 para IPv6 se não tiver prefixo
            ip_part, prefix_str = cidr.split('/')
            prefix = int(prefix_str)
            if '.' in ip_part:
                packed_ip = socket.inet_aton(ip_part)
                ip_int = struct.unpack("!L", packed_ip)[0]
                if not (0 <= prefix <= 32):
                    return False
                if strict:
                    mask = ((1 << prefix) - 1) << (32 - prefix)
                    return ip_int & ~mask == 0  # os bits fora da máscara devem ser zero
                return True
            else:
                packed_ip = socket.inet_pton(socket.AF_INET6, ip_part)
                ip_int = int.from_bytes(packed_ip, byteorder='big')
                if not (0 <= prefix <= 128):
                    return False
                if strict:
                    mask = ((1 << prefix) - 1) << (128 - prefix)
                    return ip_int & ~mask == 0
                return True
        except Exception:
            return False
    def get_valid_cidr(self, cidr: str, normalize: bool = True) -> str:
        """Returns a valid normalized CIDR (IPv4 or IPv6) in pure Python.
        
        If normalize is False, it returns the CIDR as it is, without checking if the bits outside the mask are zero.
        
        If normalize is True, it returns the CIDR with the network address, ensuring that the bits outside the mask are zero.
        """
        try:
            cidr = cidr.strip()
            if '/' not in cidr:
                if not normalize:
                    return None
                cidr = self._normalize_cidr_suffix(cidr)
            ip_str, prefix_str = cidr.split('/')
            prefix = int(prefix_str)
            if '.' in ip_str:
                if not (0 <= prefix <= 32):
                    return None
                packed = socket.inet_aton(ip_str)
                ip_int = struct.unpack("!L", packed)[0]
                if normalize:
                    mask = ((1 << prefix) - 1) << (32 - prefix)
                    network_int = ip_int & mask
                    network_ip = socket.inet_ntoa(struct.pack("!L", network_int))
                    return f"{network_ip}/{prefix}"
                else:
                    mask = ((1 << prefix) - 1) << (32 - prefix)
                    if ip_int & ~mask != 0:
                        return None
                    return f"{ip_str}/{prefix}"
            else:
                packed = socket.inet_pton(socket.AF_INET6, ip_str)
                if not (0 <= prefix <= 128):
                    return None
                ip_int = int.from_bytes(packed, byteorder='big')
                if normalize:
                    mask = ((1 << prefix) - 1) << (128 - prefix)
                    network_int = ip_int & mask
                    network_ip = self.compress_ipv6(self.int_to_ip(network_int))
                    return f"{network_ip}/{prefix}"
                else:
                    mask = ((1 << prefix) - 1) << (128 - prefix)
                    if ip_int & ~mask != 0:
                        return None
                    return f"{ip_str}/{prefix}"
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.get_valid_cidr({cidr}): {str(ERR)}")
            return None
    def ip_to_int(self, ipaddr: str) -> int:
        """Converts an IPv4/IPv6 address to an integer. (Elapsed average time: 0.000001)"""
        try:
            return struct.unpack("!L", socket.inet_aton(ipaddr.strip()))[0]
        except Exception:
            try:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6, ipaddr.strip()), byteorder="big")
            except Exception:
                return None
    def int_to_ip(self, iplong: int) -> str:
        """Convert an integer to IP Address (IPv4 or IPv6). For IPv6, returns the full expanded zero-padded form."""
        try:
            if iplong <= 2**32:  # MAX IPv4
                return socket.inet_ntoa(struct.pack(">L", iplong))
            else:
                ip_bytes = iplong.to_bytes(16, byteorder="big")
                hextets = [f"{(ip_bytes[i] << 8 | ip_bytes[i+1]):04x}" for i in range(0, 16, 2)]
                return ":".join(hextets)
        except Exception:
            return None
    def compress_ipv6(self, hextets: typing.Union[str, list]) -> str:
        """Compresses an IPv6 address represented as a list of hextets."""
        if isinstance(hextets, str):
            if "/" in hextets:
                hextets = hextets.split("/")[0]
            hextets = hextets.split(":")
        hextets = [h if h else "0000" for h in hextets]  # replace empty hextets with "0000"
        if len(hextets) != 8: # fill missing hextets with "0000"
            hextets = hextets + ["0000"] * (8 - len(hextets))
        best_start = best_len = -1
        curr_start = curr_len = -1
        for i in range(8):
            if hextets[i] == "0000":
                if curr_start == -1:
                    curr_start = i
                    curr_len = 1
                else:
                    curr_len += 1
            else:
                if curr_len > best_len:
                    best_start, best_len = curr_start, curr_len
                curr_start = curr_len = -1
        if curr_len > best_len:
            best_start, best_len = curr_start, curr_len
        if best_len > 1:
            hextets = hextets[:best_start] + [""] + hextets[best_start + best_len:]
            if best_start == 0:
                hextets = [""] + hextets
            if best_start + best_len == 8:
                hextets += [""]
        return ":".join(hextets).replace(":::", "::")
    def _normalize_cidr_suffix(self, ipaddr: str):
        """Converts an IP address to CIDR format. Add /32 to the IPv4 address if it is not present 
        or add /128 to the IPv6 address if it is not present. (Elapsed average time 0.0000006)"""
        ip = ipaddr.strip()
        if '/' in ip:
            return ip
        return f"{ip}/32" if ':' not in ip else f"{ip}/128"
    def __split_list(self, a_list, size):
        """Split a_list in chunks defined by size"""
        try:
            return [a_list[i:i + size] for i in range(0, len(a_list), size)]
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.__split_list(): {str(ERR)}")
            return []
    def __get_first_last_ip_cidr(self, cidr: str) -> tuple:
        """Get the first and last IP of a CIDR in integer format."""
        try:
            ip_part, prefix_part = cidr.split("/")
            prefix = int(prefix_part)
            ip_int = self.ip_to_int(ip_part)
            if ":" in ip_part:  # IPv6
                bits = 128
            else:  # IPv4
                bits = 32
            mask = ((1 << prefix) - 1) << (bits - prefix)
            mask &= (1 << bits) - 1  # garante que só usamos os bits válidos
            network_ip = ip_int & mask
            broadcast_ip = network_ip | ((1 << (bits - prefix)) - 1)
            return network_ip, broadcast_ip
        except Exception:
            return 0,0
    def __find_balanced_chunk_size(self, list_size, min_chunk_size: int = 100, max_chunk_size: int = 5000):
        """Finds a balanced chunk size for splitting a list of size n into chunks,
        such that the difference between the number of chunks and the chunk size is minimized."""
        if list_size <= min_chunk_size:
            return list_size  # if the list is smaller than the minimum chunk size, return the list size
        best_chunk_size = 1
        best_diff = float("inf")
        for chunk_size in range(1, max_chunk_size + 1):
            q = math.ceil(list_size / chunk_size)
            diff = abs(chunk_size - q)
            if diff <= 1:  # the best value!
                return chunk_size
            elif diff < best_diff:
                best_diff = diff
                best_chunk_size = chunk_size
        return best_chunk_size
    def __clear_lists(self, clear_discarded_cidr: bool = False):
        """Clear the internal lists used for processing"""
        with self._lock:
            self._cidrs.clear()
            self.__list_chunks.clear()
            self.__first_ip_chunks.clear()
            self.__last_ip_chunks.clear()
            self.__list_index.clear()
            if clear_discarded_cidr:
                self.last_discarted_ips.clear()
    def __ip_ranges_overlap(self, first1: int, last1: int, first2: int, last2: int) -> bool:
        """Check if two IP ranges overlap."""
        return not (last1 < first2 or first1 > last2)
    def _find_cidr_overlap(self, cidr: str) -> tuple:
        """Detects if a CIDR overlaps with any existing CIDR in the already processed list."""
        try:
            if not self._cidrs:
                return False
            first_ip, last_ip = self.__get_first_last_ip_cidr(self._normalize_cidr_suffix(cidr))
            match_root_index = bisect.bisect_right(self.__list_index, first_ip) - 1
            if match_root_index < 0:
                match_root_index = 0
            # Verify current chunk
            for i in range(len(self.__first_ip_chunks[match_root_index])):
                if self.__ip_ranges_overlap(first_ip, last_ip, self.__first_ip_chunks[match_root_index][i], self.__last_ip_chunks[match_root_index][i]):
                    return self.__list_chunks[match_root_index][i]
            # Verify the prior and the next chunk (if exists)
            for offset in [-1, 1]:
                idx = match_root_index + offset
                if 0 <= idx < len(self.__first_ip_chunks):
                    for i in range(len(self.__first_ip_chunks[idx])):
                        if self.__ip_ranges_overlap(first_ip, last_ip, self.__first_ip_chunks[idx][i], self.__last_ip_chunks[idx][i]):
                            return self.__list_chunks[idx][i]
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList._find_cidr_overlap(): {str(ERR)}")
        return False
    def _remove_overlapping_cidrs(self, new_list: typing.List[str]) -> None:
        """Remove overlapping CIDRs from the new_list and sort them."""
        self._log_debug(f"Processing {len(new_list)} CIDRs to remove overlaps and sorting them.")
        cidrs = [(cidr, *self.__get_first_last_ip_cidr(cidr)) for cidr in new_list]
        cidrs.sort(key=lambda x: x[1])  # Ordena por first_ip
        filtered = []
        prev_cidr, prev_first, prev_last = cidrs[0]
        filtered.append(prev_cidr)
        for cidr, first, last in cidrs[1:]:
            if first <= prev_last:  # overlap
                self.last_discarted_ips.append(cidr)
            else:
                filtered.append(cidr)
                # prev_first, prev_last = first, last
                prev_last = last
        new_list = filtered.copy()
        filtered.clear()
        return new_list
    def __normalize_and_remove_invalid_cidr(self, ip_networks_list: typing.List[str]) -> typing.List[str]:
        """Normalize the list of IPs in CIDR format and remove invalid CIDRs."""
        normalized_list = []
        for cidr in ip_networks_list:
            valid_cidr = self.get_valid_cidr(cidr, normalize=True)
            if valid_cidr:
                if valid_cidr != cidr:
                    self._log_debug(f"Normalized CIDR: {cidr} => {valid_cidr}")
                normalized_list.append(valid_cidr)
            else:
                self._log_debug(f"Invalid CIDR: {cidr}")
                self.last_discarted_ips.append(cidr)
        return normalized_list
    def __normalize_cidr(self, ip_networks_list: typing.List[str]) -> typing.List[str]:
        """Normalize the list of IPs in CIDR format and remove invalid CIDRs. 
        Just add /32 to IPv4 addresses and /128 to IPv6 addresses if they are not present."""
        normalized_list = []
        for cidr in ip_networks_list:
            normalized_list.append(self._normalize_cidr_suffix(cidr))
        return normalized_list
    def __discard_invalid_cidr(self, ip_networks_list: typing.List[str]) -> typing.List[str]:
        """Remove invalid CIDRs from the list."""
        valid_list = []
        for cidr in ip_networks_list:
            if self.is_valid_cidr(cidr):
                valid_list.append(cidr)
            else:
                self._log_debug(f"Invalid CIDR: {cidr}")
                self.last_discarted_ips.append(cidr)
        return valid_list
    def __process_list(self, ip_networks_list: typing.List[str], **kwargs) -> typing.List[str]:
        """Process the ip_networks_list"""
        try:
            if kwargs.get("last_discarted_ips", []) == []:
                self.last_discarted_ips.clear()  # Clear the last discarded CIDR list
            new_list = list(set(ip_networks_list))  # remove duplicates
            new_list = [item.strip() for item in new_list if item.strip()]  # remove blank items
            self._log_debug(f"Processing the ip_networks_list with {len(new_list)} unique items.")
            if len(new_list) == 0:
                self._log_debug("The list is empty after removing duplicates and blank items, clearing the lists.")
                self.__clear_lists()
                return False  # No valid CIDRs to process
            else:
                # normalize the list of IPs in cidr format and test if the IP is valid
                if self.__normalize_invalid_cidr:
                    # Normalize the CIDRs and remove duplicates
                    # Example: 10.10.10.10/8 => 10.0.0.0/8
                    self._log_debug(f"Normalizing the list of IPs in CIDR format and removing invalid CIDRs. Current size: {len(new_list)}")
                    new_list = self.__normalize_and_remove_invalid_cidr(new_list)
                    self._log_debug(f"After normalization, the list size is {len(new_list)}.")
                else:
                    # Just normalize the CIDRs adding /32 to IPv4 addresses and /128 to IPv6 addresses if they are not present
                    # Do not remove invalid CIDRs
                    # Example: 10.10.10.10 => 10.10.10.10/32
                    self._log_debug("Normalizing the list of IPs in CIDR format without removing invalid CIDRs.")
                    new_list = self.__normalize_cidr(new_list)
                self._log_debug(f"Removing invalid CIDRs from the list. Current size: {len(new_list)}")
                new_list = self.__discard_invalid_cidr(new_list)
                self._log_debug(f"After removing invalid CIDRs, the list size is {len(new_list)}.")
                if len(new_list) == 0:
                    self._log_debug("All CIDRs were discarded, clearing the lists.")
                    self.__clear_lists()
                    return False  # No valid CIDRs to process
                else:
                    new_list = sorted(list(filter(None, sorted(list(dict.fromkeys(new_list))))), key=lambda ip: self.ip_to_int(ip.split("/")[0]))
                    if kwargs.get("check_overlap", True):
                        new_list = self._remove_overlapping_cidrs(new_list)
                    self._log_debug(f"Discarded {len(self.last_discarted_ips)} invalid or overlapping CIDRs from the list ({self.last_discarted_ips})")
                  
                    chunk_size = len(new_list) if len(new_list) <= 100 else self.__find_balanced_chunk_size(len(new_list))
                    self._log_debug(f"Splitting the list into chunks of size {chunk_size} for better performance.")
                    try:
                        ip_temp_list = [self.__get_first_last_ip_cidr(item) for item in new_list]
                        with self._lock:
                            self.__list_chunks = self.__split_list(new_list, chunk_size)
                            self.__first_ip_chunks = self.__split_list([item[0] for item in ip_temp_list], chunk_size)
                            self.__last_ip_chunks = self.__split_list([item[1] for item in ip_temp_list], chunk_size)
                            self.__list_index = [item[0] for item in self.__first_ip_chunks]
                            self._cidrs = new_list.copy()
                        return True  # Successfully processed the list
                    except Exception as ERR:
                        self._log_debug(f"Failed to process the list into chunks: {str(ERR)}")
                        return False
                    finally:
                        ip_temp_list.clear()
                        new_list.clear()
        except Exception as ERR:
            self.clear_ip_networks_list() # Clear the list on error
            self._log_debug(f"Failed at NoLimitList.__process_list(): {str(ERR)}")
            return False
    def set_ip_networks_list(self, list_items: typing.List[str]):
        """Set a new networks list"""
        self.clear_ip_networks_list()
        self.__process_list(list_items)
    def get_ip_networks_list(self) -> typing.List[str]:
        """Get the current ip networks list"""
        return list(self._cidrs)  # returns a copy of the list
    def clear_ip_networks_list(self):
        """Clear the ip networks list"""
        self.__clear_lists(clear_discarded_cidr=True)
        self._log_debug("Cleared the ip networks list.")
    def test_is_valid_ip_network(self, ipaddr: str) -> str:
        """ Check if the provided IP address or CIDR is valid to be added into the ip list.
            Returns the CIDR (normalized with /32 or /128) if valid, otherwise returns False.
        """
        if not isinstance(ipaddr, str):
            raise TypeError("ipaddr must be a string (IPv4/IPv6 address or CIDR)")
        try:
            cidr = self._normalize_cidr_suffix(ipaddr.strip())
            if not self.is_valid_cidr(cidr):
                self._log_debug(f"Invalid CIDR: {cidr}")
                return False  # Invalid CIDR
            if cidr in self._cidrs:
                self._log_debug(f"CIDR {cidr} already exists in the list.")
                return False  # CIDR already exists in the list
            overlap_result = self._find_cidr_overlap(cidr)
            if overlap_result:
                self._log_debug(f"CIDR {cidr} overlaps with existing CIDRs ({overlap_result}) in the list.")
                return False  # CIDR overlaps with existing CIDRs
            return cidr
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.add_ip(): {str(ERR)}")
        return False
    def add_ip(self, ipaddr: str) -> bool:
        """Add an IPv4/IPv6 address or CIDR to ip list"""
        if not isinstance(ipaddr, str):
            raise TypeError("ipaddr must be a string (IPv4/IPv6 address or CIDR)")
        try:
            self.last_discarted_ips.clear()  # Clear the last discarded CIDR
            cidr = ipaddr.strip()
            if self.__normalize_invalid_cidr:
                cidr = self.get_valid_cidr(cidr, normalize=True)
                if not cidr:
                    self.last_discarted_ips.append(ipaddr.strip())
                    return False
            cidr = self.test_is_valid_ip_network(cidr)
            if not cidr:
                self.last_discarted_ips.append(ipaddr.strip())
                return False
            self._cidrs.append(cidr)
            self.__process_list(self._cidrs, check_overlap=False, last_discarted_ips=self.last_discarted_ips)  # Process the list without check overlaps because is not needed
            return True
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.add_ip(): {str(ERR)}")
        return False
    def add_ips(self, ipaddr_list: typing.List[str]) -> bool:
        """Add a list of IPv4/IPv6 addresses or CIDRs to ip list"""
        if not isinstance(ipaddr_list, list):
            raise TypeError("ipaddr_list must be a list of strings (IPv4/IPv6 addresses or valid CIDRs)")
        try:
            self.last_discarted_ips.clear()  # Clear the last discarded CIDR
            for ip in ipaddr_list:
                cidr = ip.strip()
                if self.__normalize_invalid_cidr:
                    cidr = self.get_valid_cidr(cidr, normalize=True)
                if not cidr:
                    self.last_discarted_ips.append(ip.strip())
                    continue
                cidr = self.test_is_valid_ip_network(cidr)
                if not cidr:
                    self.last_discarted_ips.append(ip.strip())
                else:
                    self._cidrs.append(cidr)
            self.__process_list(self._cidrs, check_overlap=True, last_discarted_ips=self.last_discarted_ips) # reprocess the list to check overlaps for the last time
            return True
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.add_ip_list(): {str(ERR)}")
        return False
    def remove_ip(self, ipaddr: str):
        """Remove an IPv4/IPv6 or a CIDR from ip list"""
        if not isinstance(ipaddr, str):
            raise TypeError("ipaddr must be a string (a valid IPv4/IPv6 address or valid CIDR)")
        if not self._cidrs:
            return False
        try:
            ip = self._normalize_cidr_suffix(ipaddr.strip())
            if ip and ip in self._cidrs:
                self._cidrs.remove(ip)
                self.__process_list(self._cidrs, check_overlap=False)  # Process the list without check overlaps because is not needed
                return True
            else:
                self._log_debug(f"IP address or CIDR {ip} not found in the list.")
                return False
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.remove_ip_network(): {str(ERR)}")
        return False
    def remove_ips(self, ipaddr_list: typing.List[str]):
        """Remove a list of IPv4/IPv6 addresses or CIDRs from ip list"""
        if not isinstance(ipaddr_list, list):
            raise TypeError("ipaddr_list must be a list of strings (IPv4/IPv6 addresses or valid CIDRs)")
        if not self._cidrs:
            return False
        try:
            for ip in ipaddr_list:
                ip = self._normalize_cidr_suffix(ip.strip())
                if ip and ip in self._cidrs:
                    self._cidrs.remove(ip)
                else:
                    self._log_debug(f"IP address or CIDR {ip} not found in the list.")
            self.__process_list(self._cidrs, check_overlap=False)  # Process the list to remove overlaps and sort it
            return True
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.remove_ip_network_list(): {str(ERR)}")
        return False
    def __call__(self, ipaddr: typing.Union[str, int]) -> typing.Union[str, bool]:
        """Check if an IP address is in the ip list. Returns (True,<CIDR>) the network CIDR if the IP is in the list,
        otherwise it returns (False, None). (Elapsed average time: 0.000002)
        """
        try:
            if not self._cidrs:
                return False, None
            if isinstance(ipaddr, int):
                iplong = ipaddr
            elif isinstance(ipaddr, str):
                if not self.is_valid_ipaddr(str(ipaddr).strip()):
                    self._log_debug(f"Invalid IP address: {ipaddr.strip()}")
                    return False, None
                iplong = self.ip_to_int(ipaddr.strip())
            if iplong is None or iplong <= 0:
                self._log_debug(f"Invalid IP address: {ipaddr.strip()}")
                return False, None
            match_root_index = bisect.bisect_right(self.__list_index, iplong) - 1
            match_list_index = bisect.bisect_right(self.__first_ip_chunks[match_root_index], iplong) - 1
            try:
                network = self.__list_chunks[match_root_index][match_list_index]
            except Exception:
                network = False
            inside_network = (iplong >= self.__first_ip_chunks[match_root_index][match_list_index]) and (iplong <= self.__last_ip_chunks[match_root_index][match_list_index])
            if network and inside_network:
                return True, network
            return False, None  # IP not found in the list
        except Exception as ERR:
            self._log_debug(f"Failed at NoLimitList.check_ipaddr({ipaddr.strip()}): {str(ERR)}")
            return False, None
    def check_ipaddr(self, ipaddr: str):
        """Check if an IP address is in the ip list. Returns (True,<CIDR>) the network CIDR if the IP is in the list,
        otherwise it returns (False, None). (Elapsed average time: 0.000002)
        """
        return self.__call__(ipaddr)
    def check_iplong(self, iplong: int):
        """Check if an IP address as integer is in the ip list. Returns (True,<CIDR>) the network CIDR if the IP is in the list,
        otherwise it returns (False, None). (Elapsed average time: 0.000002)
        """
        return self.__call__(iplong)


class FastRateLimiter():
    def __init__(self,rate_limit:int,per:int=1,block_time:int=0,no_limit_list:List[str]=[],with_stats:bool=False,cache_cleanup_interval:int=3,lru_cache_maxsize:int=512,debug:bool=False,normalize_invalid_cidr:bool=False):
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
            - normalize_invalid_cidr: If True, it normalizes the CIDRs (10.0.0.10/8 becomes 10.0.0.0/8).

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
        self.no_limit_list = NoLimitList(ip_networks_list=no_limit_list,debug=debug,normalize_invalid_cidr=normalize_invalid_cidr)
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
            return struct.unpack("!L",socket.inet_aton(str(ipaddr).strip()))[0]
        except Exception:
            try:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6,str(ipaddr).strip()),byteorder='big')
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
        except Exception as ERR:
            raise Exception(f"Invalid IP address '{ipaddr}': {str(ERR)}") from None
        try:
            start_time = time.monotonic()
            no_limit_result,no_limit_network = self.no_limit_list(iplong)
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
        