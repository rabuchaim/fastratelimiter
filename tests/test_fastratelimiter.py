#!/usr/bin/env python3
import unittest, random, socket, struct, time
from fastratelimiter import FastRateLimiter

def int2ip(iplong):
    try:
        if iplong < 2**32:  # MAX IPv4
            return socket.inet_ntoa(struct.pack('>L',iplong))
        else:
            ip_bytes = iplong.to_bytes(16,byteorder='big')
            hextets = [f"{(ip_bytes[i] << 8 | ip_bytes[i+1]):04x}" for i in range(0,16,2)]
            return ':'.join(hextets)
    except Exception:
        return None
def ip2int(ipaddr):
    if ipaddr.find(":") < 0:
        return struct.unpack("!L",socket.inet_aton(ipaddr))[0]
    else:
        return int.from_bytes(socket.inet_pton(socket.AF_INET6,ipaddr),byteorder='big')
def randomipv4():
    return int2ip(random.randint(16777216,3758096383))        
def randomipv6():
    return ':'.join([f'{random.randint(0, 0xffff):04x}' for _ in range(8)])

class TestFastRateLimiter(unittest.TestCase):
    def test_01_100_hits_per_second_ipv4(self):
        rate_limiter.rate_limit = 100
        ipaddr_v4 = randomipv4()
        for I in range(101):
            result = rate_limiter(ipaddr_v4)
        self.assertTrue(result)
        self.assertIn(ipaddr_v4,rate_limiter.get_stats())
        
        rate_limiter.rate_limit = 1
        ipaddr_v4 = randomipv4()
        for I in range(2):
            result = rate_limiter(ipaddr_v4)
        self.assertTrue(result)
        self.assertIn(ipaddr_v4,rate_limiter.get_stats())

    def test_02_100_hits_per_second_ipv6(self):
        rate_limiter.rate_limit = 100
        ipaddr_v6 = randomipv6()
        for I in range(101):
            result = rate_limiter(ipaddr_v6)
        self.assertTrue(result)
        self.assertIn(ipaddr_v6,rate_limiter.get_stats())
        
        rate_limiter.rate_limit = 1
        ipaddr_v6 = randomipv6()
        for I in range(2):
            result = rate_limiter(ipaddr_v6)
        self.assertTrue(result)
        self.assertIn(ipaddr_v6,rate_limiter.get_stats())
        
    def test_03_advanced_ipv4(self):
        self.assertEqual(len(rate_limiter.get_stats()),4)
        rate_limiter.rate_limit = 5
        self.assertEqual(len(rate_limiter.get_stats()),4)
        rate_limiter.block_time = 2
        self.assertEqual(len(rate_limiter.get_stats()),0)
        ipaddr_v4 = randomipv4()
        for I in range(8):
            result = rate_limiter(ipaddr_v4)
        self.assertTrue(result)
        self.assertIn(ipaddr_v4,rate_limiter.get_blocked_ips())
        time.sleep(1.9)
        result = rate_limiter(ipaddr_v4)
        self.assertTrue(result)
        time.sleep(0.1)
        result = rate_limiter(ipaddr_v4)
        self.assertFalse(result)
        self.assertIn(ipaddr_v4,rate_limiter.get_stats())
        self.assertNotIn(ipaddr_v4,rate_limiter.get_blocked_ips())

    def test_04_advanced_ipv6(self):
        self.assertEqual(len(rate_limiter.get_stats()),1)
        rate_limiter.rate_limit = 5
        self.assertEqual(len(rate_limiter.get_stats()),1)
        rate_limiter.block_time = 2
        self.assertEqual(len(rate_limiter.get_stats()),0)
        ipaddr_v6 = randomipv6()
        for I in range(6):
            result = rate_limiter(ipaddr_v6)
        self.assertTrue(result)
        # fixed in 1.0.2 - For IPv6, returns the full expanded zero-padded form
        # cd70:cca0:a29a:0879:4099:4e5d:7a05:0b73 == cd70:cca0:a29a:879:4099:4e5d:7a05:b73 (is equal as IPv6 but is different as string)
        self.assertIn(ipaddr_v6,rate_limiter.get_blocked_ips())
        time.sleep(1.9)
        result = rate_limiter(ipaddr_v6)
        self.assertTrue(result)
        time.sleep(0.1)
        result = rate_limiter(ipaddr_v6)
        self.assertFalse(result)
        self.assertNotIn(ipaddr_v6,rate_limiter.get_blocked_ips())
        
    def test_05_advanced_per_change(self):
        rate_limiter.rate_limit = 5
        rate_limiter.block_time = 2
        rate_limiter.per = 4
        ipaddr_v4 = randomipv4()
        for I in range(6):
            result = rate_limiter(ipaddr_v4)
            time.sleep(0.4)
        self.assertTrue(result)
        self.assertIn(ipaddr_v4,rate_limiter.get_blocked_ips())
        time.sleep(2)
        result = rate_limiter(ipaddr_v4)
        self.assertFalse(result)
        self.assertIn(ipaddr_v4,rate_limiter.get_stats())
        self.assertNotIn(ipaddr_v4,rate_limiter.get_blocked_ips())

    def test_06_no_limit_list_add_ip(self):
        rate_limiter.no_limit_list.add_ip('1.2.3.4')
        self.assertIn('1.2.3.4/32',rate_limiter.no_limit_list)
        rate_limiter.no_limit_list.add_ip('1.2.3.0/24')
        self.assertNotIn('1.2.3.0/24',rate_limiter.no_limit_list)
        self.assertIn('1.2.3.0/24',rate_limiter.no_limit_list.last_discarted_ips)
        
    def test_07_no_limit_list_add_ips(self):
        rate_limiter.no_limit_list.add_ips(['1.1.1.1/24','10.10.10.10','10.0.0.0/8'])
        self.assertNotIn('1.1.1.1/24',rate_limiter.no_limit_list)
        self.assertNotIn('10.10.10.10/32',rate_limiter.no_limit_list)
        self.assertIn('10.0.0.0/8',rate_limiter.no_limit_list)
        self.assertIn('1.1.1.1/24',rate_limiter.no_limit_list.last_discarted_ips)
        self.assertIn('10.10.10.10/32',rate_limiter.no_limit_list.last_discarted_ips)
    
    def test_08_no_limit_list_remove_ip(self):
        rate_limiter.no_limit_list.remove_ip('1.2.3.4/32')
        self.assertNotIn('1.2.3.4/32',rate_limiter.no_limit_list)

    def test_09_no_limit_list_remove_ips(self):
        rate_limiter.no_limit_list.remove_ips(['10.10.10.10/32','10.0.0.0/8'])
        self.assertNotIn('10.10.10.10/32',rate_limiter.no_limit_list)
        self.assertNotIn('10.0.0.0/8',rate_limiter.no_limit_list)
        self.assertEqual(len(rate_limiter.no_limit_list),0)
        
    def test_10_no_limit_list_check_ipaddr(self):
        ipaddr_v4 = randomipv4()
        iplong_v4 = ip2int(ipaddr_v4)
        oct = ipaddr_v4.split('.')
        ipnetwork_v4 = f"{oct[0]}.{oct[1]}.{oct[2]}.0/24"
        rate_limiter.no_limit_list.add_ip(ipnetwork_v4)
        rate_limiter.no_limit_list.add_ip('1.2.3.4/32')
        rate_limiter.no_limit_list.add_ip('10.0.0.0/8')
        self.assertIn(ipnetwork_v4,rate_limiter.no_limit_list)
        self.assertIn('1.2.3.4/32',rate_limiter.no_limit_list)
        result,network = rate_limiter.no_limit_list.check_ipaddr('1.2.3.4')
        self.assertTrue(result)
        self.assertEqual(network,'1.2.3.4/32')
        result,network = rate_limiter.no_limit_list.check_ipaddr('10.10.10.10')
        self.assertTrue(result)
        self.assertEqual(network,'10.0.0.0/8')
        result,network = rate_limiter.no_limit_list.check_ipaddr(ipaddr_v4)
        self.assertTrue(result)
        self.assertEqual(network,ipnetwork_v4)
        result,network = rate_limiter.no_limit_list.check_iplong(iplong_v4)
        self.assertTrue(result)
        self.assertEqual(network,ipnetwork_v4)
        ipaddr_v6 = randomipv6()
        rate_limiter.no_limit_list.add_ip(ipaddr_v6)
        result,network = rate_limiter.no_limit_list.check_ipaddr(ipaddr_v6)
        self.assertTrue(result)
        self.assertEqual(network,ipaddr_v6+"/128")

if __name__ == '__main__':
    rate_limiter = FastRateLimiter(rate_limit=5,per=1,block_time=0,with_stats=True)
    unittest.main(verbosity=2)
