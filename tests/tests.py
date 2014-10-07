import sys, os
import unittest

sys.path.insert(0, os.path.dirname(".."))

import utilitybelt as ub

class TestUB(unittest.TestCase):

    def setUp(self):
        pass

    ## isA Tests
    def test_is_IPv4Address(self):
        self.assertIsInstance(ub.is_IPv4Address("8.8.4.4"), bool)
        self.assertTrue(ub.is_IPv4Address("8.8.4.4"))
        self.assertTrue(ub.is_IPv4Address("127.0.0.1"))
        self.assertFalse(ub.is_IPv4Address("8.8.4"))
        self.assertFalse(ub.is_IPv4Address("google.com"))

    ## Geolocation Tests
    def test_ip_to_geo(self):
        self.assertIsInstance(ub.ip_to_geo("192.30.252.130"), dict)
        self.assertEqual(ub.ip_to_geo("192.30.252.130")["city"], 'San Francisco')
        self.assertEqual(ub.ip_to_geo("192.30.252.130")["region_name"], 'California')
        self.assertEqual(ub.ip_to_geo("192.30.252.130")["country_name"], 'United States')

    def test_domain_to_geo(self):
        pass

    def test_ip_to_geojson(self):
        self.assertIsInstance(ub.ip_to_geojson("192.30.252.130"), dict)

    def test_ips_to_geojson(self):
        self.assertIsInstance(ub.ips_to_geojson(["192.30.252.130", "74.125.236.169"]), dict)

    ## Reverse DNS Tests
    def test_reverse_dns(self):
        self.assertIsInstance(ub.reverse_dns("192.30.252.130"), list)
        self.assertEqual(ub.reverse_dns("192.30.252.130"), ['github.com'])
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), ['google.com'])
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), 'github.com')
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), [])

    def test_reverse_dns_sna(self):
        self.assertIsInstance(ub.reverse_dns("192.30.252.130"), list)
        self.assertEqual(ub.reverse_dns("192.30.252.130"), ['github.com'])
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), ['google.com'])
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), 'github.com')
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), [])

    def test_ip_to_long(self):
        self.assertIsInstance(ub.ip_to_long("192.30.252.130"), int)
        self.assertEqual(ub.ip_to_long("192.30.252.130"), 3223256194)

    def test_ip_between(self):
        self.assertIsInstance(ub.ip_between("192.30.252.130", "1.1.1.1", "255.255.255.255"), bool)
        self.assertTrue(ub.ip_between("192.30.252.130", "1.1.1.1", "255.255.255.255"))
        self.assertFalse(ub.ip_between("192.30.252.130", "1.1.1.1", "255.255.255"))

    def test_is_rfc1918(self):
        self.assertIsInstance(ub.is_rfc1918("10.10.10.10"), bool)
        self.assertTrue(ub.is_rfc1918("10.10.10.10"))
        self.assertTrue(ub.is_rfc1918("172.16.10.10"))
        self.assertTrue(ub.is_rfc1918("192.168.1.1"))
        self.assertFalse(ub.is_rfc1918("172.15.10.10"))
        self.assertFalse(ub.is_rfc1918("192.30.252.130"))

if __name__ == '__main__':
    unittest.main()
