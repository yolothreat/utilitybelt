import os
import time
import unittest

from utilitybelt import utilitybelt as ub


class TestUB(unittest.TestCase):

    def setUp(self):
        pass

    # isA Tests
    def test_is_IPv4Address(self):
        self.assertIsInstance(ub.is_IPv4Address("8.8.4.4"), bool)
        self.assertTrue(ub.is_IPv4Address("8.8.4.4"))
        self.assertTrue(ub.is_IPv4Address("127.0.0.1"))
        self.assertFalse(ub.is_IPv4Address("8.8.4"))
        self.assertFalse(ub.is_IPv4Address("google.com"))

    def test_is_IPv6Address(self):
        self.assertIsInstance(ub.is_IPv6Address("1:2:3:4:5:6:7:8"), bool)
        self.assertTrue(ub.is_IPv6Address("1:2:3:4:5:6:7:8"))
        self.assertTrue(ub.is_IPv6Address("::ffff:10.0.0.1"))
        self.assertTrue(ub.is_IPv6Address("::ffff:1.2.3.4"))
        self.assertTrue(ub.is_IPv6Address("::ffff:0.0.0.0"))
        self.assertTrue(ub.is_IPv6Address("1:2:3:4:5:6:77:88"))
        self.assertTrue(ub.is_IPv6Address("::ffff:255.255.255.255"))
        self.assertTrue(ub.is_IPv6Address("fe08::7:8"))
        self.assertTrue(ub.is_IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
        self.assertFalse(ub.is_IPv6Address("google.com"))
        self.assertFalse(ub.is_IPv6Address("8.8.4.4"))

    def test_is_url(self):
        self.assertIsInstance(ub.is_url("http://example.com"), bool)
        self.assertTrue(ub.is_url("http://example.com"))
        self.assertFalse(ub.is_url("example.com"))

    # Geolocation Tests
    def test_ip_to_geo(self):
        self.assertIsInstance(ub.ip_to_geo("192.30.252.130"), dict)
        self.assertEqual(ub.ip_to_geo("192.30.252.130")["city"], 'San Francisco')
        self.assertEqual(ub.ip_to_geo("192.30.252.130")["region_code"], 'CA')
        self.assertEqual(ub.ip_to_geo("192.30.252.130")["country_name"], 'United States')

    def test_domain_to_geo(self):
        self.assertIsInstance(ub.domain_to_geo("github.com"), dict)
        self.assertEqual(ub.domain_to_geo("github.com")["city"], 'San Francisco')
        self.assertEqual(ub.domain_to_geo("github.com")["region_code"], 'CA')
        self.assertEqual(ub.domain_to_geo("github.com")["country_name"], 'United States')

    def test_ip_to_geojson(self):
        self.assertIsInstance(ub.ip_to_geojson("192.30.252.130"), dict)

    def test_ips_to_geojson(self):
        self.assertIsInstance(ub.ips_to_geojson(["192.30.252.130", "74.125.236.169"]), dict)

    # Reverse DNS Tests
    def test_reverse_dns(self):
        self.assertIsInstance(ub.reverse_dns("192.30.252.130"), list)
        self.assertEqual(ub.reverse_dns("192.30.252.130"), ['github.com'])
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), ['google.com'])
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), 'github.com')
        self.assertNotEqual(ub.reverse_dns("192.30.252.130"), [])

    def test_reverse_dns_sna(self):
        self.assertIsInstance(ub.reverse_dns_sna("192.30.252.130"), list)
        self.assertEqual(ub.reverse_dns_sna("192.30.252.130"), ['github.com'])
        self.assertNotEqual(ub.reverse_dns_sna("192.30.252.130"), ['google.com'])
        self.assertNotEqual(ub.reverse_dns_sna("192.30.252.130"), 'github.com')
        self.assertNotEqual(ub.reverse_dns_sna("192.30.252.130"), [])
        self.assertIsNone(ub.reverse_dns_sna('192.0.0.50'))

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

    def test_is_reserved(self):
        self.assertIsInstance(ub.is_reserved("10.10.10.10"), bool)
        self.assertTrue(ub.is_reserved("0.0.1.1"))
        self.assertTrue(ub.is_reserved("10.100.100.100"))
        self.assertTrue(ub.is_reserved("100.90.200.200"))
        self.assertTrue(ub.is_reserved("127.50.50.1"))
        self.assertTrue(ub.is_reserved("169.254.13.37"))
        self.assertTrue(ub.is_reserved("172.16.10.10"))
        self.assertTrue(ub.is_reserved("192.0.0.50"))
        self.assertTrue(ub.is_reserved("192.0.2.50"))
        self.assertTrue(ub.is_reserved("192.88.99.50"))
        self.assertTrue(ub.is_reserved("192.168.50.50"))
        self.assertTrue(ub.is_reserved("198.18.50.50"))
        self.assertTrue(ub.is_reserved("198.51.100.50"))
        self.assertTrue(ub.is_reserved("203.0.113.50"))
        self.assertTrue(ub.is_reserved("224.50.50.50"))
        self.assertFalse(ub.is_reserved("3.0.0.0"))
        self.assertFalse(ub.is_reserved("8.8.4.4"))
        self.assertFalse(ub.is_reserved("192.30.252.131"))

    def test_is_hash(self):
        # all hashes of the empty string
        self.assertIsInstance(ub.is_hash("d41d8cd98f00b204e9800998ecf8427e"), bool)
        # MD5
        self.assertTrue(ub.is_hash("d41d8cd98f00b204e9800998ecf8427e"))
        # SHA1
        self.assertTrue(ub.is_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
        # SHA256
        self.assertTrue(ub.is_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        # SHA512
        self.assertTrue(ub.is_hash("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))
        # ssdeep
        self.assertTrue(ub.is_hash("96:EQOJvOl4ab3hhiNFXc4wwcweomr0cNJDBoqXjmAHKX8dEt001nfEhVIuX0dDcs:3mzpAsZpprbshfu3oujjdENdp21"))
        self.assertFalse(ub.is_hash("KilroyWasHere"))

    @unittest.skipUnless(os.getenv("VT_API"), "No VT_API set")
    def test_vt_ip_check(self):
        vt_api = os.environ["VT_API"]
        self.assertIsNone(ub.vt_ip_check('asdf', vt_api))
        vt_ip_data = ub.vt_ip_check("192.30.252.130", vt_api)
        self.assertIsInstance(vt_ip_data, dict)
        self.assertIn('detected_urls', vt_ip_data)
        self.assertIn('country', vt_ip_data)
        self.assertEqual(vt_ip_data['country'], 'US')
        self.assertIn('resolutions', vt_ip_data)
        is_gh = False
        for resolution in vt_ip_data['resolutions']:
            if resolution['hostname'] == "github.com":
                is_gh = True
        self.assertTrue(is_gh)
        time.sleep(15)  # VT rate limiting

    @unittest.skipUnless(os.getenv("VT_API"), "No VT_API set")
    def test_vt_name_check(self):
        vt_api = os.environ["VT_API"]
        self.assertIsNone(ub.vt_name_check('asdf', vt_api))
        vt_name_data = ub.vt_name_check("github.com", vt_api)
        self.assertIsInstance(vt_name_data, dict)
        self.assertIn('resolutions', vt_name_data)
        is_gh = False
        for resolution in vt_name_data['resolutions']:
            if resolution['ip_address'] == '192.30.252.130':
                is_gh = True
        self.assertTrue(is_gh)
        time.sleep(15)  # VT rate limiting

    @unittest.skipUnless(os.getenv("VT_API"), "No VT_API set")
    def test_vt_hash_check(self):
        vt_api = os.environ["VT_API"]
        self.assertIsNone(ub.vt_hash_check('asdf', vt_api))
        vt_hash_data = ub.vt_hash_check("fe03b4181707f1ea1f3c69dc0a9904181c6fce91", vt_api)
        self.assertIsInstance(vt_hash_data, dict)
        self.assertIn('resource', vt_hash_data)
        self.assertIn('positives', vt_hash_data)
        self.assertGreater(vt_hash_data['positives'], 0)
        time.sleep(15)  # VT rate limiting
        vt_hash_data = ub.vt_hash_check("d41d8cd98f00b204e9800998ecf8427e", vt_api)
        self.assertIn('positives', vt_hash_data)
        self.assertEqual(vt_hash_data['positives'], 0)
        time.sleep(15)  # VT rate limiting

    @unittest.skipUnless(os.getenv("VT_API"), "No VT_API set")
    def test_vt_rate_limiting(self):
        vt_api = os.environ["VT_API"]
        # Exceed 4x in 60 seconds
        data = ub.vt_hash_check("d41d8cd98f00b204e9800998ecf8427e", vt_api)
        self.assertIsInstance(data, dict)
        data = ub.vt_hash_check("d41d8cd98f00b204e9800998ecf8427e", vt_api)
        data = ub.vt_hash_check("d41d8cd98f00b204e9800998ecf8427e", vt_api)
        data = ub.vt_hash_check("d41d8cd98f00b204e9800998ecf8427e", vt_api)
        data = ub.vt_name_check("example.org", vt_api)
        self.assertIsNone(data)
        data = ub.vt_ip_check("192.30.252.130", vt_api)
        self.assertIsNone(data)
        data = ub.vt_hash_check("d41d8cd98f00b204e9800998ecf8427e", vt_api)
        self.assertIsNone(data)
        time.sleep(15)

    def test_ipinfo(self):
        self.assertIsNone(ub.ipinfo_ip_check('asdf'))
        data = ub.ipinfo_ip_check('8.8.8.8')
        self.assertEqual(data['city'], 'Mountain View')
        self.assertEqual(data['country'], 'US')
        self.assertEqual(data['org'], 'AS15169 Google Inc.')

    def test_ipvoid_check(self):
        self.assertIsNone(ub.ipvoid_check('asdf'))
        good_ip = '192.30.252.130'
        bad_ip = '178.217.187.39'  # tor exit node, not really "bad"
        self.assertIsNone(ub.ipvoid_check(good_ip))
        tor_data = ub.ipvoid_check(bad_ip)
        self.assertIsInstance(tor_data, dict)
        self.assertIn('ProjectHoneypot', tor_data)

    @unittest.skipUnless(os.getenv("URLVOID_API"), "No VT_API set")
    def test_urlvoid_check(self):
        urlvoid_api = os.environ["URLVOID_API"]
        self.assertIsNone(ub.urlvoid_check('asdf', urlvoid_api))
        com_data = ub.urlvoid_check('github.com', urlvoid_api)
        self.assertIsInstance(com_data, list)
        self.assertIn('SCUMWARE', com_data)
        io_data = ub.urlvoid_check('github.io', urlvoid_api)
        self.assertIsNone(io_data)

    def test_urlvoid_ip_check(self):
        self.assertIsNone(ub.urlvoid_ip_check('asdf'))
        self.assertIsNone(ub.urlvoid_ip_check('166.216.157.95'))
        data = ub.urlvoid_ip_check('8.8.8.8')
        self.assertIn('google-public-dns-a.google.com', data['other_names'])
        self.assertIn('androidbia.info', data['bad_names'])

    def test_dshield_ip_check(self):
        self.assertIsNone(ub.dshield_ip_check('asdf'))
        self.assertIsInstance(ub.dshield_ip_check('166.216.157.95'), dict)
        data = ub.dshield_ip_check('8.8.8.8')
        self.assertIn('google', data['ip']['asname'].lower())
