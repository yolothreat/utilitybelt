"""
 _   _ _   _ _ _ _          ______      _ _
| | | | | (_) (_) |         | ___ \    | | |
| | | | |_ _| |_| |_ _   _  | |_/ / ___| | |_
| | | | __| | | | __| | | | | ___ \/ _ \ | __|
| |_| | |_| | | | |_| |_| | | |_/ /  __/ | |_
 \___/ \__|_|_|_|\__|\__, | \____/ \___|_|\__|
                      __/ |
                     |___/

A library to make you a Python CND Batman
"""

import re
import socket

import pygeoip
import requests
from bs4 import BeautifulSoup
from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange

gi = pygeoip.GeoIP("data/GeoLiteCity.dat", pygeoip.MEMORY_CACHE)

# Indicators
re_ipv4 = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', re.I | re.S | re.M)
re_email = re.compile("\\b[A-Za-z0-9_.]+@[0-9a-z.-]+\\b", re.I | re.S | re.M)
re_fqdn = re.compile('(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', re.I | re.S | re.M)
re_cve = re.compile("(CVE-(19|20)\\d{2}-\\d{4,7})", re.I | re.S | re.M)
re_url = re.compile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", re.I | re.S | re.M)

# Hashes
re_md5 = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
re_sha1 = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
re_sha256 = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
re_sha512 = re.compile("\\b[a-f0-9]{128}\\b", re.I | re.S | re.M)
re_ssdeep = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)

# File Types
re_doc = '\W([\w-]+\.)(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt)'
re_web = '\W([\w-]+\.)(html|php|js)'
re_exe = '\W([\w-]+\.)(exe|dll|jar)'
re_zip = '\W([\w-]+\.)(zip|zipx|7z|rar|tar|gz)'
re_img = '\W([\w-]+\.)(jpeg|jpg|gif|png|tiff|bmp)'
re_flash = '\W([\w-]+\.)(flv|swf)'

whitelist = [{'net': IPNetwork('10.0.0.0/8'), 'org': 'Private per RFC 1918'},
             {'net': IPNetwork('172.16.0.0/12'), 'org': 'Private per RFC 1918'},
             {'net': IPNetwork('192.168.0.0/16'), 'org': 'Private per RFC 1918'},
             {'net': IPNetwork('0.0.0.0/8'), 'org': 'Invalid per RFC 1122'},
             {'net': IPNetwork('127.0.0.0/8'), 'org': 'Loopback per RFC 1122'},
             {'net': IPNetwork('169.254.0.0/16'), 'org': 'Link-local per RFC 3927'},
             {'net': IPNetwork('100.64.0.0/10'), 'org': 'Shared address space per RFC 6598'},
             {'net': IPNetwork('192.0.0.0/24'), 'org': 'IETF Protocol Assignments per RFC 6890'},
             {'net': IPNetwork('192.0.2.0/24'), 'org': 'Documentation and examples per RFC 6890'},
             {'net': IPNetwork('192.88.99.0/24'), 'org': 'IPv6 to IPv4 relay per RFC 3068'},
             {'net': IPNetwork('198.18.0.0/15'), 'org': 'Network benchmark tests per RFC 2544'},
             {'net': IPNetwork('198.51.100.0/24'), 'org': 'Documentation and examples per RFC 5737'},
             {'net': IPNetwork('203.0.113.0/24'), 'org': 'Documentation and examples per RFC 5737'},
             {'net': IPNetwork('224.0.0.0/4'), 'org': 'IP multicast per RFC 5771'},
             {'net': IPNetwork('240.0.0.0/4'), 'org': 'Reserved per RFC 1700'},
             {'net': IPNetwork('255.255.255.255/32'), 'org': 'Broadcast address per RFC 919'}]

useragent = 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0'


def ip_to_long(ip):
    """Convert an IPv4Address string to long"""
    return int(IPAddress(ip))


def ip_between(ip, start, finish):
    """Checks to see if IP is between start and finish"""

    if is_IPv4Address(ip) and is_IPv4Address(start) and is_IPv4Address(finish):
        return IPAddress(ip) in IPRange(start, finish)
    else:
        return False


def is_rfc1918(ip):
    if ip_between(ip, "10.0.0.0", "10.255.255.255"):
        return True
    elif ip_between(ip, "172.16.0.0", "172.31.255.255"):
        return True
    elif ip_between(ip, "192.168.0.0", "192.168.255.255"):
        return True
    else:
        return False


def is_reserved(ip):
    if ip_between(ip, "0.0.0.0", "0.255.255.255"):
        return True
    elif ip_between(ip, "10.0.0.0", "10.255.255.255"):
        return True
    elif ip_between(ip, "100.64.0.0", "100.127.255.255"):
        return True
    elif ip_between(ip, "127.0.0.0", "127.255.255.255"):
        return True
    elif ip_between(ip, "169.254.0.0", "169.254.255.255"):
        return True
    elif ip_between(ip, "172.16.0.0", "172.31.255.255"):
        return True
    elif ip_between(ip, "192.0.0.0", "192.0.0.255"):
        return True
    elif ip_between(ip, "192.0.2.0", "192.0.2.255"):
        return True
    elif ip_between(ip, "192.88.99.0", "192.88.99.255"):
        return True
    elif ip_between(ip, "192.168.0.0", "192.168.255.255"):
        return True
    elif ip_between(ip, "198.18.0.0", "198.19.255.255"):
        return True
    elif ip_between(ip, "198.51.100.0", "198.51.100.255"):
        return True
    elif ip_between(ip, "203.0.113.0", "203.0.113.255"):
        return True
    elif ip_between(ip, "224.0.0.0", "255.255.255.255"):
        return True
    else:
        return False


def is_IPv4Address(ipv4address):
    """Returns true for valid IPv4 Addresses, false for invalid."""

    # alternately: catch AddrConversionError from IPAddress(ipv4address).ipv4()
    return bool(re.match(re_ipv4, ipv4address))


def is_fqdn(address):
    """Returns true for valid DNS addresses, false for invalid."""

    return re.match(re_fqdn, address)


def is_url(url):
    """Returns true for valid URLs, false for invalid."""

    return bool(re.match(re_url, url))


def ip_to_geo(ipaddress):
    """Convert IP to Geographic Information"""

    return gi.record_by_addr(ipaddress)


def domain_to_geo(domain):
    """Convert Domain to Geographic Information"""

    return gi.record_by_name(domain)


def ip_to_geojson(ipaddress, name="Point"):
    """Generate GeoJSON for given IP address"""

    geo = ip_to_geo(ipaddress)

    point = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {
                    "name": name
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [
                        geo["longitude"],
                        geo["latitude"]
                    ]
                }
            }
        ]
    }

    return point


def ips_to_geojson(ipaddresses):
    """Generate GeoJSON for given IP address"""

    features = []

    for ipaddress in ipaddresses:
        geo = gi.record_by_addr(ipaddress)

        features.append({
            "type": "Feature",
            "properties": {
                "name": ipaddress
            },
            "geometry": {
                "type": "Point",
                "coordinates": [
                    geo["longitude"],
                    geo["latitude"]
                ]
            }
        })

    points = {
        "type": "FeatureCollection",
        "features": features
    }

    return points


def reverse_dns_sna(ipaddress):
    """Returns a list of the dns names that point to a given ipaddress using StatDNS API"""

    r = requests.get("http://api.statdns.com/x/%s" % ipaddress)

    if r.status_code == 200:
        names = []

        for item in r.json()['answer']:
            name = str(item['rdata']).strip(".")
            names.append(name)

        return names
    elif r.json()['code'] == 503:
        # NXDOMAIN - no PTR record
        return None


def reverse_dns(ipaddress):
    """Returns a list of the dns names that point to a given ipaddress"""

    name = socket.gethostbyaddr(ipaddress)[0]
    return [str(name)]


def vt_ip_check(ip, vt_api):
    """Checks VirusTotal for occurrences of an IP address"""
    if not is_IPv4Address(ip):
        return None

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': ip, 'apikey': vt_api}
    response = requests.get(url, params=parameters)
    return response.json()


def vt_name_check(domain, vt_api):
    """Checks VirusTotal for occurrences of a domain name"""
    if not is_fqdn(domain):
        return None

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': domain, 'apikey': vt_api}
    response = requests.get(url, params=parameters)
    return response.json()


def ipinfo_ip_check(ip):
    """Checks ipinfo.io for basic WHOIS-type data on an IP address"""
    if not is_IPv4Address(ip):
        return None

    response = requests.get('http://ipinfo.io/%s/json' % ip)
    return response.json()


def ipvoid_check(ip):
    """Checks IPVoid.com for info on an IP address"""
    if not is_IPv4Address(ip):
        return None

    return_dict = {}
    headers = {'User-Agent': useragent}
    url = 'http://ipvoid.com/scan/%s/' % ip
    response = requests.get(url, headers=headers)
    data = BeautifulSoup(response.text)
    if data.findAll('span', attrs={'class': 'label label-success'}):
        return None
    elif data.findAll('span', attrs={'class': 'label label-danger'}):
        for each in data.findAll('img', alt='Alert'):
            detect_site = each.parent.parent.td.text.lstrip()
            detect_url = each.parent.a['href']
            return_dict[detect_site] = detect_url

    return return_dict


def urlvoid_check(name):
    """Checks URLVoid.com for info on a domain"""
    if not is_fqdn(name):
        return None

    return_dict = {}
    headers = {'User-Agent': useragent}
    url = 'http://urlvoid.com/scan/%s/' % name
    response = requests.get(url, headers=headers)
    data = BeautifulSoup(response.text)
    if data.findAll('div', attrs={'class': 'bs-callout bs-callout-info'}):
        return None
    elif data.findAll('div', attrs={'class': 'bs-callout bs-callout-danger'}):
        for each in data.findAll('img', alt='Alert'):
            detect_site = each.parent.parent.td.text.lstrip()
            detect_url = each.parent.a['href']
            return_dict[detect_site] = detect_url

    return return_dict


def urlvoid_ip_check(ip):
    """Checks URLVoid.com for info on an IP address"""
    if not is_IPv4Address(ip):
        return None

    return_dict = {}
    headers = {'User-Agent': useragent}
    url = 'http://urlvoid.com/ip/%s/' % ip
    response = requests.get(url, headers=headers)
    data = BeautifulSoup(response.text)
    h1 = data.findAll('h1')[0].text
    if h1 == 'Report not found':
        return None
    elif re.match('^IP', h1):
        return_dict['bad_names'] = []
        return_dict['other_names'] = []
        for each in data.findAll('img', alt='Alert'):
            return_dict['bad_names'].append(each.parent.text.strip())
        for each in data.findAll('img', alt='Valid'):
            return_dict['other_names'].append(each.parent.text.strip())

    return return_dict


def dshield_ip_check(ip):
    """Checks dshield for info on an IP address"""
    if not is_IPv4Address(ip):
        return None

    headers = {'User-Agent': useragent}
    url = 'https://isc.sans.edu/api/ip/'
    response = requests.get('{0}{1}?json'.format(url, ip), headers=headers)
    return response.json()
