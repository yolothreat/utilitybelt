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

import GeoIP
import json
import netaddr
import re
import requests
import socket
from PassiveTotal import PassiveTotal
from bs4 import BeautifulSoup

gi = GeoIP.open("./data/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

# Indicators
re_ipv4 = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I | re.S | re.M)
re_email = re.compile("\\b[A-Za-z0-9_.]+@[0-9a-z.-]+\\b", re.I | re.S | re.M)
re_domain = re.compile("([a-z0-9-_]+\\.){1,4}(com|aero|am|asia|au|az|biz|br|ca|cat|cc|ch|co|coop|cx|de|edu|fr|gov|hk|info|int|ir|jobs|jp|kr|kz|me|mil|mobi|museum|name|net|nl|nr|org|post|pre|ru|tel|tk|travel|tw|ua|uk|uz|ws|xxx)", re.I | re.S | re.M)
re_cve = re.compile("(CVE-(19|20)\\d{2}-\\d{4})", re.I | re.S | re.M)

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

# TODO: submit this upstream
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


def is_IPv4Address(ipv4address):
    """Returns true for valid IPv4 Addresses, false for invalid."""

    return re.match(re_ipv4, ipv4address)


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
    else:
        raise Exception("No PTR record for %s" % ipaddress)
        return ""


def reverse_dns(ipaddress):
    """Returns a list of the dns names that point to a given ipaddress"""

    name, alias, addresslist = socket.gethostbyaddr(ipaddress)
    return [str(name)]


# Checks VirusTotal for occurrences of an IP address
def vt_ip_check(ip, vt_api):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': ip, 'apikey': vt_api}
        response = requests.get(url, params=parameters)
        return response.json()
    except:
        return None


# Checks VirusTotal for occurrences of a domain name
def vt_name_check(domain, vt_api):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        parameters = {'domain': domain, 'apikey': vt_api}
        response = requests.get(url, params=parameters)
        return response.json()
    except:
        return None


# Checks Hurricane Electric for DNS information on an IP address
def he_ip_check(ip):
    if DEBUG:
        sys.stderr.write("Attempting HE retrieval for %s\n" % ip)
    url = 'http://bgp.he.net/ip/%s#_dns' % ip
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36'}
    response = requests.get(url, headers=headers)
    if response.text:
        # TODO: use BeautifulSoup
        pattern = re.compile('\/dns\/.+\".title\=\".+\"\>(.+)<\/a\>', re.IGNORECASE)
        hostnames = re.findall(pattern, response.text)
        return hostnames
    else:
        return None


# Checks Hurricane Electric for DNS information on an IP address
def he_name_check(domain):
    url = 'http://bgp.he.net/dns/%s#_whois' % domain
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36'}
    response = requests.get(url, headers=headers)
    if response.text:
        # TODO: use BeautifulSoup
        pattern = re.compile('\/dns\/.+\".title\=\".+\"\>(.+)<\/a\>', re.IGNORECASE)
        hostnames = re.findall(pattern, response.text)
        return hostnames
    else:
        return None


# Checks SANS ISC for attack data on an IP address
def isc_ip_check(ip):
    try:
        url = 'https://isc.sans.edu/api/ip/%s?json' % ip
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36'}
        response = requests.get(url, headers=headers)
        data = response.json()
        return {'count': data['count']['text'],
                'attacks': data['attacks']['text'],
                'mindate': data['mindate']['text'],
                'maxdate': data['maxdate']['text']}
    except:
        return None


# Checks Farsight passive DNS for information on an IP address
def pdns_ip_check(ip, dnsdb_api):
    pdns_results = []
    url = 'https://api.dnsdb.info/lookup/rdata/ip/%s?limit=50' % ip
    headers = {'Accept': 'application/json', 'X-Api-Key': dnsdb_api}

    if DEBUG:
        sys.stderr.write("Attempting pDNS retrieval for %s\n" % ip)
    response = requests.get(url, headers=headers)
    return response.json()


# Checks Farsight passive DNS for information on a name
def pdns_name_check(name, dnsdb_api):
    pdns_results = []
    url = 'https://api.dnsdb.info/lookup/rrset/name/%s?limit=50' % name
    headers = {'Accept': 'application/json', 'X-Api-Key': dnsdb_api}

    response = requests.get(url, headers=headers)
    return response.json()


# Checks ipinfo.io for basic WHOIS-type data on an IP address
def ipinfo_ip_check(ip):
    response = requests.get('http://ipinfo.io/%s/json' % ip)
    return response.json()


def ipvoid_check(ip):
    if not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
        return None

    return_dict = dict()
    url = 'http://ipvoid.com/scan/%s/' % ip
    response = requests.get(url)
    data = BeautifulSoup(response.text)
    if data.findAll('span', attrs={'class': 'label label-success'}):
        return None
    elif data.findAll('span', attrs={'class': 'label label-danger'}):
        for each in data.findAll('img', alt='Alert'):
            detect_site = each.parent.parent.td.text.lstrip()
            detect_url = each.parent.a['href']
            return_dict[detect_site] = detect_url
    else:
        return None

    if len(return_dict) == 0:
        return None
    return return_dict


def urlvoid_check(name):
    if not re.match('[\.a-zA-Z]', name):
        return None

    return_dict = dict()
    url = 'http://urlvoid.com/scan/%s/' % name
    response = requests.get(url)
    data = BeautifulSoup(response.text)
    if data.findAll('div', attrs={'class': 'bs-callout bs-callout-info'}):
        return None
    elif data.findAll('div', attrs={'class': 'bs-callout bs-callout-warning'}):
        for each in data.findAll('img', alt='Alert'):
            detect_site = each.parent.parent.td.text.lstrip()
            detect_url = each.parent.a['href']
            return_dict[detect_site] = detect_url

    if len(return_dict) == 0:
        return None
    return return_dict


def urlvoid_ip_check(ip):
    if not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
        return None

    return_dict = dict()
    url = 'http://urlvoid.com/ip/%s/' % ip
    response = requests.get(url)
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
    else:
        return None

    if len(return_dict) == 0:
        return None
    return return_dict


def pt_check(addr, pt_api):
    # TODO: Replace with is_ipv4() and is_dns()
    if is_ipv4address(addr) or is_dns(addr):
        pt = PassiveTotal(pt_api)
        results = pt.search(addr)
        if results['success']:
            return results['results']
    else:
        return None
