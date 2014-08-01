import GeoIP
import json
import re

gi = GeoIP.open("./data/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

def is_IPv4Address(ipv4address):
    ip_regex = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    if re.match(ip_regex, ipv4address):
        return True
    else:
        return False

def ip_to_geo(ipaddress):
    """Convert IP to Geographic Information"""

    gir = gi.record_by_addr(ipaddress)

    geo = {
        "city": gir["city"],
        "region": gir["region_name"],
        "country": gir["country_name"],
        "latitude": gir["latitude"],
        "longitude": gir["longitude"]
    }

    return geo

def domain_to_geo(domain):
    """Convert Domain to Geographic Information"""

    gir = gi.record_by_name(domain)

    geo = {
        "city": gir["city"],
        "region": gir["region_name"],
        "country": gir["country_name"],
        "latitude": gir["latitude"],
        "longitude": gir["longitude"]
    }

    return json.dumps(geo)

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

    return json.dumps(point)

def ips_to_geojson(ipaddresses):
    """Generate GeoJSON for given IP address"""

    features = []

    for ipaddress in ipaddresses:
        geo = ip_to_geo(ipaddress)

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

    return json.dumps(points)
