utilitybelt
===========

[![Stories in Ready](https://badge.waffle.io/yolothreat/utilitybelt.svg?label=ready&title=Ready)](http://waffle.io/yolothreat/utilitybelt)
[![Circle CI](https://circleci.com/gh/yolothreat/utilitybelt.svg?style=svg)](https://circleci.com/gh/yolothreat/utilitybelt)
[![Coverage Status](https://coveralls.io/repos/yolothreat/utilitybelt/badge.svg?branch=circleci)](https://coveralls.io/r/yolothreat/utilitybelt?branch=circleci)
[![Code Health](https://landscape.io/github/yolothreat/utilitybelt/master/landscape.svg?style=flat)](https://landscape.io/github/yolothreat/utilitybelt/master)

A Python library for being a CND Batman.

![Batmans Utility Belt](http://cdn.ttgtmedia.com/ITKE/uploads/blogs.dir/141/files/2010/04/batmans-utility-belt.jpg)

## Purpose
__Utilitybelt__ provides common functions needed when writing security tools.

- Reverse DNS
- Geolocation
- IP Range Calculators (Long, Between, is_RFC1918, etc)
- Common Regular Expressions

We aim to provide more and welcome [contributions](/CONTRIBUTING.md).

## Use

You can get UtilityBelt like a sane human being using pip:

```
$ pip install utilitybelt
```

From there add a simple:
`
```python
import utilibelt as ub

ub.is_reserved("1.1.1.1")
```

And away you go!

## Development

You want to add some features? Awesome! First off take a look at the [contributing guide](/CONTRIBUTING.md).

### Setup
You'll want to run ```script/bootstrap``` from time to time to update the GeoLiteCity database from [Maxmind](https://www.maxmind.com/en/home), although we have packaged a version with this. In Linux (Ubuntu), you may need to install ```libgeoip-dev```.

## Tests
Super simple. After you've run ```pip install -e .```, just use ```script/test``` to run the test suite.

---


This product includes GeoLite data created by MaxMind, available from [maxmind.com](http://www.maxmind.com).
