from setuptools import setup, find_packages


setup(
    name="utilitybelt",
    version="0.1",
    description="Utilities to make you a CND Batman",
    url="https://github.com/sroberts/utilitybelt",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['requests', 'GeoIP']
)
