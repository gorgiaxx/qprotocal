from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='qprotocal',
      version=version,
      description="Android QQ protocal for Python",
      long_description="""\
A library that provides a Python interface to the Android QQ Protocal
That's all.""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='qq protocal',
      author='Gorgiaxx',
      author_email='gorgiaxx@gmail.com',
      url='http://blog.gorgiaxx.com',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
