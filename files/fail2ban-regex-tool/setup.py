#!/usr/bin/env python

from setuptools import setup

setup(name='regexmaker',
      version='1.0',
      description='Make failregexes interactively',
      author='Joseph Atkins-Turkish',
      author_email='spacerat3004@gmail.com',
      packages=['regexmaker', 'regexmaker.lib', 'regexmaker.test'],
      entry_points = {
              'console_scripts': [
                  'failregexmaker=regexmaker.regex_maker:main',                  
              ],              
          },
      install_requires=["six"],
     )
