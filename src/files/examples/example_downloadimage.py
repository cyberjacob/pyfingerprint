#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PyFingerprint
Copyright (C) 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.

"""

import tempfile
from pyfingerprint.pyfingerprint import PyFingerprint


## Reads image and download it
##

## Tries to initialize the sensor
try:
    f = PyFingerprint('/dev/ttyUSB0', 57600, 0xFFFFFFFF, 0x00000000)

    if ( f.verify_password() == False):
        raise ValueError('The given fingerprint sensor password is wrong!')

except Exception as e:
    print('The fingerprint sensor could not be initialized!')
    print('Exception message: ' + str(e))
    exit(1)

## Gets some sensor information
print('Currently used templates: ' + str(f.get_template_count()) + '/' + str(f.get_storage_capacity()))

## Tries to read image and download it
try:
    print('Waiting for finger...')

    ## Wait that finger is read
    while (f.read_image() == False):
        pass

    print('Downloading image (this take a while)...')

    imageDestination =  tempfile.gettempdir() + '/fingerprint.bmp'
    f.download_image(imageDestination)

    print('The image was saved to "' + imageDestination + '".')

except Exception as e:
    print('Operation failed!')
    print('Exception message: ' + str(e))
    exit(1)
