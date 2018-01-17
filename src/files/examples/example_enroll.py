#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PyFingerprint
Copyright (C) 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.

"""

import time
from pyfingerprint.pyfingerprint import PyFingerprint


## Enrolls new finger
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

## Tries to enroll new finger
try:
    print('Waiting for finger...')

    ## Wait that finger is read
    while (f.read_image() == False):
        pass

    ## Converts read image to characteristics and stores it in charbuffer 1
    f.convert_image(0x01)

    ## Checks if finger is already enrolled
    result = f.search_template()
    positionNumber = result[0]

    if ( positionNumber >= 0 ):
        print('Template already exists at position #' + str(positionNumber))
        exit(0)

    print('Remove finger...')
    time.sleep(2)

    print('Waiting for same finger again...')

    ## Wait that finger is read again
    while (f.read_image() == False):
        pass

    ## Converts read image to characteristics and stores it in charbuffer 2
    f.convert_image(0x02)

    ## Compares the charbuffers
    if ( f.compare_characteristics() == 0):
        raise Exception('Fingers do not match')

    ## Creates a template
    f.create_template()

    ## Saves template at new position number
    positionNumber = f.store_template()
    print('Finger enrolled successfully!')
    print('New template position #' + str(positionNumber))

except Exception as e:
    print('Operation failed!')
    print('Exception message: ' + str(e))
    exit(1)
