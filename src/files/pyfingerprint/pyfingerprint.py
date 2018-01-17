#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PyFingerprint
Copyright (C) 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.

"""

import os
import serial
from PIL import Image
import struct

## Baotou start byte
FINGERPRINT_STARTCODE = 0xEF01

## Packet identification
##

FINGERPRINT_COMMANDPACKET = 0x01

FINGERPRINT_ACKPACKET = 0x07
FINGERPRINT_DATAPACKET = 0x02
FINGERPRINT_ENDDATAPACKET = 0x08

## Instruction codes
##

FINGERPRINT_VERIFYPASSWORD = 0x13
FINGERPRINT_SETPASSWORD = 0x12
FINGERPRINT_SETADDRESS = 0x15
FINGERPRINT_SETSYSTEMPARAMETER = 0x0E
FINGERPRINT_GETSYSTEMPARAMETERS = 0x0F
FINGERPRINT_TEMPLATEINDEX = 0x1F
FINGERPRINT_TEMPLATECOUNT = 0x1D

FINGERPRINT_READIMAGE = 0x01

## Note: The documentation mean upload to host computer.
FINGERPRINT_DOWNLOADIMAGE = 0x0A

FINGERPRINT_CONVERTIMAGE = 0x02

FINGERPRINT_CREATETEMPLATE = 0x05
FINGERPRINT_STORETEMPLATE = 0x06
FINGERPRINT_SEARCHTEMPLATE = 0x04
FINGERPRINT_LOADTEMPLATE = 0x07
FINGERPRINT_DELETETEMPLATE = 0x0C

FINGERPRINT_CLEARDATABASE = 0x0D
FINGERPRINT_GENERATERANDOMNUMBER = 0x14
FINGERPRINT_COMPARECHARACTERISTICS = 0x03

## Note: The documentation mean download from host computer.
FINGERPRINT_UPLOADCHARACTERISTICS = 0x09

## Note: The documentation mean upload to host computer.
FINGERPRINT_DOWNLOADCHARACTERISTICS = 0x08

## Packet reply confirmations
##

FINGERPRINT_OK = 0x00
FINGERPRINT_ERROR_COMMUNICATION = 0x01

FINGERPRINT_ERROR_WRONGPASSWORD = 0x13

FINGERPRINT_ERROR_INVALIDREGISTER = 0x1A

FINGERPRINT_ERROR_NOFINGER = 0x02
FINGERPRINT_ERROR_READIMAGE = 0x03

FINGERPRINT_ERROR_MESSYIMAGE = 0x06
FINGERPRINT_ERROR_FEWFEATUREPOINTS = 0x07
FINGERPRINT_ERROR_INVALIDIMAGE = 0x15

FINGERPRINT_ERROR_CHARACTERISTICSMISMATCH = 0x0A

FINGERPRINT_ERROR_INVALIDPOSITION = 0x0B
FINGERPRINT_ERROR_FLASH = 0x18

FINGERPRINT_ERROR_NOTEMPLATEFOUND = 0x09

FINGERPRINT_ERROR_LOADTEMPLATE = 0x0C

FINGERPRINT_ERROR_DELETETEMPLATE = 0x10

FINGERPRINT_ERROR_CLEARDATABASE = 0x11

FINGERPRINT_ERROR_NOTMATCHING = 0x08

FINGERPRINT_ERROR_DOWNLOADIMAGE = 0x0F
FINGERPRINT_ERROR_DOWNLOADCHARACTERISTICS = 0x0D

## Unknown error codes
##

FINGERPRINT_ADDRCODE = 0x20
FINGERPRINT_PASSVERIFY = 0x21

FINGERPRINT_PACKETRESPONSEFAIL = 0x0E

FINGERPRINT_ERROR_TIMEOUT = 0xFF
FINGERPRINT_ERROR_BADPACKET = 0xFE


def _right_shift(n, x):
    """
    Shift a byte.

    @param integer n
    @param integer x
    @return integer
    """

    return n >> x & 0xFF


def _left_shift(n, x):
    """
    Shift a byte.

    @param integer n
    @param integer x
    @return integer
    """

    return n << x


def _bit_at_position(n, p):
    """
    Get the bit of n at position p.

    @param integer n
    @param integer p
    @return integer
    """

    ## A bitshift 2 ^ p
    two_p = 1 << p

    ## Binary AND composition (on both positions must be a 1)
    ## This can only happen at position p
    result = n & two_p
    return int(result > 0)


def _byte_to_string(byte):
    """
    Converts a byte to string.

    @param byte byte
    @return string
    """

    return struct.pack('@B', byte)


def _string_to_byte(string):
    """
    Convert one "string" byte (like '0xFF') to real integer byte (0xFF).

    @param string string
    @return byte
    """

    return struct.unpack('@B', string)[0]


class PyFingerprint(object):
    """
    A python written library for the ZhianTec ZFM-20 fingerprint sensor.

    @attribute integer(4 bytes) __address
    Address to connect to sensor.

    @attribute integer(4 bytes) __password
    Password to connect to sensor.

    @attribute Serial __serial
    UART serial connection via PySerial.
    """
    __address = None
    __password = None
    __serial = None

    def __init__(self, port='/dev/ttyUSB0', baud_rate=57600, address=0xFFFFFFFF, password=0x00000000):
        """
        Constructor

        @param string port
        @param integer baudRate
        @param integer(4 bytes) address
        @param integer(4 bytes) password
        """

        if not os.path.exists(port):
            raise ValueError('The fingerprint sensor port "' + port + '" was not found!')

        if baud_rate < 9600 or baud_rate > 115200 or baud_rate % 9600 != 0:
            raise ValueError('The given baudrate is invalid!')

        if address < 0x00000000 or address > 0xFFFFFFFF:
            raise ValueError('The given address is invalid!')

        if password < 0x00000000 or password > 0xFFFFFFFF:
            raise ValueError('The given password is invalid!')

        self.__address = address
        self.__password = password

        ## Initialize PySerial connection
        self.__serial = serial.Serial(port=port, baudrate=baud_rate, bytesize=serial.EIGHTBITS, timeout=2)

        if self.__serial.isOpen():
            self.__serial.close()

        self.__serial.open()

    def __del__(self):
        """
        Destructor

        """

        ## Close connection if still established
        if self.__serial is not None and self.__serial.isOpen():
            self.__serial.close()

    def _write_packet(self, packet_type, packet_payload):
        """
        Send a packet to fingerprint sensor.

        @param integer(1 byte) packet_type
        @param tuple packet_payload

        @return void
        """

        ## Write header (one byte at once)
        self.__serial.write(_byte_to_string(_right_shift(FINGERPRINT_STARTCODE, 8)))
        self.__serial.write(_byte_to_string(_right_shift(FINGERPRINT_STARTCODE, 0)))

        self.__serial.write(_byte_to_string(_right_shift(self.__address, 24)))
        self.__serial.write(_byte_to_string(_right_shift(self.__address, 16)))
        self.__serial.write(_byte_to_string(_right_shift(self.__address, 8)))
        self.__serial.write(_byte_to_string(_right_shift(self.__address, 0)))

        self.__serial.write(_byte_to_string(packet_type))

        ## The packet length = package payload (n bytes) + checksum (2 bytes)
        packet_length = len(packet_payload) + 2

        self.__serial.write(_byte_to_string(_right_shift(packet_length, 8)))
        self.__serial.write(_byte_to_string(_right_shift(packet_length, 0)))

        ## The packet checksum = packet type (1 byte) + packet length (2 bytes) + payload (n bytes)
        packet_checksum = packet_type + _right_shift(packet_length, 8) + _right_shift(packet_length, 0)

        ## Write payload
        for i in range(0, len(packet_payload)):
            self.__serial.write(_byte_to_string(packet_payload[i]))
            packet_checksum += packet_payload[i]

        ## Write checksum (2 bytes)
        self.__serial.write(_byte_to_string(_right_shift(packet_checksum, 8)))
        self.__serial.write(_byte_to_string(_right_shift(packet_checksum, 0)))

    def _read_packet(self):
        """
        Receive a packet from fingerprint sensor.

        Return a tuple that contain the following information:
        0: integer(1 byte) The packet type.
        1: integer(n bytes) The packet payload.

        @return tuple
        """

        received_packet_data = []
        i = 0

        while True:
            ## Read one byte
            received_fragment = self.__serial.read()

            if len(received_fragment) != 0:
                received_fragment = _string_to_byte(received_fragment)
                ## print 'Received packet fragment = ' + hex(received_fragment)

            ## Insert byte if packet seems valid
            received_packet_data.insert(i, received_fragment)
            i += 1

            ## Packet could be complete (the minimal packet size is 12 bytes)
            if i >= 12:

                ## Check the packet header
                if received_packet_data[0] != _right_shift(FINGERPRINT_STARTCODE, 8) or received_packet_data[1] != _right_shift(FINGERPRINT_STARTCODE, 0):
                    raise Exception('The received packet do not begin with a valid header!')

                ## Calculate packet payload length (combine the 2 length bytes)
                packet_payload_length = _left_shift(received_packet_data[7], 8)
                packet_payload_length = packet_payload_length | _left_shift(received_packet_data[8], 0)

                ## Check if the packet is still fully received
                ## Condition: index counter < packet payload length + packet frame
                if i < packet_payload_length + 9:
                    continue

                ## At this point the packet should be fully received

                packet_type = received_packet_data[6]

                ## Calculate checksum:
                ## checksum = packet type (1 byte) + packet length (2 bytes) + packet payload (n bytes)
                packet_checksum = packet_type + received_packet_data[7] + received_packet_data[8]

                packet_payload = []

                ## Collect package payload (ignore the last 2 checksum bytes)
                for j in range(9, 9 + packet_payload_length - 2):
                    packet_payload.append(received_packet_data[j])
                    packet_checksum += received_packet_data[j]

                ## Calculate full checksum of the 2 separate checksum bytes
                received_checksum = _left_shift(received_packet_data[i - 2], 8)
                received_checksum = received_checksum | _left_shift(received_packet_data[i - 1], 0)

                if received_checksum != packet_checksum:
                    raise Exception('The received packet is corrupted (the checksum is wrong)!')

                return packet_type, packet_payload

    def verify_password(self):
        """
        Verify password of the fingerprint sensor.

        @return boolean
        """

        packet_payload = (
            FINGERPRINT_VERIFYPASSWORD,
            _right_shift(self.__password, 24),
            _right_shift(self.__password, 16),
            _right_shift(self.__password, 8),
            _right_shift(self.__password, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Sensor password is correct
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ADDRCODE:
            raise Exception('The address is wrong')

        ## DEBUG: Sensor password is wrong
        elif received_packet_payload[0] == FINGERPRINT_ERROR_WRONGPASSWORD:
            return False

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def set_password(self, new_password):
        """
        Set the password of the sensor.

        @param integer(4 bytes) newPassword
        @return boolean
        """

        ## Validate the password (maximum 4 bytes)
        if new_password < 0x00000000 or new_password > 0xFFFFFFFF:
            raise ValueError('The given password is invalid!')

        packet_payload = (
            FINGERPRINT_SETPASSWORD,
            _right_shift(new_password, 24),
            _right_shift(new_password, 16),
            _right_shift(new_password, 8),
            _right_shift(new_password, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Password set was successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            self.__password = new_password
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def set_address(self, new_address):
        """
        Set the module address of the sensor.

        @param integer(4 bytes) new_address
        @return boolean
        """

        ## Validate the address (maximum 4 bytes)
        if new_address < 0x00000000 or new_address > 0xFFFFFFFF:
            raise ValueError('The given address is invalid!')

        packet_payload = (
            FINGERPRINT_SETADDRESS,
            _right_shift(new_address, 24),
            _right_shift(new_address, 16),
            _right_shift(new_address, 8),
            _right_shift(new_address, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Address set was successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            self.__address = new_address
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def set_system_parameter(self, parameter_number, parameter_value):
        """
        Set a system parameter of the sensor.

        @param integer(1 byte) parameter_number
        @param integer(1 byte) parameter_value
        @return boolean
        """

        ## Validate the baudrate parameter
        if parameter_number == 4:

            if parameter_value < 1 or parameter_value > 12:
                raise ValueError('The given baudrate parameter is invalid!')

        ## Validate the security level parameter
        elif parameter_number == 5:

            if parameter_value < 1 or parameter_value > 5:
                raise ValueError('The given security level parameter is invalid!')

        ## Validate the package length parameter
        elif parameter_number == 6:

            if parameter_value < 0 or parameter_value > 3:
                raise ValueError('The given package length parameter is invalid!')

        ## The parameter number is not valid
        else:
            raise ValueError('The given parameter number is invalid!')

        packet_payload = (
            FINGERPRINT_SETSYSTEMPARAMETER,
            parameter_number,
            parameter_value,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Parameter set was successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_INVALIDREGISTER:
            raise Exception('Invalid register number')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def get_system_parameters(self):
        """
        Get all available system information of the sensor.

        Return a tuple that contain the following information:
        0: integer(2 bytes) The status register.
        1: integer(2 bytes) The system id.
        2: integer(2 bytes) The storage capacity.
        3: integer(2 bytes) The security level.
        4: integer(4 bytes) The sensor address.
        5: integer(2 bytes) The packet length.
        6: integer(2 bytes) The baudrate.

        @return tuple
        """

        packet_payload = (
            FINGERPRINT_GETSYSTEMPARAMETERS,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Read successfully
        if received_packet_payload[0] == FINGERPRINT_OK:

            status_register = _left_shift(received_packet_payload[1], 8) | _left_shift(received_packet_payload[2], 0)
            system_id = _left_shift(received_packet_payload[3], 8) | _left_shift(received_packet_payload[4], 0)
            storage_capacity = _left_shift(received_packet_payload[5], 8) | _left_shift(received_packet_payload[6], 0)
            security_level = _left_shift(received_packet_payload[7], 8) | _left_shift(received_packet_payload[8], 0)
            device_address = ((received_packet_payload[9] << 8 | received_packet_payload[10]) << 8 | received_packet_payload[11]) << 8 | received_packet_payload[12]  ## TODO
            packet_length = _left_shift(received_packet_payload[13], 8) | _left_shift(received_packet_payload[14], 0)
            baud_rate = _left_shift(received_packet_payload[15], 8) | _left_shift(received_packet_payload[16], 0)

            return status_register, system_id, storage_capacity, security_level, device_address, packet_length, baud_rate

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def get_template_index(self, page):
        """
        Get a list of the template positions with usage indicator.

        @param integer(1 byte) page
        @return list
        """

        if page < 0 or page > 3:
            raise ValueError('The given index page is invalid!')

        packet_payload = (
            FINGERPRINT_TEMPLATEINDEX,
            page,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Read index table successfully
        if received_packet_payload[0] == FINGERPRINT_OK:

            template_index = []

            ## Contain the table page bytes (skip the first status byte)
            page_elements = received_packet_payload[1:]

            for page_element in page_elements:
                ## Test every bit (bit = template position is used indicator) of a table page element
                for p in range(0, 7 + 1):
                    position_is_used = (_bit_at_position(page_element, p) == 1)
                    template_index.append(position_is_used)

            return template_index

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def get_template_count(self):
        """
        Get the number of stored templates.

        @return integer(2 bytes)
        """

        packet_payload = (
            FINGERPRINT_TEMPLATECOUNT,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Read successfully
        if received_packet_payload[0] == FINGERPRINT_OK:
            template_count = _left_shift(received_packet_payload[1], 8)
            template_count = template_count | _left_shift(received_packet_payload[2], 0)
            return template_count

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def read_image(self):
        """
        Read the image of a finger and stores it in ImageBuffer.

        @return boolean
        """

        packet_payload = (
            FINGERPRINT_READIMAGE,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Image read successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: No finger found
        elif received_packet_payload[0] == FINGERPRINT_ERROR_NOFINGER:
            return False

        elif received_packet_payload[0] == FINGERPRINT_ERROR_READIMAGE:
            raise Exception('Could not read image')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    ## TODO:
    ## Implementation of uploadImage()

    def download_image(self, image_destination):
        """
        Download the image of a finger to host computer.

        @param string image_destination
        @return void
        """

        destination_directory = os.path.dirname(image_destination)

        if os.access(destination_directory, os.W_OK) == False:
            raise ValueError('The given destination directory "' + destination_directory + '" is not writable!')

        packet_payload = (
            FINGERPRINT_DOWNLOADIMAGE,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)

        ## Get first reply packet
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: The sensor will sent follow-up packets
        if received_packet_payload[0] == FINGERPRINT_OK:
            pass

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_DOWNLOADIMAGE:
            raise Exception('Could not download image')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

        ## Initialize image library
        result_image = Image.new('L', (256, 288), 'white')
        pixels = result_image.load()

        ## Y coordinate of current pixel
        line = 0

        ## Get follow-up data packets until the last data packet is received
        while received_packet_type != FINGERPRINT_ENDDATAPACKET:

            received_packet = self._read_packet()

            received_packet_type = received_packet[0]
            received_packet_payload = received_packet[1]

            if received_packet_type != FINGERPRINT_DATAPACKET and received_packet_type != FINGERPRINT_ENDDATAPACKET:
                raise Exception('The received packet is no data packet!')

            ## X coordinate of current pixel
            x = 0

            for i in range(0, len(received_packet_payload)):

                ## Thanks to Danylo Esterman <soundcracker@gmail.com> for the "multiple with 17" improvement:

                ## Draw left 4 Bits one byte of package
                pixels[x, line] = (received_packet_payload[i] >> 4) * 17
                x = x + 1

                ## Draw right 4 Bits one byte of package
                pixels[x, line] = (received_packet_payload[i] & 0b00001111) * 17
                x = x + 1

            line = line + 1

        result_image.save(image_destination)

    def convert_image(self, char_buffer_number=0x01):
        """
        Convert the image in ImageBuffer to finger characteristics and store in CharBuffer1 or CharBuffer2.

        @param integer(1 byte) char_buffer_number
        @return boolean
        """

        if char_buffer_number != 0x01 and char_buffer_number != 0x02:
            raise ValueError('The given charbuffer number is invalid!')

        packet_payload = (
            FINGERPRINT_CONVERTIMAGE,
            char_buffer_number,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Image converted
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_MESSYIMAGE:
            raise Exception('The image is too messy')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_FEWFEATUREPOINTS:
            raise Exception('The image contains too few feature points')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_INVALIDIMAGE:
            raise Exception('The image is invalid')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def create_template(self):
        """
        Combine the characteristics which are stored in CharBuffer1 and CharBuffer2 to a template.
        The created template will be stored again in CharBuffer1 and CharBuffer2 as the same.

        @return boolean
        """

        packet_payload = (
            FINGERPRINT_CREATETEMPLATE,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template created successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: The characteristics not matching
        elif received_packet_payload[0] == FINGERPRINT_ERROR_CHARACTERISTICSMISMATCH:
            return False

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def store_template(self, position_number=-1, char_buffer_number=0x01):
        """
        Save a template from the specified CharBuffer to the given position number.

        @param integer(2 bytes) position_number
        @param integer(1 byte) char_buffer_number
        @return integer
        """

        ## Find a free index
        if position_number == -1:
            for page in range(0, 4):
                ## Free index found?
                if position_number >= 0:
                    break

                template_index = self.get_template_index(page)

                for i in range(0, len(template_index)):
                    ## Index not used?
                    if not template_index[i]:
                        position_number = (len(template_index) * page) + i
                        break

        if position_number < 0x0000 or position_number >= self.get_storage_capacity():
            raise ValueError('The given position number is invalid!')

        if char_buffer_number != 0x01 and char_buffer_number != 0x02:
            raise ValueError('The given charbuffer number is invalid!')

        packet_payload = (
            FINGERPRINT_STORETEMPLATE,
            char_buffer_number,
            _right_shift(position_number, 8),
            _right_shift(position_number, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template stored successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return position_number

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_INVALIDPOSITION:
            raise Exception('Could not store template in that position')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_FLASH:
            raise Exception('Error writing to flash')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def search_template(self):
        """
        Search the finger characteristics in CharBuffer in database.

        Return a tuple that contain the following information:
        0: integer(2 bytes) The position number of found template.
        1: integer(2 bytes) The accuracy score of found template.

        @return tuple
        """

        ## CharBuffer1 and CharBuffer2 are the same in this case
        char_buffer_number = 0x01

        ## Begin search at index 0
        position_start = 0x0000
        templates_count = self.get_storage_capacity()

        packet_payload = (
            FINGERPRINT_SEARCHTEMPLATE,
            char_buffer_number,
            _right_shift(position_start, 8),
            _right_shift(position_start, 0),
            _right_shift(templates_count, 8),
            _right_shift(templates_count, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Found template
        if received_packet_payload[0] == FINGERPRINT_OK:

            position_number = _left_shift(received_packet_payload[1], 8)
            position_number = position_number | _left_shift(received_packet_payload[2], 0)

            accuracy_score = _left_shift(received_packet_payload[3], 8)
            accuracy_score = accuracy_score | _left_shift(received_packet_payload[4], 0)

            return position_number, accuracy_score

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: Did not found a matching template
        elif received_packet_payload[0] == FINGERPRINT_ERROR_NOTEMPLATEFOUND:
            return -1, -1

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def load_template(self, position_number, char_buffer_number=0x01):
        """
        Load an existing template specified by position number to specified CharBuffer.

        @param integer(2 bytes) position_number
        @param integer(1 byte) char_buffer_number
        @return boolean
        """

        if position_number < 0x0000 or position_number >= self.get_storage_capacity():
            raise ValueError('The given position number is invalid!')

        if char_buffer_number != 0x01 and char_buffer_number != 0x02:
            raise ValueError('The given charbuffer number is invalid!')

        packet_payload = (
            FINGERPRINT_LOADTEMPLATE,
            char_buffer_number,
            _right_shift(position_number, 8),
            _right_shift(position_number, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template loaded successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_LOADTEMPLATE:
            raise Exception('The template could not be read')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_INVALIDPOSITION:
            raise Exception('Could not load template from that position')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def delete_template(self, position_number, count=1):
        """
        Delete templates from fingerprint database. Per default one.

        @param integer(2 bytes) position_number
        @param integer(2 bytes) count
        @return boolean
        """

        capacity = self.get_storage_capacity()

        if position_number < 0x0000 or position_number >= capacity:
            raise ValueError('The given position number is invalid!')

        if count < 0x0000 or count > capacity - position_number:
            raise ValueError('The given count is invalid!')

        packet_payload = (
            FINGERPRINT_DELETETEMPLATE,
            _right_shift(position_number, 8),
            _right_shift(position_number, 0),
            _right_shift(count, 8),
            _right_shift(count, 0),
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template deleted successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_INVALIDPOSITION:
            raise Exception('Invalid position')

        ## DEBUG: Could not delete template
        elif received_packet_payload[0] == FINGERPRINT_ERROR_DELETETEMPLATE:
            return False

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def clear_database(self):
        """
        Clear the complete template database.

        @return boolean
        """

        packet_payload = (
            FINGERPRINT_CLEARDATABASE,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Database cleared successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            return True

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: Could not clear database
        elif received_packet_payload[0] == FINGERPRINT_ERROR_CLEARDATABASE:
            return False

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def compare_characteristics(self):
        """
        Compare the finger characteristics of CharBuffer1 with CharBuffer2 and return the accuracy score.

        @return integer(2 bytes)
        """

        packet_payload = (
            FINGERPRINT_COMPARECHARACTERISTICS,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Comparison successful
        if received_packet_payload[0] == FINGERPRINT_OK:
            accuracy_score = _left_shift(received_packet_payload[1], 8)
            accuracy_score = accuracy_score | _left_shift(received_packet_payload[2], 0)
            return accuracy_score

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: The characteristics do not matching
        elif received_packet_payload[0] == FINGERPRINT_ERROR_NOTMATCHING:
            return 0

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

    def upload_characteristics(self, char_buffer_number=0x01, characteristics_data=None):
        """
        Upload finger characteristics to CharBuffer1 or CharBuffer2.

        @author: David Gilson <davgilson@live.fr>

        @param integer(1 byte) char_buffer_number
        @param integer(list) characteristics_data

        @return boolean
        Return true if everything is right.
        """

        if characteristics_data is None:
            characteristics_data = [0]
        if char_buffer_number != 0x01 and char_buffer_number != 0x02:
            raise ValueError('The given charbuffer number is invalid!')

        if characteristics_data == [0]:
            raise ValueError('The characteristics data is required!')

        max_packet_size = self.get_max_packet_size()

        ## Upload command

        packet_payload = (
            FINGERPRINT_UPLOADCHARACTERISTICS,
            char_buffer_number
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)

        ## Get first reply packet
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: The sensor will sent follow-up packets
        if received_packet_payload[0] == FINGERPRINT_OK:
            pass

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_PACKETRESPONSEFAIL:
            raise Exception('Could not upload characteristics')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

        ## Upload data packets
        packet_number = len(characteristics_data) / max_packet_size

        if packet_number <= 1:
            self._write_packet(FINGERPRINT_ENDDATAPACKET, characteristics_data)
        else:
            i = 1
            while i < packet_number:
                lfrom = (i - 1) * max_packet_size
                lto = lfrom + max_packet_size
                self._write_packet(FINGERPRINT_DATAPACKET, characteristics_data[lfrom:lto])
                i += 1

            lfrom = (i - 1) * max_packet_size
            lto = lfrom + max_packet_size
            self._write_packet(FINGERPRINT_ENDDATAPACKET, characteristics_data[lfrom:lto])

        ## Verify uploaded characteristics
        characterics = self.download_characteristics(char_buffer_number)
        return characterics == characteristics_data

    def get_max_packet_size(self):
        """
        Get the maximum allowed size of packet by sensor.

        @author: David Gilson <davgilson@live.fr>

        @return int
        Return the max size. Default 32 bytes.
        """

        packet_max_size_type = self.get_system_parameters()[5]

        if packet_max_size_type == 1:
            return 64
        elif packet_max_size_type == 2:
            return 128
        elif packet_max_size_type == 3:
            return 256
        else:
            return 32

    def get_storage_capacity(self):
        """
        Get the sensor storage capacity.

        @return int
        The storage capacity.
        """

        return self.get_system_parameters()[2]

    def generate_random_number(self):
        """
        Generate a random 32-bit decimal number.

        @author: Philipp Meisberger <team@pm-codeworks.de>

        @return int
        The generated random number
        """
        packet_payload = (
            FINGERPRINT_GENERATERANDOMNUMBER,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        if received_packet_payload[0] == FINGERPRINT_OK:
            pass

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

        number = 0
        number = number | _left_shift(received_packet_payload[1], 24)
        number = number | _left_shift(received_packet_payload[2], 16)
        number = number | _left_shift(received_packet_payload[3], 8)
        number = number | _left_shift(received_packet_payload[4], 0)
        return number

    def download_characteristics(self, char_buffer_number=0x01):
        """
        Download the finger characteristics of CharBuffer1 or CharBuffer2.

        @param integer(1 byte) char_buffer_number

        @return list
        Return a list that contains 512 integer(1 byte) elements of the characteristic.
        """

        if char_buffer_number != 0x01 and char_buffer_number != 0x02:
            raise ValueError('The given charbuffer number is invalid!')

        packet_payload = (
            FINGERPRINT_DOWNLOADCHARACTERISTICS,
            char_buffer_number,
        )

        self._write_packet(FINGERPRINT_COMMANDPACKET, packet_payload)

        ## Get first reply packet
        received_packet = self._read_packet()

        received_packet_type = received_packet[0]
        received_packet_payload = received_packet[1]

        if received_packet_type != FINGERPRINT_ACKPACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: The sensor will sent follow-up packets
        if received_packet_payload[0] == FINGERPRINT_OK:
            pass

        elif received_packet_payload[0] == FINGERPRINT_ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif received_packet_payload[0] == FINGERPRINT_ERROR_DOWNLOADCHARACTERISTICS:
            raise Exception('Could not download characteristics')

        else:
            raise Exception('Unknown error ' + hex(received_packet_payload[0]))

        complete_payload = []

        ## Get follow-up data packets until the last data packet is received
        while received_packet_type != FINGERPRINT_ENDDATAPACKET:

            received_packet = self._read_packet()

            received_packet_type = received_packet[0]
            received_packet_payload = received_packet[1]

            if received_packet_type != FINGERPRINT_DATAPACKET and received_packet_type != FINGERPRINT_ENDDATAPACKET:
                raise Exception('The received packet is no data packet!')

            for i in range(0, len(received_packet_payload)):
                complete_payload.append(received_packet_payload[i])

        return complete_payload
