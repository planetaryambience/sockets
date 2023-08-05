""" 
    COSC264 - assignment 1: client.py 
"""

import sys
import select

from socket import *

def error(message):
    """ prints error message and exits program. """
    print(message)
    sys.exit("exiting program...") 


def valid_port_num(port_num):
    """ checks that the port given by the user is valid.
        returns port_num if valid, otherwise exits program. """
    try:
        port_num = int(port_num)
    except Exception as er:
        print(er)
        error("please enter valid integer for the port number.")

    if not (1024 <= port_num <= 64000):
        error("port numbers must be between 1,024 and 64,000 (inclusive).")

    return port_num


def compose_packet(request):
    """ returns a DT-Request packet. """
    packet = bytearray(6)

    # MagicNo =  0x497E
    packet[0] = 0x49
    packet[1] = 0x7E

    # PacketType = 0x0001
    packet[3] = 0x01

    if request == "date":
        packet[5] = 0x01
    else: 
        # request == "time"
        packet[5] = 0x02

    return packet


def check_packet(packet):
    """ checks if packet is a valid DT-Response packet.
        returns True if packet passes all checks,
        otherwise prints error message and returns False. """

    if len(packet) < 13:
        print("packet does not contain at least 13 bytes.")
        return False

    if (packet[0] != 0x49) and (packet[1] != 0x7E):
        print("'MagicNo' field is invalid (not equal to 0x497E).")
        return False

    if (packet[2] != 0x00) and (packet[3] != 0x02):
        print("'PacketType' field is invalid (not a DT-Response packet).")
        return False
        
    if (packet[4] != 0x00) and (packet[5] not in [0x01, 0x02, 0x03]):
        print("'LanguageCode' field is invalid.")
        return False
        
    if ((packet[6] << 8) + packet[7]) >= 2100:
        print("year is a number above 2100.")
        return False
        
    if (packet[8] < 1) or (packet[8] > 12):
        print("month is not a number between 1 and 12.")
        return False
        
    if (packet[9] < 1) or (packet[9] > 31):
        print("day is not a number between 1 and 31")
        return False
        
    if (packet[10] < 0) or (packet[10] > 23):
        print("hour is not a number between 0 and 23")
        return False
        
    if (packet[11] < 0) or (packet[11] > 59):
        print("minute is not a number between 0 and 59")
        return False
        
    if len(packet) != (13 + packet[12]):
        print("total packet length is incorrect.")
        return False
        
    return True


def print_packet(packet):
    """ prints packet contents line by line """

    magic_num = (packet[0] << 8) + packet[1]
    packet_type = (packet[2] << 8) + packet[3]
    language_code = packet[4:6].hex()
    year = (packet[6] << 8) + packet[7]
    month = packet[8]
    day = packet[9]
    hour = packet[10]
    minute = packet[11]
    length = packet[12]
    text = packet[13:].decode('utf-8')

    print("magic number: {0:#0{1}x}".format(magic_num, 6))
    print("packet type: {0:#0{1}x}".format(packet_type, 6))
    print("language code: 0x{}".format(language_code))
    print("year: {}".format(year))
    print("month: {}".format(month))
    print("day: {}".format(day))
    print("hour: {}".format(hour))
    print("minute: {}".format(minute))
    print("text length: {}".format(length))
    print("text: {}".format(text))


def client(request, address, port_num):
    """ performs client operations. """

    client_socket = socket(AF_INET, SOCK_DGRAM)
    request_packet = compose_packet(request)
    server_address = (address, port_num)

    try:
        client_socket.sendto(request_packet, server_address)
        print("\nrequest packet sent to server.")
    except Exception as er:
        client_socket.close()
        print(er)
        error("failed to send packet to server.")

    # wait for response packet, timeout after 1s
    read_list, write_list, errors = select.select([client_socket], [], [], 1)

    if (len(read_list) == 0) and (len(write_list) == 0) and (len(errors) == 0):
        client_socket.close()
        error("timeout reached when waiting for response packet.")
    else:
        for pkt in read_list:
            try: 
                server_packet = pkt.recvfrom(4096)
                message, server_address = server_packet

                print("response packet received!\n")

                if check_packet(message):
                    print("--- DT-RESPONSE PACKET CONTENTS ---")
                    print_packet(message)
                else:
                    client_socket.close()
                    error("discarding packet...")
            except Exception as er:
                client_socket.close()
                print(er)
                error("error occurred when receiving packet.")
    
    client_socket.close()


def main():
    print("----- CLIENT PROGRAM ----")

    print("-'date' for current date\n-'time' for current time")
    request = input("please enter what you wish to see: ")
    if (request != "date") and (request != "time"):
        error("invalid request. please enter either 'date' or 'time'")

    address = input("please enter IP address (dotted-decimal) or a hostname: ")

    port_num = input("please enter a port number between 1,024 and 64,000: ")
    port_num = valid_port_num(port_num)

    try:
        address = getaddrinfo(address, port_num)[0][4][0]
    except gaierror as er:
        print(er)
        error("could not convert given address to IP address.")

    client(request, address, port_num)


if __name__ == "__main__":
    main()