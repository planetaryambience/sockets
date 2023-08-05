""" 
    COSC264 - assignment 1: server.py 
"""

import sys
import select
import datetime

from socket import *

HOST = ""

def error(message):
    """ prints error message and exits program. """
    print(message)
    sys.exit("exiting program...")


def check_port_inputs(port_1, port_2, port_3):
    """ checks that ports given by the user are valid,
        exits program if ports don't pass checks. """

    try:
        ports = [int(port_1), int(port_2), int(port_3)]
    except ValueError:
        error("please enter valid integers.")

    for i in range(len(ports)):
        if not (1024 <= ports[i] <= 64000):
            error("port numbers must be between 1,024 and 64,000 (inclusive).")

    if len(set(ports)) != len(ports):
        error("port numbers must be unique.")


def check_packet(packet):
    """ checks if packet is a valid DT-Request packet.
        returns True if packet passes all checks,
        otherwise calls error function which exits program. """

    if len(packet) != 6:
        error("packet does not contain exactly six bytes.")

    if (packet[0] != 0x49) and (packet[1] != 0x7E):
        error("'MagicNo' field is invalid (not equal to 0x497E).")

    if (packet[2] != 0x00) and (packet[3] != 0x01):
        error("'PacketType' field is invalid (not a DT-Request packet).")

    if (packet[4] != 0x00) and ((packet[5] != 0x01) or (packet[5] != 0x02)):
        error("'RequestType' field is invalid (not equal to 0x001 or 0x002).")

    return True


def compose_packet(rcv_pkt, lang):
    """ returns a DT-Response packet. """

    eng_months = ['January', 'February', 'March', 'April', 'May',
                  'June', 'July', 'August', 'September', 'October',
                  'November', 'December']
    maori_months = ['Kohitatea', 'Hui-tanguru', 'Poutu-te-rangi',
                    'Paenga-whawha', 'Haratua', 'Pipiri', 'Hongongoi',
                    'Here-turi-koka', 'Mahuru', 'Whiringa-a-nuku',
                    'Whiringa-a-rangi', 'Hakihea']
    ger_months = ['Januar', 'Februar', 'Marz', 'April', 'Mai', 'Juni', 'Juli',
                  'August', 'September', 'Oktober', 'November', 'Dezember']

    current_time = datetime.datetime.now()
    year = current_time.year
    month = current_time.month
    day = current_time.day
    hour = current_time.hour
    minute = current_time.minute

    if lang == 0:
        language = 0x01
        date_str = ("Today's date is {} {}, {}"
                    .format(eng_months[month-1], day, year))
        time_str = "The current time is {}:{}".format(hour, minute)
    elif lang == 1:
        language = 0x02
        date_str = ("Ko te ra o tenei ra ko {} {}, {}"
                    .format(maori_months[month-1], day, year))
        time_str = "Ko te wa o tenei wa {}:{}".format(hour, minute)
    else:
        language = 0x03
        date_str = ("Heute ist der {}. {} {}"
                    .format(day, ger_months[month-1], year))
        time_str = "Die Uhrzeit ist {}:{}".format(hour, minute)

    if rcv_pkt[5] == 0x01:
        text = date_str.encode('utf-8')
    else:
        text = time_str.encode('utf-8')

    text_len = len(text)

    if text_len <= 255:
        packet = bytearray(13)

        # MagicNo =  0x497E
        packet[0] = 0x49
        packet[1] = 0x7E

        # PacketType
        packet[3] = 0x02
        
        packet[5] = language
        packet[6] = year >> 8
        packet[7] = year & 0x00FF
        packet[8] = month
        packet[9] = day
        packet[10] = hour
        packet[11] = minute
        packet[12] = text_len

        packet += bytearray(text)
        return packet
    else:
        print("ERROR: length of text too long.\ndiscarding request...")
        return None


def server(port_1, port_2, port_3):
    """ performs server operations. """
    # open and bind sockets
    try:
        socket_1 = socket(AF_INET, SOCK_DGRAM)
        socket_2 = socket(AF_INET, SOCK_DGRAM)
        socket_3 = socket(AF_INET, SOCK_DGRAM)

        socket_1.bind((HOST, int(port_1)))
        socket_2.bind((HOST, int(port_2)))
        socket_3.bind((HOST, int(port_3)))
    except Exception as er:
        print(er)
        error("ERROR: could not open/bind sockets.")

    print("socket binding successful!\n")
    
    sockets = [socket_1, socket_2, socket_3]
    while True:
        print("listening for incoming packets...")
        read_list, write_list, errors = select.select(sockets, [], [])

        for pkt in read_list:
            # read_list will contain value if packet received
            print("request packet received!")

            client_packet = pkt.recvfrom(4096)
            message, client_address = client_packet
            receiving_socket = sockets.index(pkt)

            if check_packet(message):
                response_pkt = compose_packet(message, receiving_socket)

                if response_pkt is not None:
                    try:
                        pkt.sendto(response_pkt, client_address)
                        print("response packet sent back to client.\n")
                    except Exception as er:
                        print(er)
                        error("failed to send packet to client.")
        

def main():
    print("----- SERVER PROGRAM -----")

    # get port numbers
    print("please enter 3 different port numbers between 1,024 and 64,000.")
    port_1 = input("port 1: ")
    port_2 = input("port 2: ")
    port_3 = input("port 3: ")

    check_port_inputs(port_1, port_2, port_3)
    server(port_1, port_2, port_3)


if __name__ == "__main__":
    main()