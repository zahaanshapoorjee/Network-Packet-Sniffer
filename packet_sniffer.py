import socket
import struct
import textwrap

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATA_TAB1 = '\t '
DATA_TAB2 = '\t\t '
DATA_TAB3 = '\t\t\t '
DATA_TAB4 = '\t\t\t\t '

#PACKET SNIFFER IN PYTHON BASED ON THENEWBOSTON'S TUTORIAL
def main():

    print("INITIALIZING SOCKET...\n")
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))
    print("SOCKET INITIALIZED")

    print("STARTING PACKET SNIFFER:\n")
    while(True):

        raw_data, address = connection.recvfrom(65536)
        destination_MAC, source_MAC, proto, data = unpack_Ethernet_Frame(raw_data)

        print("Ethernet Frame: ")
        print(TAB1+"Source Address: {}, Destination Address: {}, Protocol: {}".format(source_MAC, destination_MAC, proto))

        if(proto==8):
            version, header_length, ttl, protocol, destination, source, data = unpackIP(data)
            print(TAB1+'IPv4 Packet:')
            print(TAB2+'Version: {}, Header Length: {}, Time to Live: {}'.format(version, header_length, ttl))
            print(TAB2+'Protocol: {}, Source: {}, Destination: {}'.format(proto, source, destination))

            if(proto==1): #IF THE PACKET IS AN ICMP PACKET
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB1+'ICMP Packet:')
                print(TAB2+'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB2+'Data:')

                print(multi_line_format(DATA_TAB3, data))


            if(proto==6): #IF THE PACKET IS A TCP PACKET
                source_port, destination_port, sequence, acknowledgement, offset_reserved_flags, offset_urgent, offset_ack, offset_psh, offset_rst, offset_syn, offset_fin, data = unpack_TCP(data)
                print(TAB1+'TCP Packet:')
                print(TAB2+'Source Port: {}, Destination Port: {}'.format(source_port, destination_port))
                print(TAB2+'Sequence : {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB2+'Flags:')
                print(TAB3+'URGENT: {}, ACK: {}, PUSH: {}, RESET: {}, SYN: {}, FIN: {}'.format(offset_urgent, offset_ack, offset_psh, offset_rst, offset_syn, offset_fin))
                print(TAB2+'Data:')

                print(multi_line_format(DATA_TAB3, data))


            elif(proto==17):
                source_port, destination_port, size, data = unpack_UDP(data)
                print(TAB1+'UDP Packet:')
                print(TAB2+'Source Port: {}, Destination Port: {}, Size: {}'.format(source_port, destination_port, size))
                print(TAB2+'Data:')

                print(multi_line_format(DATA_TAB3, data))

                
            else: #ELSE
                print(TAB1+'Data:')

                print(multi_line_format(DATA_TAB2, data))

#Function to unpack ethernet frames
def unpack_Ethernet_Frame(ethFrame):
    destination_MAC, source_MAC, proto = struct.unpack('! 6s 6s H', ethFrame[:14] ) #! - convert from big-endian to little-endian, 6 bits for source,
    return format_MAC_ADDRESS(destination_MAC),format_MAC_ADDRESS(source_MAC),socket.htons(proto),ethFrame[14:] #6 bits for address, H - unsigned int, THUS 14 bits in total.
#ethFrame[14:] contains the payload of the ethernet frame - it is the remaining bits after the source, destination, and type.


#Function to format MAC addresses (AA:BB:CC:DD:EE:FF)
def format_MAC_ADDRESS(bytes_address):
    bytes_string = map('{:02x}'.format,bytes_address)
    return ':'.join(bytes_string).upper()

#Function to unpack the IPV4 Packets
def unpackIP(packet):
    version_and_headerlength = packet[0]
    version = version_and_headerlength >> 4
    header_length  = (version_and_headerlength & 15)*4
    ttl, protocol, source_address, destination_address = struct.unpack('! 8x B B 2x 4s 4s', packet[:20])
    return version, header_length, ttl, protocol, ip_Format(destination_address), ip_Format(source_address), packet[header_length:]

#Function to properly format IPv4 address
def ip_Format(ip):
    return '.'.join(map(str,ip))

#Function to unpack ICMP packets
def icmp_packet(packet):
    icmp_type, code, checksum = struct.unpack('! B B H', packet[:4])
    return icmp_type, code, checksum, packet[4:] #packet[4:] will contain the payload as the header ends by packet[4]

#Function to unpack TCP segment
def unpack_TCP(packet):
    (source_port, destination_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', packet[:14])

    offset = (offset_reserved_flags >> 12)*4
    offset_fin = offset_reserved_flags & 1
    offset_urgent = (offset_reserved_flags & 32) >> 5
    offset_ack = (offset_reserved_flags & 16) >> 4
    offset_psh = (offset_reserved_flags & 8) >> 3
    offset_rst = (offset_reserved_flags & 4) >> 2
    offset_syn = (offset_reserved_flags & 2) >> 1
    return source_port, destination_port, sequence, acknowledgement, offset_reserved_flags, offset_urgent, offset_ack, offset_psh, offset_rst, offset_syn, offset_fin, packet[offset:]

#Function to unpack UDP segment
def unpack_UDP(packet):
    source_port, destination_port, size = struct.unpack('! H H 2x H', packet[:8])
    return source_port, destination_port, size, packet[8:]

#Function to format multi-line strings (Found Online)
def multi_line_format(prefix,string,size=69):
    size-=len(prefix)
    if isinstance(string, bytes):
        string = '.'.join(r'\x{:02x}'.format(byte) for byte in string)
        if size%2:
            size-=1
    return '\n'.join([prefix+line for line in textwrap.wrap(string, size)])

main()

