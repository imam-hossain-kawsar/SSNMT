from email.policy import HTTP
import asyncio
from tkinter import *
from tkinter import messagebox
from tkinter.ttk import Progressbar
import fpdf
from fpdf import FPDF
import socket
import struct
import textwrap
import time
from threading import Thread

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

root = Tk()
root.title('Packet Capturing Tool')
root.geometry('800x500')

tracker = FALSE
captureTracker = TRUE


def detectInterface():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('connection created!!!!!!!!!')
    messagebox.showinfo("Connection", "Successfully Connection Created!. ")
    global tracker
    tracker = TRUE


def savePacket():
    if tracker == TRUE:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Times', 'B', 16)
        pdf.cell(80)
        pdf.cell(40, 10, 'Captured Packet Information', 1, 0, 'C')
        pdf.output('packet.pdf', 'F')
        print("Packet saved!!!!!!!!!!")
        messagebox.showinfo("Store Capture Packet", "saved!!!!!")
    else:
        messagebox.showerror("Error", "Please create connection first!")


def generateReport():
    if tracker == TRUE:
        pdf = FPDF()
        pdf.add_page()
        pdf.image('iit1.png', 10, 8, 33)
        pdf.set_font('Arial', 'B', 15)
        pdf.cell(200, 10, txt="Capture Packet Information", ln=1, align="C")
        pdf.output('report.pdf', 'F')
        print("Report generated!!!!!!!!!!")
        messagebox.showinfo("Report", "Report generated successfully")
    else:
        messagebox.showerror("Error", "Please create connection first!")


def threaded_run():
    t = Thread(target=startCapture)
    t.daemon = True
    t.start()

def stopCapture():
    global captureTracker
    captureTracker = FALSE


def startCapture():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    cou = 0
    global captureTracker

    while captureTracker == TRUE:
        cou = cou + 1
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\n Ethernet Frame: ' + str(cou))
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
            print(TAB_1 + "IPV4 Packet:")
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_output_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
                    '! H H L L H H H H H H', raw_data[:24])
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))

                if len(data) > 0:
                    # HTTP
                    if src_port == 80 or dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_output_line(DATA_TAB_3, data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_output_line(DATA_TAB_3, data))
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_seg(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_output_line(DATA_TAB_2, data))
            # await stopCapture()
        else:
            print('Ethernet Data:')
            print(format_output_line(DATA_TAB_1, data))


# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H',
                                                                                                 data[:14])
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, destination_port, sequence, acknowledgenment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                               offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


toplabel = Label(root, text="Packet Capturing Tool", bg="#4a6966", fg="white")
toplabel.config(font=("Times", 25))
toplabel.pack(fill=X)

topFrame = Frame(root, bg="#47965c")
topFrame.pack()

bottomFrame = Frame(root)
bottomFrame.pack(side=BOTTOM)

connectionPhoto = PhotoImage(file="connection.png")
connectionCreation = Button(topFrame, text="Create Connection", image=connectionPhoto, compound=LEFT, fg="#3c6160",
                            command=detectInterface)
connectionCreation.pack(side=LEFT)

startphoto = PhotoImage(file="start.png")
captureStart = Button(topFrame, text="Start", image=startphoto, compound=LEFT, fg="#3c6160", command=threaded_run)
captureStart.pack(side=LEFT)

stopPhoto = PhotoImage(file="finish.png")

captureStop = Button(topFrame, text="Stop", image=stopPhoto, compound=LEFT, fg="#3c6160", command=stopCapture)
captureStop.pack(side=LEFT)

savePhoto = PhotoImage(file="save.png")
saveFile = Button(topFrame, text="Save", image=savePhoto, compound=LEFT, fg="#3c6160", command=savePacket)
saveFile.pack(side=LEFT)

reportPhoto = PhotoImage(file="report.png")
reportGenerate = Button(topFrame, text="Report", fg="#3c6160", image=reportPhoto, compound=LEFT, command=generateReport)
reportGenerate.pack(side=LEFT)

helpPhoto = PhotoImage(file="help.png")
helpButton = Button(topFrame, text="Help", image=helpPhoto, compound=LEFT, fg="#3c6160")
helpButton.pack(side=LEFT)

aboutPhoto = PhotoImage(file="about.png")
aboutButton = Button(topFrame, text="About", image=aboutPhoto, compound=LEFT, fg="#3c6160")
aboutButton.pack(side=LEFT)

exitPhoto = PhotoImage(file="exit.png")
exitButton = Button(topFrame, text="Exit", image=exitPhoto, compound=LEFT, fg="#3c6160", command=root.destroy)
exitButton.pack(side=LEFT)

root.mainloop()
