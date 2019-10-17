from tkinter import *
from tkinter import messagebox

import fpdf
from fpdf import FPDF
import socket
import struct
import textwrap

root = Tk()
root.title('Packet Capturing Tool')
root.geometry('800x500')

tracker = FALSE


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
        pdf.set_font('Times', 'B', 16)
        pdf.cell(40, 10, 'Report')
        pdf.output('report.pdf', 'F')
        print("Report generated!!!!!!!!!!")
        messagebox.showinfo("Report", "Report generated successfully")
    else:
        messagebox.showerror("Error", "Please create connection first!")


toplabel = Label(root, text="Packet Capturing Tool", bg="#4a6966", fg="white")
toplabel.config(font=("Times", 25))
toplabel.pack(fill=X)

topFrame = Frame(root, bg="#47965c")
topFrame.pack()

bottomFrame = Frame(root)
bottomFrame.pack(side=BOTTOM)

connectionCreation = Button(topFrame, text="Create Connection", fg="#3c6160", command=detectInterface)
connectionCreation.pack(side=LEFT)

captureStart = Button(topFrame, text="Start Capture", fg="#3c6160")
captureStart.pack(side=LEFT)

captureStop = Button(topFrame, text="Stop Capture", fg="#3c6160")
captureStop.pack(side=LEFT)

saveFile = Button(topFrame, text="Save", fg="#3c6160", command=savePacket)
saveFile.pack(side=LEFT)

reportGenerate = Button(topFrame, text="Report", fg="#3c6160", command=generateReport)
reportGenerate.pack(side=LEFT)


exitButton = Button(topFrame, text="Exit", fg="#3c6160", command=root.destroy)
exitButton.pack(side=LEFT)

root.mainloop()
