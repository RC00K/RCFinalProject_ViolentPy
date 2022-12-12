import builtins
import csv
import json
import os.path
import socket
import sys
from datetime import datetime

import psutil
import scapy.all as scapy
from flask import (
    Blueprint, flash, render_template, request
)

from flaskr.battery.battery import battery_percentage
from flaskr.threading.threading import portthreading

bp = Blueprint('violentpy', __name__)


@bp.route('/')
def index():
    # Returns a tuple
    battery = psutil.sensors_battery()

    percent = battery.percent
    power = battery.power_plugged
    remaining = battery_percentage(battery.secsleft)

    # Print out the battery information
    print("Battery percentage: ", battery.percent, "%")
    print("Power plugged in: ", battery.power_plugged)

    # Convert seconds to hh:mm:ss
    print("Battery left: ", battery_percentage(battery.secsleft))

    with open('ports.csv') as file:
        reader = csv.reader(file)
        header = next(reader)

    return render_template('violentpy/index.html', percent=percent, plugged=power, left=remaining, header=header, rows=reader)


exc = getattr(builtins, "IOError", "FileNotFoundError")


@bp.route('/port_scan', methods=('GET', 'POST'))
def port_scan():
    # Ask for input
    if request.method == "POST":
        targethost = request.form["target"]
        targethostip = socket.gethostbyname(targethost)
        range_low = int(request.form["range_low"])
        range_high = int(request.form["range_high"])
    else:
        return EnvironmentError

    print("Please wait, scanning target IP:", targethostip)

    # Get relative path to the absolute path
    def get_absolute_path(relative_path):
        direcory = os.path.dirname(os.path.abspath(__file__))
        split_path = relative_path.split("/")
        absolute_path = os.path.join(direcory, *split_path)
        return absolute_path

    # Check the scan start time
    t1 = datetime.now()

    # Getting the port range from config.json
    try:
        with open(get_absolute_path('/config.json')) as config_file:
            config = json.load(config_file)
            print(get_absolute_path('/config.json'))
        CONST_NUM_THREADS = int(config['thread']['count'])

    except IOError:
        print("config.json file not found")
    except ValueError:
        print("Kindly check the json file for appropriateness of range")

    ports = list(range(range_low, range_high, 1))

    portnum = []

    def scan(ports, range_low, range_high):
        # Try to connect to a certain port
        # If open print port # and open
        try:
            for port in range(range_low, range_high):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((targethostip, port))
                if result == 0:
                    print("Port {}: 	 Open".format(port))
                    portnum.append("Port "+str(port))

                    pscan = [str(port),
                             str(targethostip),
                             "Open"]
                    with open(r'ports.csv',  'a') as f:
                        writer = csv.writer(f)
                        writer.writerow(pscan)
                sock.close()

        except KeyboardInterrupt:
            print("You ended the scan")
            sys.exit()

        except socket.gaierror:
            print("Target could not be resolve. Exiting")
            sys.exit()

        except socket.error:
            print("Couldn't connect to server")
            sys.exit()

    # Get multithreading function
    portthreading(ports, CONST_NUM_THREADS, scan, range_low, range_high)

    # Check the scan end time
    t2 = datetime.now()

    total = t2 - t1

    # Scan is complete
    print("Scan Completed In: ", total)

    return render_template('violentpy/scanner.html', target=targethostip, portnum=portnum, range_low=range_low, range_high=range_high, total=total)


@bp.route('/ip_scan', methods=('GET', 'POST'))
def ipscan():
    # Ask for input
    if request.method == "POST":
        target_ip = request.form["gateway"]
        # Determine if there is a target IP
        if not target_ip:
            error = 'Target is required.'
            # Error
            if error is not None:
                flash(error)

        # Scan start time
        timeStart = datetime.now()

        print("Please wait, scanning target IP:", target_ip)

        # Target IP to send ARP to
        arp = scapy.ARP(pdst=target_ip)

        # MAC Address of destination device
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # Packet to send is a combination of the Target IP and MAC Address
        packet = ether / arp

        # Response that is given back from the packet
        result = scapy.srp(packet, timeout=3, verbose=0)[0]

        # Prints out all the IP Address/MAC Address on the network
        clients = []

        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("Devices Found On The Network: \n")
        print("IP ADDRESS" + " " * 10 + "MAC ADDRESS")
        for client in clients:
            print("{:16}    {}".format(client['ip'], client['mac']), "\n")

            ip_scan = [str(target_ip),
                       str(client['ip']),
                       str(client['mac'])]
            with open(r'ip_scan.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerow(ip_scan)

        # Check the time again
        timeElapsed = datetime.now()

        # Calculate the total time
        totaltime = timeElapsed - timeStart

        return render_template('violentpy/scanner.html', gateway=target_ip, clients=clients, totaltime=totaltime)


@bp.route('/scanner.html')
def scanner():
    return render_template('violentpy/scanner.html')
