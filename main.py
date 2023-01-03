#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import argparse

now = datetime.now().strftime("%d-%m-%y %H-%M-%S")

DEFAULT_WORKING_FOLDER = "results"
DEFAULT_MASSCAN_RATE = 5000
DEFAULT_MASSCAN_INITIAL_PORT = 1  # TODO assert lower than 1
DEFAULT_MASSCAN_FINAL_PORT = 65535  # TODO assert biggest than 65535

MASSCAN_FILENAME = f"mass_result_{now}.xml"
NMAP_OUTPUT_FILENAME = f"nmap_result_{now}.txt"

script_dir = os.path.realpath(os.path.dirname(__file__))
results_dir = os.path.join(script_dir, DEFAULT_WORKING_FOLDER)
masscan_result_dir = os.path.join(results_dir, MASSCAN_FILENAME)


def main() -> None:
    # Assertions
    #TODO masscan y nmap installed on host

    # Process console arguments
    arguments = catch_arguments()

    if arguments.ports:
        MASSCAN_INITIAL_PORT, MASSCAN_FINAL_PORT = port_parser(arguments.ports)
    else:
        MASSCAN_INITIAL_PORT, MASSCAN_FINAL_PORT = DEFAULT_MASSCAN_INITIAL_PORT, DEFAULT_MASSCAN_FINAL_PORT
    
    if arguments.rate:
        assert arguments.rate > 0, f"At 0 rate it will take an eternity. try something bigger"
        MASSCAN_RATE = arguments.rate
    else:
        MASSCAN_RATE = DEFAULT_MASSCAN_RATE

    # Main Script
    if not os.path.isdir(results_dir):
        os.mkdir(results_dir)

    execute_masscan(arguments.network, MASSCAN_INITIAL_PORT,
                    MASSCAN_FINAL_PORT, masscan_result_dir, MASSCAN_RATE)

    nmap_targets = parse_masscan_xml(masscan_result_dir)

    for target in nmap_targets:
        execute_nmap(target[0], target[1], results_dir)


def execute_masscan(network: str, initial_port: int, final_port: int, outputfile: str, rate=5000) -> None:
    """
    executes masscan program from python, massscan must be installed in the host

    Parameters
    ----------
    network         : string
        absolute path to a file where the ip's to scan should be found.
        Example: '192.168.1.0/24'

    initial_port    : int
        lower port to be scanned.

    final_port      : int
        upper port to be scanned.

    outputfile      : str
        name of the file that it will output (in the context of this script it will be used by nmap).
        Example: '/home/usr/result.xml'

    rate            : int
        number of kilobytes per second that masscan will use.

    Returns
    -------
        None

    Examples
    --------
    >>> execute_masscan('192.168.1.0/24', 0, 65536, "result", rate=100)

    """
    base, filename = os.path.split(outputfile)
    assert os.path.isdir(base), f"The Path: {base}, Doesn't Exist."

    # This command has all of the options but lack the output path, this is bcuz split can broke the path
    command = f'sudo masscan --ports {initial_port}-{final_port} {network} --rate={rate} -oX'
    subprocess.run(command.split() + [outputfile], capture_output=True, text=True)
    return None


def parse_masscan_xml(source_file) -> list[tuple]:
    """
    read the masscan xml result file and returns every ip where a service was found

    Parameters
    ----------
    source_file : string
        absolute path where the masscan result file is located.
        if it was created by this script, it should be in the working folder

    Returns
    -------
        list of tuples with the combination of (IP, PORT)

    Examples
    --------
    >>> parse_masscan_xml('path/to/file.xml')

    """
    ips = []
    tree = ET.parse(source_file)
    root = tree.getroot()
    for child in root:
        if child.tag == 'host':
            detected_host = child
            for child in detected_host:
                if child.tag == "address":
                    detected_ip = child.attrib['addr']
                elif child.tag == "ports":
                    for sibling in child:
                        detected_port = int(sibling.attrib['portid'])
            service_at = (detected_ip, detected_port)
            ips.append(service_at)
    return ips


def execute_nmap(ip: str, port: int, result_path: str) -> None:
    """
    Takes an ip and a port, and execute nmap with the vulners script on it,
    the returned data will be appended to /result_path/nmap_result.txt

    Parameters
    ----------
    ip : string
        The ip address where the nmap command will target.
        Example: '192.168.1.1'

    port : int
        The port of the ip where the nmap scan will run

    output_file : string
        Absolute reference to the file where the output will be stored

    Returns
    -------
        A String containing the result of the nmap command execution

    Examples
    --------
    >>> execute_nmap('8.8.8.8', 80, '/home/usr/out/output.txt')
    >>> execute_namp('192.168.1.1', 22, 'home/usr/out/output.txt')
    """
    output_file = os.path.join(result_path, NMAP_OUTPUT_FILENAME)
    command = f'nmap {ip} -p {port} -sV -T4 -A -v --script vulners.nse'
    process = subprocess.run(command.split(), capture_output=True, text=True)

    if not os.path.isfile(output_file):
        with open(output_file, 'x') as newfile:
            pass

    with open(output_file, 'a') as file:
        file.write(process.stdout)
        file.write('\n')

    return None


def catch_arguments() -> argparse.Namespace:
    # This function adds CLI Arguments usage
    program_description = "This program will execute nmap with vulners script over the result of an masscan"

    args_parser = argparse.ArgumentParser(
        prog = "massvulnersmap.py",
        description = program_description,
        epilog = "Type massvuln -h for help" 
    )
    args_parser.add_argument('network', metavar="IPv4 Network. e.g. 192.168.1.1/24", help="by example: 192.168.1.1/24")
    args_parser.add_argument('-p', "--ports", type = str,  help = "Initial and final port. Default: 1-65535")
    args_parser.add_argument("-r", "--rate", type = int, help = "Kb/s of scan, must be an int. Default: 1000")
    args = args_parser.parse_args()
    return args


def port_parser(port_string: str) -> tuple[int]:
    # This function parses a port string with 'int-int' format
    ports = port_string.split("-")
    try:
        initial_port = int(ports[0])
        final_port = int(ports[1])

        assert initial_port > 1 and final_port < 65535, "Port range must be between 1 and 65535."
        assert initial_port < final_port, f"{final_port} must be bigger than {initial_port}."

        return (initial_port, final_port)
    except ValueError:
        print("Error parsing ports. Try something like: 22-23")
        raise SystemExit


if __name__ == '__main__':
    main()
