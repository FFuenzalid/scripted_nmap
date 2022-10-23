#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import os
import subprocess
import xml.etree.ElementTree as ET


def parse_ips(source_file: str) -> list:
    """
    Takes a absolute path to a file where ip's should be stored separated by newlines
    it return the data as a list containing all of the newlines as elements

    Parameters
    ----------
    source_file : string
        absolute path to a file where the ip's to scan should be found
        Example: /home/user/iplist.txt

    Returns
    -------
        a list that contains the ip's of the given file

    Examples
    --------
    >>> source_file(home/user/out/ip_lists.txt)

    TODO:
        - check that the newline actually contains a valid ip

    """
    result = []
    with open(source_file, 'r') as file:
        file_content = file.readlines()
        for line in file_content:
            if not ('/') in line:
                result.append(line.split()[0])
            else:
                print(f'Network {line} found in {source_file}')
    return result


def append_to_file(data: str, output_file: str) -> None:
    """
    Takes string data and append it to the output_file file

    Parameters
    ----------
    data : string
        The data that will be appended to the output_file
        Example: "Hello World!"
    output_file : string
        Absolute reference to the file where the output will be stored

    Returns
    -------
        None

    Examples
    --------
    >>> append_to_file('8.8.8.8', home/user/out/output.txt)
    >>> append_to_file('Hello World', home/user/out/output.txt)
    """
    with open(output_file, 'a') as file:
        file.write('\n' + data)
    return None


def execute_nmap(ip: str, output_file: str) -> str:
    """
    Takes a file that contains ip's separated by newlines
    and returns the stdout of the execution

    Parameters
    ----------
    ip : string
        The ip address where the nmap command will target.
        Example: /home/user/file.txt
    output_file : string
        Absolute reference to the file where the output will be stored

    Returns
    -------
        A String containing the result of the nmap command execution

    Examples
    --------
    >>> execute_nmap('8.8.8.8', home/user/out/output.txt)
    >>> execute_namp('192.168.1.1, home/user/out/output.txt)
    """

    base, filename = os.path.split(output_file)
    assert os.path.isdir(base), f"The Path: {base}, Doesn't Exist."

    command = f'nmap {ip} -sV -T4 -A -v --script vulners.nse'
    process = subprocess.run(command.split(), capture_output=True, text=True)

    return process.stdout


def read_masscan_xml(source_file):
    ips = []
    tree = ET.parse(source_file)
    root = tree.getroot()
    for child in root:
        if child.tag == 'host':
            host = child
            for child in host:
                if child.tag == "address":
                    ips.append(child.attrib['addr'])
    return ips


def execute_masscan(network: str, initial_port: int, final_port: int, outputfile: str, rate=5000) -> None:
    base, filename = os.path.split(output_file)
    assert os.path.isdir(base), f"The Path: {base}, Doesn't Exist."

    command = f'sudo masscan --ports {initial_port}-{final_port} {network} --rate={rate} -oX {output_file}.xml'
    subprocess.run(command.split())
    return None


def save_masscan_ips(ips: list, source_file: str) -> None:
    with open(source_file, 'w') as f:
        f.write('\n'.join(ips))


def main(source_file, output_file):
    network = '66.96.134.1/23'
    masscan_file_output = 'masscan_result.xml'
    execute_masscan(network, 0, 100, masscan_file_output, rate=10000)
    ip_list = read_masscan_xml(masscan_file_output)
    save_masscan_ips(ip_list, source_file)
    res = parse_ips(source_file)
    for ip in res:
        stdout = execute_nmap(ip, output_file)
        append_to_file(stdout, output_file)


if __name__ == '__main__':
    start_time = time.time()
    pwd = os.getcwd()

    INPUT_FILE_NAME = "ip_list.txt"
    OUTPUT_FOLDER_NAME = "result"
    OUTPUT_FILE_NAME = "scan.txt"

    dest_path = os.path.join(pwd, OUTPUT_FOLDER_NAME)
    source_file = os.path.join(pwd, INPUT_FILE_NAME)
    output_file = os.path.join(dest_path, OUTPUT_FILE_NAME)

    main(source_file, output_file)

    time_log = f"Executed in: {(time.time() - start_time)/60} Minutes."
    with open(output_file, 'a') as file:
        file.write(time_log)
