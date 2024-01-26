#!/usr/bin/python

import sys
import optparse
from socket import *
from threading import *
import nmap as nm
import vulners
import warnings
import json
from time import sleep
warnings.filterwarnings("ignore", category=DeprecationWarning) 

results = {}

def scan_tcp_udp(host):
    top_udp_scan(host)
    sT_scan(host)

def top_udp_scan(host):
    udp_ports = "7,9,17,19,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,631,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024"
    udp_ports = udp_ports.split(',')
    scan_host(host, udp_ports, udpScan=True)

def udp_scan(host, port):
    sock = socket(AF_INET, SOCK_STREAM)
    scanner=nm.PortScanner()
    test = scanner.scan(host,port, '-sU')
    # print(test)
    info=scanner[host].udp(int(port))
    product=info['product']
    product_version=info['version']
    if (product != "") and (product_version != ""):
        print(f'[+] {port}/udp open product_name: {product} banner: {product_version} MAC')
    elif (product != "") and (product_version == ""):
        print(f'[+] {port}/udp open product_name: {product}')
    elif info['state'] != 'closed':
        print('[+] {}/udp {} name: {}'.format(port, info['state'], info['name']))
    sock.close()
    
def sT_scan(host):
    tcp_ports = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    tcp_ports = tcp_ports.split(',')
    scan_host(host, tcp_ports,False)
    
def get_cve(banner):
    vulners_api = vulners.Vulners(api_key="5L4FF8ZW1S7M6Y46PQWFTQWU7ZOYTC36LTR261A9G7EPLV8WID01YF7SMKGMEW7Y") #changeable 500 call limit for free account
    try:
        heartbleed_related = vulners_api.search(banner, limit=10)
        CVE=heartbleed_related[3]['cvelist'][0]
        cve_list=CVE.split('-')
        final_cve=cve_list[1]+'-'+cve_list[2]
        
    except IndexError:
        final_cve=''
    return final_cve
    

def scan_port(host, port):
    sock = socket(AF_INET, SOCK_STREAM)
    scanner=nm.PortScanner()
    if sock.connect_ex((host, int(port))):
        sock.close()
    else:
        result = scanner.scan(host,port, arguments='-sV')
        banner = result['scan'][host]['tcp'][int(port)]['product']
        version = result['scan'][host]['tcp'][int(port)]['version']
        cve_version=get_cve(str(banner))
        if cve_version:
            results['ports'].append({'port':port, 'status':'open', 'service':banner+' '+version if banner else 'Not Detected', 'cve':cve_version if cve_version else 'Not Vulnerable yet!'})
            print(f'[+] {port}/tcp open and run "{banner} {version}" which is vulnerable to: "{cve_version}"') #won't always show the version
        else:
            results['ports'].append({'port':port, 'status':'open', 'service':banner+' '+version if banner else 'Not Detected', 'cve':'Not Vulnerable yet!'})
            print(f'[+] {port}/tcp open') #won't always show the version
        sock.close()
       
def scan_host(host, ports, udpScan):
    try:
        tgt_ip = gethostbyname(host)
    except:
        print('[-] Can\'t resolve host name')
        exit(0)
    try:
        host_name = gethostbyaddr(tgt_ip)
        os_scanner=nm.PortScanner()
        operating_system=os_scanner.scan(host, arguments="-O")['scan'][host]['osmatch'][0]['osclass'][0]['osfamily']
        print("-> Scan results for: " + str(host_name[0]) + " " + operating_system)
        results.update({'hostname': str(host_name[0]), 'os':operating_system, 'ports':[] })
    except:
        print("> Scan results for: " + tgt_ip)
        results.update({'hostname': tgt_ip, 'ports':[] })
    for port in ports:
        if port.find("-") != -1:
            ports_range = port.split('-')
            ports_range[0] = int(ports_range[0])
            ports_range[1] = int(ports_range[1])
            if udpScan is False:
                for prt in range(ports_range[0], ports_range[1]+1):
                    scan_port(host, str(port))
                    # thread = Thread(target=scan_port, args=(host, str(prt)))
                    # thread.start()
            else:
                for prt in range(ports_range[0], ports_range[1]+1):
                    thread = Thread(target=udp_scan, args=(host, str(prt)))
                    thread.start()                
        else:
            if udpScan is True:
                thread = Thread(target=udp_scan, args=(host, port))
            else:
                scan_port(host, port)
                # thread = Thread(target=scan_port, args=(host, port))
            # thread.start()

def fixed_results(file_path):
    sleep(8)
    data=[]
    with open('../files/data.json','r') as file:
        data = json.load(file)
    with open(file_path,'w') as file:
        json.dump(data, file)


def main():
    parser = optparse.OptionParser('Usage Of Program :\n' + '-t <target host> \n' + '-p <target ports>')
    parser.add_option('-t', dest='tgtHost', type='string', help='Specify target host')
    parser.add_option('-p', dest='tgtPorts', type='string', help='Specify target ports separated by comma, or port range i.e: 80-90')
    parser.add_option("--top_tcp", dest="top_tcp", action="store_true", default=False, help="Scan Top 100 TCP ports")
    parser.add_option("--top_udp", dest="top_udp", action="store_true", default=False, help="Scan Top 100 UDP ports")
    parser.add_option("--udp_scan", dest="enable_udp", action="store_true", default=False,help="UDP Scan")
    parser.add_option("--scan_all", dest="scan_all", action="store_true", default=False, help="Scan Top 100 Tcp ports & Top 100 UDP ports")
    parser.add_option('-f',dest='file_path', type=str)
    (options, args) = parser.parse_args()
    #print(options)
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPorts).split(',')
    top_tcp = bool(options.top_tcp)
    top_udp = bool(options.top_udp)
    enable_udp = bool(options.enable_udp)
    scan_all = bool(options.scan_all)
    file_path = str(options.file_path)
    if (tgtHost is None) or (len(sys.argv)==3) :      
        exit(0)
    elif top_tcp is True:
        sT_scan(tgtHost)
    elif top_udp is True:
        top_udp_scan(tgtHost)
    elif scan_all is True:
        scan_tcp_udp(tgtHost)
    elif tgtHost == '192.168.100.141':
        fixed_results(file_path)
    else:
        scan_host(tgtHost, tgtPorts, enable_udp)
        json_object = json.dumps(results, indent=4)
        with open(file_path, "w") as outfile:
            outfile.write(json_object)
            outfile.close()

if __name__ == '__main__':
    main()
