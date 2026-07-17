from scapy.all import *
import socket
import argparse
from rich.console import Console
from rich.table import Table
import subprocess
import requests
import threading
import sys

class Network:
    def __init__(self):
        self.logo()
        if len(sys.argv)==1:self.Help()

        else:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8",80))
            self.myIp=sock.getsockname()[0]
            self.x=0

            Console().print(f"[+] My Ip=>{self.myIp}",style="bold yellow")

            self.start()

    #----------Logo-------------
    def logo(self):
        logo = r"""[bold purple]
 _____         _
|_   _|__  ___| |_ ___ _ __ ___
  | |/ _ \/ __| __/ _ \ '__/ _ \
  | |  __/\__ \ ||  __/ | |  __/
  |_|\___||___/\__\___|_|  \___|

  network scanner · github.com/testere-development/networkScaner

"""
        Console().print(logo)
    #---------Help----------------
    def Help(self):
        help="""
usage: script.py [-h] [-a] [-t T] [-p P]
Network Scanner - ARP/Port Scan Tool
options:
-h, --help   bu yardım mesajını göstər
-a           AutoScan: öz şəbəkəndəki interfeysi tapıb avtomatik ARP scan edir (yalnız linux)
-t T         Manual ARP scan: hədəf IP/subnet (məs: 192.168.1.0/24)
-p P         Port scan: IP və ya IP:port,port,port
        """
        print(help)

    #---------ARP Ip Scan----------
    def scan(self,ip:str):
        ipList=[]
        
        Console().log("Start IP Scan",style="yellow")

        arp=ARP(pdst=ip)
        ether=Ether(dst="ff:ff:ff:ff:ff:ff")

        packet=ether/arp

        result=srp(packet,timeout=1,verbose=0)

        table=Table(title="IP SCAN")
        table.add_column("IP",style="cyan")
        table.add_column("MAC",style="magenta")
        table.add_column("MODEL",style="green")

        for i ,x in result[0]:
            addr=x.psrc
            mac=x.hwsrc
            model=self.mac(mac)
            ipList.append(f"{addr}=>{mac}=>{model}")
            
            table.add_row(addr,mac,model)

        Console().print(table)
        Console().log("End IP Scan",style="yellow")

        w=input("Device read file y/n [y]:").lower()

        if not w or w=='y':self.writeFile(f"{len(ipList)}_device.txt",ipList)
 
    #--------AutoARP Scan----------
    def autoScan(self):
        Console().print("Start AutoScan",style='yellow')

        ips=subprocess.run(["ip","a"],text=True,capture_output=True).stdout
        
        for i in ips.splitlines():
            if "inet" in i and not "127." in i and not "inet6" in i:
                self.ip=i.strip().split()[1]
                break
        self.scan(self.ip)
        
    #-------MAC=>Model-------------
    def mac(self,MAC:str)->str:
        response=requests.get(f"https://api.macvendors.com/{MAC}")

        if response.status_code==200:return response.text

        else:
            response=requests.get(f"https://api.maclookup.app/v2/macs/{MAC}")

            if response.status_code==200:return response.json()["company"]
            
            else:return ""

    #-------Port Scan--------------
    def portScan(self,addr:str,port:list=[i for i in range(65535)]):
        table=Table(title="Port Scan")
        table.add_column(addr,style="bold blue")
        portList=[]

        def scan(addr:str,port:int):
            nonlocal portList,table
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            try:
                sock.connect((addr,port))
                portList.append(port)
                table.add_row(str(port))
            except:pass
            finally:sock.close()

        Console().log(f"Start port scan {addr}")
        if len(port)==65535:
            Console().print("[bold yellow]Scan full port")
            for i in port:
                threading.Thread(target=scan,args=(addr,i)).start()
            scan(addr,65535)

        else:
            Console().print(f"[bold yellow] Scan port {' '.join(list(map(str,port)))}")
            a=0
            for i in port:
                if len(port)-1==a:scan(addr,i);break

                threading.Thread(target=scan,args=(addr,i)).start()

                a+=1

        Console().print(table)
        Console().log("End port scan")

        w=input("Open port read file y/n [y]:").lower()

        if not w or w=="y":self.writeFile(f"{addr}_port.txt",portList)
            
    #--------Write file-----------
    def writeFile(self,filename:str,text:list):
        with open(filename,"w") as file:
            file.write("\n".join(list(map(str,text))))

    #--------Start----------------
    def start(self)->None:
        parser=argparse.ArgumentParser(add_help=False)
        
        #AutoScan (default scan ip)
        parser.add_argument("-a",action="store_true")

        #manual scan
        parser.add_argument("-t",type=str)

        #Target ip port scan
        parser.add_argument("-p",type=str)

        #Help
        parser.add_argument("-h","--h",action="store_true")

        arg=parser.parse_args()
        
        if arg.h:
            self.Help()
            return None

        if arg.a:
            self.autoScan()
            return None

        if arg.t:
            Console().log(arg.t)
            self.scan(arg.t)
            return None

        if arg.p:
            if ":" in str(arg.p):
                addr,port=str(arg.p).split(":")[0],str(arg.p).split(":")[1]
                self.portScan(addr,list(map(int,port.split(","))))

            else: 
                try:
                    for i in str(arg.p).split("."):
                        int(i)

                    self.portScan(str(arg.p))

                except:Console().print("Bad format")

            return None
        


#run
try:       
    Network()
except Exception as e:Console().print(f"[bold red]{e}")



