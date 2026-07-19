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
        
        self.dataList=[]

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
    usage: script.py [-h] [-aa] [-ap] [-t T] [-p P] [-sn SN] [-o O]

-h, --h   show help / kömək mesajı
-aa       auto ARP scan, detects interface (Linux only) / avtomatik ARP scan, interfeysi özü tapır (yalnız Linux)
-ap       auto PING scan, detects interface (Linux only) / avtomatik PING scan, interfeysi özü tapır (yalnız Linux)
-t T      ARP scan target IP/subnet, e.g. 192.168.1.0/24 / ARP scan hədəfi, məs: 192.168.1.0/24
-p P      port scan: IP or IP:port,port,port / port scan: IP və ya IP:port,port,port
-sn SN    ping scan, subnet mask e.g. 24 / ping scan, subnet maska, məs: 24
-o O      save output to file / nəticəni fayla yaz
        """
        print(help)

    #---------ARP Ip Scan----------
    def scanARP(self,ip:str=''):
        if not ip:ip=self.myIp+'/24'
        ipList=[]
        
        Console().log("Start ARP IP Scan",style="yellow")

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

        self.dataList=ipList

    #--------PING Ip Scan----------
    def scanPING(self,subnet:int=24):
        ipList=[]
        table=Table()
        table.add_column("IP",style="bold cyan")
        def scan(ip:str):            
            nonlocal table,ipList

            ping=subprocess.run(["ping","-c","1",ip],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            
            if ping.returncode==0:
                ipList.append(ip)
                table.add_row(str(ip))

        subnet=2**(32-subnet)
        Console().log(f"Start PING IP Scan subnet {subnet}",style="yellow")

        p=self.myIp.split(".")
        del p[3]
        p=".".join(p)+"."
        for i in range(subnet):
            i=p+str(i)
            if i==self.myIp:
                ipList.append(f"{self.myIp}(my ip)")
                continue
            threading.Thread(target=scan,args=(i,)).start()
    
        if not p+str(subnet)==self.myIp:scan(p+str(subnet))

        Console().print(table)
        Console().log("End PING IP Scan",style="yellow")
        self.dataList=ipList

    #--------AutoARP Scan----------
    def autoScan(self,option:int):
        Console().print("Start AutoScan",style='yellow')

        ips=subprocess.run(["ip","a"],text=True,capture_output=True)

        if not ips.stderr:
            for i in ips.stdout.splitlines():
                if "inet" in i and not "127." in i and not "inet6" in i:
                    self.ip=i.strip().split()[1]
                    break

            match option:
                case 1:
                    self.scanARP(self.ip)

                case 0:
                    ip=self.ip.split("/")[1]
                    self.scanPING(int(ip))
            
                case _:Console().print("Bad options use [-aa] or [-ap]")
        
        else:
            Console().log("[red]ip a command [yellow]Defaut subnet 24")
            match option:
                case 1:
                    self.scanARP()

                case 0:
                    self.scanPING()
            
                case _:Console().print("Bad options use [-aa] or [-ap]")

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

        self.dataList=portList
     
    #--------Write file-----------
    def writeFile(self,filename:str,text:list):

        with open(filename,"w") as file:
            file.write("\n".join(list(map(str,text))))

        Console().log(f"Write [bold]{filename}",style="green")

    #--------Start----------------
    def start(self):
        parser=argparse.ArgumentParser(add_help=False)
        
        #AutoScan (default scan ip)
        parser.add_argument("-aa",action="store_true")
        parser.add_argument("-ap",action="store_true")

        #ARp scan
        parser.add_argument("-t",type=str)

        #Auto ARP ip port scan
        parser.add_argument("-p",type=str)

        #Ping scan
        parser.add_argument("-sn",type=int)

        #Help
        parser.add_argument("-h","--h",action="store_true")

        #Output file
        parser.add_argument("-o",type=str)

        arg=parser.parse_args()
        
        if arg.h:self.Help()

        if arg.aa:self.autoScan(1)
        
        if arg.ap:self.autoScan(0)

        if arg.t:Console().log(arg.t);self.scanARP(arg.t)

        if arg.p:
            if ":" in str(arg.p):
                addr,port=str(arg.p).split(":")[0],str(arg.p).split(":")[1]
                self.portScan(addr,list(map(int,port.split(","))))

            else: 
                try:
                    for i in str(arg.p).split("."):
                        int(i)

                    self.portScan(str(arg.p))

                except:Console().print("Bad format",style="red")
        
        if arg.sn:self.scanPING(arg.sn)
        
        if arg.o:self.writeFile(str(arg.o),self.dataList)
        

#run
try:       
    Network()
except KeyboardInterrupt:Console().print("[red]Quit");sys.exit()
except Exception as e:Console().print(f"[bold red]{e}")


