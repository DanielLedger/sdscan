import argparse, socket, os
from cryptography import x509
from OpenSSL import SSL as ssl

import threading, queue, time

from dns import resolver

import sys


def getAltNamesOnCert(base, port = 443):
    """Gets the alternative names on the SSL certificate of 'base' (a domain name).
        Pros:
        + Much quicker than dictionary based enumeration.
        + Good way to test if there are any subdomains to find
        (since unless you're a huge company capable of signing your own SSL
        certificates, you'll wildcard or extend your existing cert as soon as you get any subdomains
        to save money/effort).
        Cons:
        - Not likely to find anything especially concrete (since it's both easier and
        future-proof to just use a wildcard on the domain, rather than directly listing subdomains).
        """
    InfoOutput.debug("Setting TLS context...")
    certCont = ssl.Context(ssl.TLSv1_2_METHOD)
    certCont.set_verify(False)

    InfoOutput.debug("Connecting...")
    sock = ssl.Connection(certCont, socket.socket())

    sock.connect((base, 443))

    sock.do_handshake()

    InfoOutput.debug("Getting X509 certificate...")

    cert = sock.get_peer_certificate().to_cryptography()

    InfoOutput.debug("Closing connection...")
    sock.close()
    
    InfoOutput.debug("Getting alternative names...")
    altNames = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    return set(altNames.value.get_values_for_type(x509.DNSName))

def queryName(name):
    """Asks our local friendly DNS server for both A and AAAA records. Since we don't care about the answers, we only need to run one check, if that returns a result."""
    try:
        resolver.resolve(name, "A")
    except resolver.NXDOMAIN:
        #Try a AAAA query.
        try:
            resolver.resolve(name, "AAAA")
        except resolver.NXDOMAIN:
            return False
    return True #We got to here, so at least one of the queries succeeded.

def dnsSubdomainScan(sdList, base, threads = 4, sleepTime = 0.05, progressBar = True):
    """Scans for subdomains via querying a DNS server from a list.
    Pros:
    + Will find any subdomains visible externally, provided they are in the wordlist we were given.
    + Intended target won't know anything unusual is happening unless they can see DNS query logs.
    Cons:
    - Slower than certificate based scan.
    - Won't find subdomains that are only listed on an internal DNS server (since those can't be queried of a generic server).
    - Can't find anything not in the wordlist.
    """
    found = queue.Queue()
    toProcess = queue.Queue()
    for sd in sdList:
        toProcess.put(sd + "." + base)
        
    def threadedRun():
        while not toProcess.empty(): #Additional error handling may be needed.
            s = toProcess.get(timeout=1)
            if not progressBar:
                InfoOutput.debug("Querying %s." % s)
            try:
                if queryName(s):
                    found.put(s)
            except:
                pass #Don't care for now.
            toProcess.task_done()
            time.sleep(sleepTime)
            
    for _ in range(threads):
        t = threading.Thread(target=threadedRun)
        t.start() #Begin making queries.
    #Print a cute progress bar if we've been asked to.
    if not progressBar:
        #Just join.
        toProcess.join()
    else:
        target = len(sdList)
        targetLen = len(str(target)) #Size to leftpad the "items remaining" bar to.
        while (remaining := toProcess.qsize()) > 0:
            InfoOutput.info("Done %s/%i." % (str(target - remaining).rjust(targetLen, "0"), target), end = "\r")
            time.sleep(0.1)
    res = set()
    while not found.empty():
        res.add(found.get())
    return res

def getList(fPath):
    """Gets a list of subdomains from a file."""
    with open(fPath) as dFile:
        subdomains = dFile.readlines()
    return list(map(lambda k: k.replace("\n", ""), filter(lambda x:not x.startswith("#") and len(x) > 0, subdomains)))

def makeHostReq(ip, port = 80, subdomain = None, path = "/", additionalHeaders = "\r\n", httpVer = 1.1):
    """Sends a HTTP request with an optionally specified hostname. See below.
        Returns the response the server gave to us."""
    req = "HEAD %s HTTP/%.1f\r\n" % (path, httpVer)
    if subdomain != None:
        req += "Host: %s\r\n" % subdomain
    req += additionalHeaders
    req += "\r\n"
    cs = socket.socket()
    cs.connect((ip, port))
    #print(req)
    cs.send(req.encode("UTF-8"))
    resp = bytes()
    while len(chunk := cs.recv(1024)) > 0: #More data to come
        resp += chunk
    cs.close() #Close the socket.
    return resp.decode("UTF-8") #Yes I know not every site will use UTF-8, but it just needs to be consistent for this to work.

def hostnameSubdomainScan(ip, base, knownInvalid, sdList, threads = 4, sleepTime = 0.05, progressBar = True, additionalHeaders = "\n", path = "/"):
    """Scans for subdomains by requesting them from a specific IP address.
    Pros:
    + Assuming the IP is valid, this *will* find any subdomains on this server that are served by HTTP.
    Cons:
    - Even slower than DNS enumeration (usually).
    - Can only find HTTP domains.
    - If the IP is wrong, that won't be too obvious (the scan will just find nothing/nonsense results).
    - About as stealthy as throwing a grenade at the servers.
    - May get false positives/negatives (since we just check for a response code which differs from the response of knownInvalid)."""
    baseHeader = makeHostReq(ip, subdomain = knownInvalid + "." + base).split("\n")[0] #First line (which includes response code).
    found = queue.Queue()
    toProcess = queue.Queue()
    for sd in sdList:
        toProcess.put(sd + "." + base)
        
    def threadedRun():
        while not toProcess.empty(): #Additional error handling may be needed.
            s = toProcess.get(timeout=1)
            if not progressBar:
                InfoOutput.debug("Querying %s." % s)
            try:
                headers = makeHostReq(ip, subdomain = s)
                if headers.split("\n")[0] != baseHeader:
                    #We got something.
                    found.put(s)
            except:
                pass #Don't care for now.
            toProcess.task_done()
            time.sleep(sleepTime)
            
    for _ in range(threads):
        t = threading.Thread(target=threadedRun)
        t.start() #Begin making queries.
    #Print a cute progress bar if we've been asked to.
    if not progressBar:
        #Just join.
        toProcess.join()
    else:
        target = len(sdList)
        targetLen = len(str(target)) #Size to leftpad the "items remaining" bar to.
        while (remaining := toProcess.qsize()) > 0:
            InfoOutput.info("Done %s/%i." % (str(target - remaining).rjust(targetLen, "0"), target), end = "\r")
            time.sleep(0.1)
    res = set()
    while not found.empty():
        res.add(found.get())
    return res
    
class InfoOutput:
    
    outputTarget = None
    useDebug = False
    useColour = False
    
    @staticmethod
    def debug(msg, end = "\n"):
        if not InfoOutput.useDebug:
            return #Don't output debug stuff.
        template = "\x1b[2;37mDEBUG: %s\x1b[0m" if InfoOutput.useColour else "DEBUG: %s"
        print(template % msg, end = end, file = InfoOutput.outputTarget)
    
    @staticmethod
    def info(msg, end = "\n"):
        template = "\x1b[0;36mINFO: %s\x1b[0m" if InfoOutput.useColour else "INFO: %s"
        print(template % msg, end = end, file = InfoOutput.outputTarget)
    
    @staticmethod
    def success(msg, end = "\n"):
        template = "\x1b[1;32mSUCCESS: %s\x1b[0m" if InfoOutput.useColour else "SUCCESS: %s"
        print(template % msg, end = end, file = InfoOutput.outputTarget)
    
    @staticmethod
    def fail(msg, end = "\n"):
        template = "\x1b[1;33mFAIL: %s\x1b[0m" if InfoOutput.useColour else "FAIL: %s"
        print(template % msg, end = end, file = InfoOutput.outputTarget)
    
    @staticmethod
    def critical(msg, end = "\n"):
        template = "\x1b[1;31mCRITICAL: %s\x1b[0m" if InfoOutput.useColour else "CRITICAL: %s"
        print(template % msg, end = end, file = InfoOutput.outputTarget)
    
    

#Temporary (add a way to specify a target, and general commandline interface)
#print(dnsSubdomainScan(getList("domains.txt"), BASE, sleepTime= 0.01, threads = 8))
#makeHostReq(0, "completely-invalid-hostname")
#print("\n%s" % str(hostnameSubdomainScan("185.150.190.185", "hellominers.com", os.urandom(32).hex(), ["a", "b", "play", "c", "d"], threads = 1)))
parser = argparse.ArgumentParser()
#Add the scan method arguments
parser.add_argument("-c", "--certificate", help="Scans for alternative subdomains on the SSL certificate.", action="store_true")
parser.add_argument("-C", "--force-certificate", help="As with -c, but fail if the method failed for whatever reason.", action="store_true")

parser.add_argument("-d", "--dns", help="Enumerate subdomains from a wordlist by requesting from a DNS server.", action="store_true")
parser.add_argument("-D", "--force-dns", help="As with -d, but fail if the method failed for whatever reason.", action="store_true")

parser.add_argument("-i", "--iphost", help="Enumerate subdomains from a wordlist using HEAD requests at a specific IP.", action="store_true")
parser.add_argument("-I", "--force-iphost", help="As with -i, but fail if the method failed for whatever reason.", action="store_true")

parser.add_argument("-t", "--threads", help="How many threads to use for DNS and IPHost scans. Defaults to 1 if unspecified.", type=int, default=1)

parser.add_argument("-v", "--verbose", help="Gives more verbose output.", action="store_true")
parser.add_argument("-n", "--no-colour", help="Disables ANSI colour code output. Useful on Windows.", action="store_true")
parser.add_argument("--ignore-tld", help="Ignore top-level domains when outputting final output. Useful if being used in a script.", action="store_true")
parser.add_argument("--ignore-wildcard", help="Ignore wildcard domains in final output. Also useful if being used in a script.", action="store_true")

parser.add_argument("--target-host", help="Specifies the target base hostname. Required for all scans.", required = True)
parser.add_argument("--target-ip", help="Specifies a target IP. Required for IPHost scans.")

res = parser.parse_args()

#Set up some output variables.
InfoOutput.useDebug = res.verbose
InfoOutput.useColour = not res.no_colour
InfoOutput.outputTarget = sys.stdout if sys.stdout.isatty() else sys.stderr #Output on stderr if our actual output is being piped. (isatty() is false on pipe)
if InfoOutput.useDebug:
    InfoOutput.debug("Verifying output types...")
    InfoOutput.debug("Debug")
    InfoOutput.info("Info")
    InfoOutput.success("Success")
    InfoOutput.fail("Fail")
    InfoOutput.critical("Critical")

found = set()

if res.certificate or res.force_certificate:
    #Do a certificate based scan, if we have a hostname.
    fail = False
    if not res.target_host:
        InfoOutput.fail("No hostname specified for SSL certificate scan! Please specify one with --target-host!")
        fail = True
    else:
        InfoOutput.info("Running SSL certificate scan...")
        try:
            sslCertScanResults = getAltNamesOnCert(res.target_host) - {res.target_host,}
            for sd in sslCertScanResults:
                if sd.startswith("*"):
                    InfoOutput.info("Found domain wildcard %s. Try using DNS based enumeration to find out what the wildcard can represent." % sd)
                else:
                    InfoOutput.success("Found subdomain %s." % sd)
                    found.add(sd) #Adds the subdomain to our final results set.
            if len(sslCertScanResults) == 0:
                InfoOutput.fail("No extra subdomains found on the SSL certificate. This is quite a strong sign that no (secure) subdomains exist.")
        except (Exception,KeyboardInterrupt) as e:
            #Something for sure went wrong.
            InfoOutput.fail("SSL certificate scan failed: %s." % e)
            fail = True
    if fail and res.force_certificate: #Something went wrong at some point.
        #Terminate with a non-zero status code
        InfoOutput.critical("SSL certificate scan failed and it was triggered using -C, so exiting.")
        quit(1)
        
if res.dns or res.force_dns:
    #Do a DNS based scan. Basically identical to SSL certificate code.
    fail = False
    if not res.target_host:
        InfoOutput.fail("No hostname specified for DNS scan! Please specify one with --target-host!")
        fail = True
    else:
        InfoOutput.info("Running DNS scan...")
        try:
            dnsScanResults = dnsSubdomainScan(getList("domains.txt"), res.target_host, progressBar = not res.verbose, threads = res.threads) - {res.target_host,}
            for sd in dnsScanResults:
                InfoOutput.success("Found subdomain %s." % sd)
                found.add(sd) #Adds the subdomain to our final results set.
            if len(dnsScanResults) == 0:
                InfoOutput.fail("No extra subdomains found. This means there are either no externally accessible subdomains, or that the wordlist isn't broad enough. If you are 100% sure that subdomains exist, try a hostname scan.")
        except (Exception,KeyboardInterrupt) as e:
            #Something for sure went wrong.
            InfoOutput.fail("DNS scan failed: %s." % e)
            fail = True
    if fail and res.force_dns: #Something went wrong at some point.
        #Terminate with a non-zero status code
        InfoOutput.critical("DNS scan failed and it was triggered using -D, so exiting.")
        quit(1)
        
if res.iphost or res.force_iphost:
    #Do an IP-Host scan. This is basically the same code again (but painfully slow).
    fail = False
    if not res.target_ip:
        InfoOutput.fail("No IP specified for IPHost scan! Please specify one with --target-ip!") #TODO: Allow a target host to be specified.
        fail = True
    elif not res.target_host:
        InfoOutput.fail("No base hostname specified for IPHost scan! Please specify one with --target-host!")
        fail = True
    else:
        InfoOutput.info("Running IPHost scan. This may take a very long time (especially with a large wordlist).")
        try:
            iphScanResults = hostnameSubdomainScan(res.target_ip, res.target_host, os.urandom(32).hex(), getList("domains.txt"), progressBar = not res.verbose, threads = res.threads) - {res.target_host,}
            for sd in iphScanResults:
                InfoOutput.success("Found subdomain %s." % sd)
                found.add(sd) #Adds the subdomain to our final results set.
            if len(dnsScanResults) == 0:
                InfoOutput.fail("No extra subdomains found! This means that this server does not host any HTTP-accessible subdomains from our wordlist, assuming the scan worked as expected.")
        except (Exception,KeyboardInterrupt) as e:
            #Something for sure went wrong.
            InfoOutput.fail("IP-host scan failed: %s." % e)
            fail = True
    if fail and res.force_iphost: #Something went wrong at some point.
        #Terminate with a non-zero status code
        InfoOutput.critical("IP-Host scan failed and it was triggered using -I, so exiting.")
        quit(1)

#Look at our set of results, do optional final clean-up and then output them.
InfoOutput.info("Subdomains found: ")
output = 0
for dom in found:
    if res.ignore_wildcard and dom.startswith("*"):
        #Wildcard domain and we're ignoring them, skip
        continue
    elif res.ignore_tld and res.target_host not in dom:
        #Seperate TLD, ignore.
        continue
    InfoOutput.success(dom)
    if not sys.stdout.isatty():
        #Output to pipe
        print(dom)
    output += 1
if output == 0:
    InfoOutput.fail("No subdomains found.")
elif output == 1:
    InfoOutput.success("Found 1 subdomain.")
else:
    InfoOutput.success("Found %i subdomains." % output)
