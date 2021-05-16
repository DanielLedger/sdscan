# sdscan - Subdomain Scanner
This is a very simple little scanner I wrote in order to discover/enumerate subdomains when provided with a primary domain name.

It's been used precisely never outside of testing, so I'm not sure how practical it is, but it still works nonetheless.

## Modes of operation

This tool has three different modes of operating, all of which can be used either independantly or together. Each mode has a lowercase and uppercase option:
the lowercase option will attempt to run the scan, but if it fails the tool will move on; the uppercase option will abort the program if the scan fails for whatever reason

The three modes are:

### SSL certificate scanning

SSL certificates cost money, so in order to maximise efficiency, they can have alternative domains listed on them. Since buying yourself 15 certificates is pricy,
it's easier to simply add a subdomain onto one you already own, so that the certificate is valid for both. By connecting to the server and requesting it's SSL
certificate, we can then just read off the domains it is valid for. This has the advantage of being very, very quick in comparison, but can't deal with wildcard certificates:
if the certificate simply says "*.\<domain\>.com" that's not much use: it only proves that subdomains exist, without telling you what they are.

#### Option: -c or -C

### DNS querying

This is the method most tools will use, and is the most obvious: we take a wordlist (currently 10k common subdomains, being able to customise the list is TODO) and for each,
we request a DNS server to lookup "\<word\>.\<domain\>". If the DNS server returns results, we know that subdomain is valid. If it returns NXDOMAIN, we know it isn't valid.
This will find any subdomains that exist in the wordlist, and since humans are predicatable, chances are that the gitlab page will be "git.\<domain\>" etc. etc. etc.

This won't find any subdomains that aren't on the wordlist, and is pretty obvious if someone is able to view network traffic (especially if there's no DNS over HTTPS). You may also
get ratelimited by the server you're querying from.

#### Option: -d or -D

### "Host" HTTP Header

Note: this is called "IPHost" scanning by the tool, since unhelpfully "Host", "HTTP" and "Header" all start with a "h", which would collide with the the "-h" help option.


This is a less usual method of enumeration, and probably the least useful, however it is useful in one, pretty specific scenario: if you suspect subdomains exists, however
cannot reliably check them, because they are only listed on an internal DNS server, which you can't connect to. This method works by sending HEAD HTTP requests to a specific
IP address, and comparing the status code to a domain which is almost certainly invalid (due to it's being a 32 byte random sequence). The theory is that valid hostnames will return
different status codes to invalid ones (e.g. a 307 vs 404 code), thus allowing valid hosts to be extracted.

#### Option: -i or -I

## Other commandline options

#### Option: -v or --verbose
This outputs more debug info to the terminal, as well as the normal messages. Debug info probably needs expanding.

#### Option: -t or --threads
This controls how many threads are used by DNS and IPHost scans. Note that due to Python's Global Interpreter Lock, this only helps if the bottleneck is network latency:
if the bottleneck is somehow processing time then more threads won't help. Defaults to 1 if unspecified.

#### Option: -n or --no-colour
Note: Yes, this is the British spelling of colour, with a U.


Disables ANSI colour codes in the output. Useful if these trip your terminal up.

#### Option: --ignore-tld and --ignore-wildcard

These two options filter out top-level domains and wildcarded subdomains from the output, respectively. These are only useful when using a certificate scan (-c/-C) since only that
scan can actually return either.

#### Option: --target-host

Required. This is your target, and is needed for all three of the scan types. This should be inputted without the "https://" and without the "www": i.e. input "github.com" not "https://www.github.com".

#### Option: --target-ip

Required for IPHost scan: this is the IP that you wish to send HTTP HEAD requests to. Port is currently hardcoded at port 80. TODO make port configurable and make this resove from target-host if unspecified.

## Usage in scripts

This can be used in scripts quite easily: if the output is being piped, the script will automatically detect that and output a simple, newline delimited list of any subdomains it finds, whilst outputting info messages
to STDERR so that they can still be read.

