#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cFire.py:    [c]loud[F]lare [ire] - IP discovery for domains behind Cloudflare
# =============================================================================
# This program utilizes several known methods for the discovery of IPs behind
# the popular Cloudflare WAF. It should be noted, that some of these methods
# may result in false positives. Researchers should confirm the results before
# moving forward. For educational purposes only.
#
# Compatible for both python 2.x and python 3.x.
#
# Pre-requisites:   Check ./requirements.txt
#
# Pre-req notes:    It should be noted that older versions of the 'requests'
#                   module has a bug in handling download streams. You should
#                   make sure that you upgrade your packages caches:
#
#                   Debian/Ubuntu:  apt-get update
#                   FreeBSD:        pkg update
#
#                   Once you update your packages cache, use the aforementioned
#                   commands to install the required modules.
#
# Methods used:     CrimeFlare database lookup [DONE]
#                   DNS Record enumeration [DONE]
#
# Rhino Security Labs //@hxmonsegur

# Standard libs
import sys
import os
import stat
import time

# Wrapper to handle CrimeFlare archives
from lib.cron import cflareupdate

# Use Sublist3r for its sweet search engine enumeration code
from lib.Sublist3r import sublist3r

# Import Cloudflare network ranges
from lib.cloudflare import ranges

# Use subbrute for DNS bruteforcing
from lib.subbrute import subbrute

# For command line argument handling
import argparse

# For use in handling URI
try:
    from urlparse import urlparse
except:
    # This is a python3 portability fix
    import urllib.parse as urlparse

# Import required modules [third party]
try:
    import requests
except:
    print("[*] You will need to install requests for python2/3")
    raise SystemExit

try:
    import netaddr
except:
    print("[*] You will need to install netaddr for python2/3")
    raise SystemExit

try:
    import sqlite3
except:
    print("[*] You will need to install sqlite3 for python2/3")
    raise SystemExit

try:
    import dns.resolver
except:
    print("[*] You will need to install dnspython(3) for python2/3")
    raise SystemExit

try:
    import ssdeep
except:
    print("[*] You will need to install ssdeep for python2/3")
    raise SystemExit

# Create global lists and dictionaries for use throughout
#_found = []
_foundns = []
_nsdict = {}
_countrydict = {}
_foundips = []

def list_uniq(seq):
    # Fastest way I've seen to uniq, does not respect order. Who cares.
    return list(set(seq))


def clean_uri(targets):
    # Late night hackathon, don't judge. LOL
    _TMPLST = []
    for TARGET in targets:
        URI = urlparse(TARGET)
        if URI.netloc == '':
            if URI.path.find(':') != -1:
                _TMPLST.append(URI.path.split(':')[0])
            elif URI.scheme != '':
                # Cheap fix for urlparse confusion bug. e.g. domain.com:port/path = scheme=domain.com
                _TMPLST.append(URI.scheme)
            elif URI.path.find('/') != -1:
                _TMPLST.append(URI.path.split('/')[0])
            else:
                _TMPLST.append(URI.path)
        elif URI.netloc.find(':') != -1:
            _TMPLST.append(URI.netloc.split(':')[0])
        else:
            _TMPLST.append(URI.netloc)
    return list_uniq(_TMPLST)


def check_cf_ranges(IP):
    return any(
        netaddr.IPAddress(IP) in netaddr.IPNetwork(CIDR)
        for CIDR in ranges.CF_RANGES
    )


def dns_resolver(hostname):
    # We could use socket.dns_resolver, but we're already using dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    try:
        return resolver.query(hostname, 'A')[0].to_text()
    except:
        return False


def query_crimeflare_database(cfdbpath, domain=None, ip=None, created=None, nameservers=None):
    """Queries CrimeFlare database"""
    # Setup query
    if domain:
        # Search by domain
        _query = f"SELECT * FROM cfdb WHERE domain='{domain}'"
    elif ip:
        # Search records for matching IP addresses
        #_query = "SELECT * FROM cfdb WHERE ip='{}' AND domain!='{}'".format(ip, domain)
        _query = f"SELECT * FROM cfdb WHERE ip='{ip}'"
    elif created:
        # Using this could be beneficial later on with implementation of analytics, graphs, etc
        _query = f"SELECT * FROM cfdb WHERE created='{created}'"
    elif nameservers:
        # Searching by nameserver may identify domains by same user
        _query = f"SELECT * FROM cfdb WHERE nameservers='{nameservers}' AND domain!='{domain}'"


    # Connect to database
    try:
        con = sqlite3.connect(f'{cfdbpath}/cf.db')

        # Execute our query
        with con:
            cur = con.cursor()
            try:
                cur.execute(_query)
                rows = cur.fetchall()
            except:
                print('[-] Error connecting to database. Run -u|--update to get update databases')
                raise SystemExit

    except(sqlite3.OperationalError):
        print("[-] CrimeFlare database not found. Install with -u|--update")
        raise SystemExit
    except Exception as err:
        print(f"[-] Exception raised: {err}")
        raise SystemExit
    finally:
        con.close()

    # Return data to main
    return rows if rows != [] else False

def printlog(message, logpath=False):
    # I think the logging module is great, but this will be used for the time being
    # Eventually, we will want to write out multiple output formats: xml,json, etc
    if logpath:
        # Next iteration of project will include a more secure logger,
        # for now, we will just write results to a file directly.

        # flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        # mode = stat.S_IRUSR | stat.S_IWUSR
        # umask_original = os.umask(0)
        # try:
        #     fdesc = os.open(logpath, flags, mode)
        # # except(OSError):
        # #     print("[-] Log file exists. Remove it, or change log filename")
        # #     raise SystemExit
        # finally:
        #     os.umask(umask_original)
        # with os.fdopen(fdesc, 'w') as fout:
        with open(logpath, 'a') as fout:
            fout.write(f"{message}\n")
    print(f"{message}")


def crimeflare_db_lookup(target, cfdbpath, logpath=False):
    if TARGET := dns_resolver(target):
        if check_cf_ranges(TARGET):
            printlog(f"[*] {target} ({TARGET}) is hosted on Cloudflare network", logpath)
        else:
            printlog(
                f"[!] {target} ({TARGET}) is NOT hosted on Cloudflare network.",
                logpath,
            )

            if not _foundips.__contains__(TARGET):
                _foundips.append(TARGET)
    else:
        printlog(f"[-] Could not resolve domain: {target}", logpath)
    if _results := query_crimeflare_database(cfdbpath, domain=target):
        print(f"[*] Found {_results.__len__()} records:")
        _found = []
        for result in _results:
            _domain, _ip, _created, _nameservers, _country = result
            printlog(
                f'Domain: {_domain}   IP: {_ip}  When: {_created}    Nameservers:    {_nameservers}  Country:    {_country}',
                logpath,
            )

            if not _found.__contains__(_ip):
                _found.append(_ip)
            if not _foundips.__contains__(_ip):
                _foundips.append(_ip)
                    # if not _foundns.__contains__(_nameservers):
                    #     _foundns.append(_nameservers)

        # Lookup domains pointing to discovered IPs
        if _found != []:
            printlog('[*] Checking if other domains are hosted on discovered IPs', logpath)
            for _ip in _found:
                _ipresults = None
                if _ipresults := query_crimeflare_database(cfdbpath, ip=_ip):
                    for ipresult in _ipresults:
                        _domain, _ip, _created, _nameservers, _country = ipresult
                        if _domain != target:
                            printlog(
                                f'Domain: {_domain}   IP: {_ip}  When: {_created}    Nameservers:    {_nameservers}  Country:    {_country}',
                                logpath,
                            )

                else:
                    printlog('[*] No other domains pointing to discovered IPs', logpath)
    else:
        printlog(f"[-] No records found for {target}", logpath)
        #
        # # Lookup domains using same nameservers as target
        # if _foundns != []:
        #     for _ns in _foundns:
        #         _nsresults = query_crimeflare_database(cfdbpath, nameservers=_ns)
        #         if _nsresults:
        #             print('[*] Other domains pointing to nameservers ({}) via CF'.format(_ns))
        #             for nsresult in _nsresults:
        #                 _domain, _ip, _created, _nameservers, _country = nsresult
        #                 print('Domain: {}   IP: {}  When: {}    Nameservers:    {}  Country:    {}'.format(_domain, _ip, _created, _nameservers, _country))

def sublister_engine_query(domain, cfdbpath, timeout, logpath=False):
    print("[*] Starting search engine scan")
    try:
        eresults = sublist3r.main(domain, 8, False, False, True, False, False, None)
    except UnboundLocalError:
        printlog(
            f"[-] Search engine scan ran into rate limiting issues. Scan {domain} again later",
            args.log,
        )

    if eresults != []:
        print("[*] Iterating over search engine results")
        for eresult in eresults:
            # Set a timeout to avoid search engine throttling
            printlog(f"[*] Engine result: {eresult}", logpath)
            crimeflare_db_lookup(eresult, cfdbpath, logpath)

def ssdeepcompare(target, IP):
    try:
        ss_target = requests.get('http://{}/'.format(target))
        ssdeep_target_fuzz = ssdeep.hash(ss_target.text)
        print target, ssdeep_target_fuzz
        content = requests.get('https://{}'.format(IP), verify=False, timeout = 5, headers = {'Host': target})
        ssdeep_fuzz = ssdeep.hash(content.text)
        print IP, ssdeep_fuzz
        print "ssdeep score for", IP, "is", ssdeep.compare(ssdeep_target_fuzz, ssdeep_fuzz)
    except(requests.exceptions.ConnectionError):
        print "cant connect to", IP

def main():
    try:
        # Configure argument parser
        parser = argparse.ArgumentParser(
            prog='cfire.py',
            description='IP discovery tool for domains behind Cloudflare',
            epilog='For educational purposes only. @hxmonsegur//RSL',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('-t', '--target', help='Target')
        parser.add_argument('-f', '--targets', help='File containing targets list')
        parser.add_argument('-u', '--update', help='Update CrimeFlare database', action='store_true')
        parser.add_argument('-d', '--updatehost', help='Host serving CrimeFlare files', default='http://crimeflare.net:82/domains')
        parser.add_argument('-p', '--cfdbpath', help='Path to cfdb directory', default='cfdb')
        parser.add_argument('-i', '--timeout', help='Set timeout between bulk search engine scans', default=1)
        # parser.add_argument('-b', '--brute', help='Activate brute force module', action='store_true')
        parser.add_argument('-e', '--engines', help='Activate search engines module', action='store_true')
        parser.add_argument('-l', '--log', help='Set log location. Default: [disabled]', default=False)
        # parser.add_argument('-s', '--ssdeep', help='Specify domain/URL for ssdeep fuzzy comparison', action='store_true')
        parser.add_argument('--ip', help='Searches CrimeFlare archives domains pointing to specified IP')

        # Parse arguments
        try:
            args = parser.parse_args()
        except:
            #parser.print_help()
            print("[-] Please refer to -h|--help for help")
            raise SystemExit

        if len(sys.argv) < 2:
            parser.print_help()
            raise SystemExit

        if args.update:
            cflareupdate.updateCFdb(cfdbpath=args.cfdbpath, updatehost=args.updatehost)

        printlog(f'[*] Start: {time.strftime("%c")}', args.log)

        if args.ip:
            if IPLookup := query_crimeflare_database(
                cfdbpath=args.cfdbpath, ip=args.ip
            ):
                for rets in IPLookup:
                    IPLDom, IPLIP, IPLDate, IPLNS, IPLCountry = rets
                    printlog(
                        f"[*] IP: {IPLIP} seen hosting {IPLDom} on {IPLDate} via NS ({IPLNS}) ({IPLCountry})",
                        args.log,
                    )


            else:
                printlog(f"[-] {args.ip} was not discovered in archives.", args.log)
        if args.target:
            print("[*] Looking target up on CrimeFlare database")
            crimeflare_db_lookup(args.target, args.cfdbpath, args.log)
            if args.engines:
                sublister_engine_query(args.target, args.cfdbpath, args.timeout, args.log)
            # if args.ssdeep:
            #     if _foundips != []:
            #             for IP in _foundips:
            #                 ssdeepcompare(args.target, IP)

        # Played with subbrute's DNS brute, but it was giving me some serious throttling issues
        # Need to come back to it.
        # if args.brute:
        #     print("[*] Starting brute force")
        #     record_type = False
        #     path_to_file = os.path.dirname(os.path.realpath(__file__))
        #     subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
        #     resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
        #     subbrute.print_target(args.target, query_type="A", subdomains=subs, resolve_list=resolvers)
        #     #print bruteforce_list



        if args.targets:
            _TARGETS = []
            # Add our list of targets to the _TARGETS list
            try:
                with open(args.targets, 'r') as targets:
                    _TARGETS = [URL.strip() for URL in targets.readlines()]
            except(IOError):
                print("[-] Problem with opening targets file. Please try again.")
                raise SystemExit

            # We do our best to parse domains from provided list
            _TARGETS = clean_uri(_TARGETS)

            for domain in _TARGETS:
                # Magic goes here
                print(f"[*] Looking up {domain}")
                crimeflare_db_lookup(domain, args.cfdbpath, args.log)
                if args.engines:
                    time.sleep(int(args.timeout))
                    sublister_engine_query(domain, args.cfdbpath, args.timeout, args.log)
                if args.ssdeep and _foundips != []:
                    for IP in _foundips:
                        ssdeepcompare(domain, IP)
                        _foundips.remove(IP)

        printlog(f'[*] Complete: {time.strftime("%c")}', args.log)

    except(KeyboardInterrupt):
        print("[!!] Program was interrupted (ctrl+c). Exiting...")
        raise SystemExit

if __name__ == "__main__":
    main()
