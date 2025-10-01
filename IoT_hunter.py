"""
IoT_hunter is a tool that prompts the user via a menu-based
interface, and will generate Suricata 5+ and Snort 2.9.x compatible
rules based on the answers provided. The program also features CSV input
to submit data in bulk, and recieve rules in bulk. Please see:
IoT_hunter.py -h
For more details on various flags that control
input and output settings.
"""
#!/usr/bin/env python3
__author__ = "Tony Robinson"
__maintainer__ = "Tony Robinson / trobinson@emergingthreats.net"
__version__ = "3.2.2"


import argparse
import csv
import re
import textwrap
from datetime import datetime
import sys
import requests
import urllib3

#I don't want to see warnings that I had to disable certificate verifcation when talking to archive.org
urllib3.disable_warnings(category = urllib3.exceptions.InsecureRequestWarning)

##Define wayback machine accesskey and secretkey here
##Don't know what this is? Visit archive.org, create an account, log in, then visit:
## https://archive.org/account/s3.php
wayback_machine_creds = "[access_key]:[secret_key]"

#This class can be used to underline, bold, or color string output using
#terminal control characters. If used, ENDC must be used to terminate
#the modified text
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

##Begin stapled musketeer logic. Most of this work was by JEC and Others before me.
# By extension, I don't know how it works really well, because I'm not great with python, and the comments are...
# kinda sparse. If you're seeing this, you need to be extremely aware that there is a possibility that
# musketeer can and does convert rules incorrectly, and even if the syntax is "valid" that having a human do a once over
# is recommend. Even better if you have a pcap of what you want and can test the musketeer-generated rule
# to confirm that it alerts as you require it to.
def pcre_fix(pcre, flag_to_add):
    pcre_flag_search = re.search(r'(\/[a-zA-Z]*";)$', pcre.strip())
    the_old_flags = re.search(r'\/([a-zA-Z]*)', pcre_flag_search.group(0))
    the_new_flags = "/" + flag_to_add + the_old_flags.group(1) + '";'
    pcre = pcre.replace(pcre_flag_search.group(0), the_new_flags)
    return pcre

def buffer_reordering(item, buffer):
    re_offset = re.compile(r'offset:(\d+|\w+);')
    re_distance = re.compile(r'distance:(\d+|\w+);')
    re_depth = re.compile(r'depth:(\d+|\w+);')
    re_within = re.compile(r'within:(\d+|\w+);')
    re_nocase = re.compile(r'nocase;')
    re_isdataat = re.compile(r'isdataat:([^\;]+);')
    re_fast_pattern = re.compile(r'fast_pattern(?:only|:[0-9]+,[0-9]+)?;')


    pcre_content = re.findall(r'!?\x22[^\x22]+\x22;', item)
    #print("buffer_reordering,pcre_content: {}".format(pcre_content))
    #rebuilt_base = "content:{} {}".format(pcre_content[0], buffer.strip()).strip()
    rebuilt_base = f"content:{pcre_content[0]} {buffer.strip().strip()}"
    #print("buffer_reordering,rebuilt_base: {}".format(rebuilt_base))


    if re.search(re_offset, item):
        found_offset = re.search(re_offset, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_offset.group(0))
        rebuilt_base = f"content:{rebuilt_base} {found_offset.group(0)}"

    if re.search(re_depth, item):
        found_depth = re.search(re_depth, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_depth.group(0))
        rebuilt_base = f"{rebuilt_base} {found_depth.group(0)}"
    if re.search(re_distance, item):
        found_distance = re.search(re_distance, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_distance.group(0))
        rebuilt_base = f"{rebuilt_base} {found_distance.group(0)}"
    if re.search(re_within, item):
        found_within = re.search(re_within, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_within.group(0))
        rebuilt_base = f"{rebuilt_base} {found_within.group(0)}"
    if re.search(re_nocase, item):
        found_nocase = re.search(re_nocase, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_nocase.group(0))
        rebuilt_base = f"{rebuilt_base} {found_nocase.group(0)}"
    if re.search(re_fast_pattern, item):
        found_fast_pattern = re.search(re_fast_pattern, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_fast_pattern.group(0))
        rebuilt_base = f"{rebuilt_base} {found_fast_pattern.group(0)}"
    if re.search(re_isdataat, item):
        found_isdataat = re.search(re_isdataat, item)
        #rebuilt_base = "{} {}".format(rebuilt_base, found_isdataat.group(0))
        rebuilt_base = f"{rebuilt_base} {found_isdataat.group(0)}"
    #print(rebuilt_base)
    return rebuilt_base

def snort_dns(rule):
    """Converts a Snort DNS rule into a Snort UDP rule with DNS payload signature.

    This function takes a Snort DNS rule string and modifies it to represent a
    Snort UDP rule, specifically targeting DNS traffic. It replaces the DNS
    alert configurations with equivalent UDP configurations and generates a
    DNS payload signature based on the content of the rule.

    Args:
        rule (str): The original Snort DNS rule to be converted.

    Returns:
        str: The converted Snort UDP rule with DNS payload signature.
        False: If the rule cannot be processed or if multiple content fields
            are found, indicating that manual review is needed.

    Example:
        >>> snort_dns('alert dns any any -> $HOME_NET any (msg:"Test"; content:"example.com"; classtype:trojan-activity;)')
        'alert udp any 53 -> $HOME_NET any content:"|07|example|03|com|00|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; nocase; )'
    """

    try:
        snort_rule_begin = re.search('^alert.+msg:[^;]+;', rule.strip())
    except Exception as e:
        raise Exception(f'unable to parse the rule beginning - {e}')
    snort_rule_end = re.search('(?:reference:.+)?classtype:.+$', rule)

    snort_rule_front = snort_rule_begin.group(0)
    snort_rule_backend = snort_rule_end.group(0)

    dns_rule_guts = rule.replace(snort_rule_front, '')
    dns_rule_guts = rule.replace(snort_rule_backend, '')

    #alert dns any any -> $HOME_NET any
    if 'alert dns any any -> $HOME_NET any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns any any -> $HOME_NET any', 'alert udp any 53 -> $HOME_NET any')
    #alert dns any any -> any any
    elif 'alert dns any any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns any any -> any any', 'alert udp any any -> any 53')
    #alert dns $HOME_NET any -> any any
    elif 'alert dns $HOME_NET any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns $HOME_NET any -> any any', 'alert udp $HOME_NET any -> any 53')
    #alert dns $HOME_NET any -> any 53
    elif 'alert dns $HOME_NET any -> any 53' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns $HOME_NET any -> any 53', 'alert udp $HOME_NET any -> any 53')
    #alert dns $HOME_NET any -> $EXTERNAL_NET any
    elif 'alert dns $HOME_NET any -> $EXTERNAL_NET any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns $HOME_NET any -> $EXTERNAL_NET any', 'alert udp $HOME_NET any -> $EXTERNAL_NET 53')
    #alert dns $HTTP_SERVERS any -> any any
    elif 'alert dns $HTTP_SERVERS any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns $HTTP_SERVERS any -> any any', 'alert udp $HTTP_SERVERS 53 -> any any')
    #alert dns $EXTERNAL_NET any -> any any
    elif 'alert dns $EXTERNAL_NET any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert dns $EXTERNAL_NET any -> any any', 'alert udp $EXTERNAL_NET 53 -> any any')
    #alert dns catchall
    else:
        snort_rule_front = snort_rule_front.replace('alert dns', 'alert udp')

    content_count_search = re.findall('content:"', dns_rule_guts)
    num_contents = len(content_count_search)
    if num_contents == 1:
        content_search = re.search('content:"([^"]+)"', dns_rule_guts)
        domain = content_search.group(1)
        levels = domain.split('.')
        for level in levels:
            if len(level) == 0:
                levels.remove(level)
        domain_sig = ' content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"'
        for level in levels:
            #domain_sig += '|%s|%s' % (hex(len(level)).lstrip('0x').zfill(2),level)
            domain_sig += f'|{hex(len(level)).lstrip('0x').zfill(2)}|{level}'
        if 'endswith;' in dns_rule_guts or 'isdataat:!1,relative' in dns_rule_guts:
            domain_sig += '|00|";'
        else:
            domain_sig += '";'
        if 'nocase;' in dns_rule_guts:
            domain_sig += ' nocase; '
        fresh_rule = snort_rule_front + domain_sig + snort_rule_backend
    else:
        ### TODO: LOG AS WARNING AND RESOLVE
        print("AHHH We'll get to this in a bit, calm down.")
        return False

    #suri5 rule rollback - update bsize;
    if 'bsize:' in fresh_rule:
        fresh_rule = re.sub(r'bsize:(\d+);', 'depth:\\1; isdataat:!1,relative;', fresh_rule)

    #check the rule again for any double spaces
    fresh_rule = re.sub(r';\s{2,}', '; ', fresh_rule)

    #clean up some spaces for readability for whitespace
    if '| ' in fresh_rule:
        fresh_rule = fresh_rule.replace("| ", " 20|")
    if ' ";' in fresh_rule:
        fresh_rule = fresh_rule.replace(' ";', '|20|";')
    if 'content:" ' in fresh_rule:
        fresh_rule = fresh_rule.replace('content:" ', 'content:"|20|')

    proback_rule = re.sub('msg:"[^"]+"; ','', fresh_rule) #remove message
    proback_rule = re.sub(r'\s*classtype:.+$',')', proback_rule) #remove end starting with classtype
    proback_rule = re.sub(r'\s*reference:.+$',')', proback_rule) #remove end starting with reference
    proback_rule = re.sub(r'\s*metadata:.+$',')', proback_rule) #remove metadata

    return proback_rule


def snort_tls_sni(rule):
    """Converts a Snort TLS rule into a Snort TCP rule for TLS SNI inspection.

    This function modifies a Snort rule targeting TLS traffic by converting
    it into a rule for TCP traffic with a focus on inspecting the Server
    Name Indication (SNI) in TLS handshakes. The rule is adjusted to monitor
    TCP traffic on port 443 and includes the necessary content matching for
    SNI.

    Args:
        rule (str): The original Snort TLS rule to be converted.

    Returns:
        str: The converted Snort TCP rule with SNI inspection criteria.
        False: If the rule cannot be processed or if multiple content fields
            are found, indicating that manual review is needed.

    Example:
        >>> snort_tls_sni('alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; content:"example.com"; classtype:trojan-activity;)')
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 content:"|16|"; depth:1; content:"|01|"; distance:4; content:"|00 00 07|example.com"; distance:0; )'
    """

    try:
        snort_rule_begin = re.search('^alert.+msg:[^;]+;', rule.strip())

    except Exception as e:
        raise Exception(f"Unable to parse the rule beginning - {e}")
    snort_rule_end = re.search('(?:reference:.+)?classtype:.+$', rule)

    snort_rule_front = snort_rule_begin.group(0)
    snort_rule_backend = snort_rule_end.group(0)

    tls_sni_rule_guts = rule.replace(snort_rule_front, '')
    tls_sni_rule_guts = rule.replace(snort_rule_backend, '')

    #alert tls $HOME_NET any -> $EXTERNAL_NET any
    if 'alert tls $HOME_NET any -> $EXTERNAL_NET any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls $HOME_NET any -> $EXTERNAL_NET any', 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443')
    #alert tls any any -> any any
    elif 'alert tls any any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls any any -> any any', 'alert tcp any any -> any any')
    #alert tls $HOME_NET any -> $EXTERNAL_NET 443
    elif 'alert tls $HOME_NET any -> $EXTERNAL_NET 443' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls $HOME_NET any -> $EXTERNAL_NET 443', 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443')
    # alert tls $HOME_NET any -> any any
    elif 'alert tls $HOME_NET any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls $HOME_NET any -> any any', 'alert tcp $HOME_NET any -> any any')
    #alert tls catchall
    else:
        snort_rule_front = snort_rule_front.replace('alert tls', 'alert tcp')

    tls_sni_dotprefix_flag = 0
    if 'dotprefix;' in tls_sni_rule_guts:
        tls_sni_dotprefix_flag = 1

    content_count_search = re.findall('content:"', tls_sni_rule_guts)
    num_contents = len(content_count_search)
    if num_contents == 1:
        content_search = re.search('content:"([^"]+)"', tls_sni_rule_guts)
        domain = content_search.group(1)

        if tls_sni_dotprefix_flag:
            #domain_len_tlssni = '{:04x}'.format(len(domain))
            domain_len_tlssni = f'{len(domain):04x}'
            domain_len_tlssni_dec = int(domain_len_tlssni, 16)
            domain_len_tlssni_hex = '\\x' + '\\x'.join(domain_len_tlssni[i:i + 2] for i in range(0, len(domain_len_tlssni), 2))

            tls_sni_sig = f' content:"|16|"; content:"|01|"; within:8; content:"|00 00|"; distance:0; content:"|00|"; distance:4; within:1; byte_jump:2,0,relative, post_offset -{domain_len_tlssni_dec}; pcre:\"/^(?:{domain_len_tlssni_hex}|.\\x2e){re.escape(domain)}/R\"; content:\"{domain}\";'
        else:
            tls_sni_sig = ' content:"|16|"; depth:1; content:"|01|"; distance:4; content:"|00 00 '
            #tls_sni_sig += '%s|%s' % (hex(len(domain)).lstrip('0x').zfill(2),domain)
            tls_sni_sig += f'{(hex(len(domain))).lstrip('0x').zfill(2)}|{domain}'


        if 'endswith;' in tls_sni_rule_guts or 'isdataat:!1,relative' in tls_sni_rule_guts:
            tls_sni_sig = re.sub(r'(endswith|isdataat:\!1,relative|bsize:\d+);', '', tls_sni_sig)
        else:
            tls_sni_sig += '";'
        if 'fast_pattern;' in tls_sni_rule_guts:
            tls_sni_sig += '"; fast_pattern:only; '
        else:
            if 'nocase;' in tls_sni_rule_guts:
                tls_sni_sig += '"; nocase; distance:0; '
            else:
                tls_sni_sig += '"; distance:0; '

        fresh_rule = snort_rule_front + tls_sni_sig + snort_rule_backend
    else:
        return False


    #check the rule again for any double spaces
    fresh_rule = re.sub(r';\s{2,}', '; ', fresh_rule)

    #check the rule again for any double quote semi
    fresh_rule = re.sub('";";', '";', fresh_rule)

    #clean up some spaces for readability for whitespace
    if '| ' in fresh_rule:
        fresh_rule = fresh_rule.replace("| ", " 20|")
    if ' ";' in fresh_rule:
        fresh_rule = fresh_rule.replace(' ";', '|20|";')
    if 'content:" ' in fresh_rule:
        fresh_rule = fresh_rule.replace('content:" ', 'content:"|20|')

    proback_rule = re.sub('msg:"[^"]+"; ','', fresh_rule) #remove message
    proback_rule = re.sub(r'\s*classtype:.+$',')', proback_rule) #remove end starting with classtype
    proback_rule = re.sub(r'\s*reference:.+$',')', proback_rule) #remove end starting with reference
    proback_rule = re.sub(r'\s*metadata:.+$',')', proback_rule) #remove metadata

    return proback_rule


def cert_items(certstring):
    sig_string = ''
    c_items = re.findall('((?:CN?=|ST=|L=|OU?=).*?(?=(?:, |/)ST=|(?:, |/)L=|(?:, |/)OU?=|(?:, |/)CN?=|$))', certstring)
    for item in c_items:
        if "C=" in item:
            country = re.search('C=(.+)$', item)
            if country is None:
                country = ""
                country_len = '|00|'
                country_within = 1
            else:
                country = country.group(1)
                #country_len = '|{:02x}|'.format(len(country))
                country_len = f'|{len(country):02x}|'
                country_within = len(country_len + country) - 3
            #sig_string += 'content:"|06 03 55 04 06|"; distance:0; content:"{}{}"; distance:1; within:{}; '.format(country_len, country, country_within)
            sig_string += f'content:"|06 03 55 04 06|"; distance:0; content:"{country_len}{country}"; distance:1; within:{country_within}; '
            ## the distance:1 skips the type of string IA4string, PrintableString, UTF8String, etc, if we know what those are for the cert, we could include them here and come up with a single content for it.
        if "L=" in item:
            locality = re.search('L=(.+)$', item)
            if locality is None:
                locality = ""
                locality_len = '|00|'
                locality_within = 1
            else:
                locality = locality.group(1)
                #locality_len = '|{:02x}|'.format(len(locality))
                locality_len = f'|{len(locality):02x}|'
                locality_within = len(locality_len + locality) - 3
            #sig_string += 'content:"|06 03 55 04 07|"; distance:0; content:"{}{}"; distance:1; within:{}; '.format(locality_len, locality, locality_within)
            sig_string += f'content:"|06 03 55 04 07|"; distance:0; content:"{locality_len}{locality}"; distance:1; within:{locality_within}; '

        if "ST=" in item:
            state = re.search('ST=(.+)$', item)
            if state is None:
                state = ""
                state_len = '|00|'
                state_within = 1
            else:
                state = state.group(1)
                #state_len = '|{:02x}|'.format(len(state))
                state_len = f'|{len(state):02x}|'
                state_within = len(state_len + state) - 3
            #sig_string += 'content:"|06 03 55 04 08|"; distance:0; content:"{}{}"; distance:1; within:{}; '.format(state_len, state, state_within)
            sig_string += f'content:"|06 03 55 04 08|"; distance:0; content:"{state_len}{state}"; distance:1; within:{state_within}; '

        if "OU=" in item:
            org_unit = re.search('OU=(.+)$', item)
            if org_unit is None:
                org_unit = ""
                org_unit_len = '|00|'
                org_unit_within = 1
            else:
                org_unit = org_unit.group(1)
                #org_unit_len = '|{:02x}|'.format(len(org_unit))
                org_unit_len = f'|{len(org_unit):02x}|'
                org_unit_within = len(org_unit_len + org_unit) - 3
            #sig_string += 'content:"|06 03 55 04 0b|"; distance:0; content:"{}{}"; distance:1; within:{}; '.format(org_unit_len, org_unit, org_unit_within)
            sig_string += f'content:"|06 03 55 04 0b|"; distance:0; content:"{org_unit_len}{org_unit}"; distance:1; within:{org_unit_within}; '
        if "O=" in item:
            org = re.search('O=(.+)$', item)
            if org is None:
                org = ""
                org_len = '|00|'
                org_within = 1
            else:
                org = org.group(1)
                #org_len = '|{:02x}|'.format(len(org))
                org_len = f'|{len(org):02x}|'
                org_within = len(org_len + org) - 3
            #sig_string += 'content:"|06 03 55 04 0a|"; distance:0; content:"{}{}"; distance:1; within:{}; '.format(org_len, org, org_within)
            sig_string += f'content:"|06 03 55 04 0a|"; distance:0; content:"{org_len}{org}"; distance:1; within:{org_within}; '
        if "CN=" in item:
            common_name = re.search('CN=(.+)$', item)
            if common_name is None:
                common_name = ""
                common_name_len = '|00|'
                common_name_within = 1
            else:
                common_name = common_name.group(1)
                #common_name_len = '|{:02x}|'.format(len(common_name))
                common_name_len = f'|{len(common_name):02x}|'
                common_name_within = len(common_name_len + common_name) - 3
            #sig_string += 'content:"|06 03 55 04 03|"; distance:0; content:"{}{}"; distance:1; within:{}; '.format(common_name_len, common_name, common_name_within)
            sig_string += f'content:"|06 03 55 04 03|"; distance:0; content:"{common_name_len}{common_name}"; distance:1; within:{common_name_within}; '


    return sig_string


def do_snort_header_buffer(line, content_buffer):
    has_bsize = False
    has_start = False
    has_end = False
    has_nothing = True
    if "startswith;" in line or "depth:" in line:
        has_start = True
        has_nothing = False
        if 'content:!"' in line:
            line = line.replace('content:!"', 'content:!"' + content_buffer + '|3a 20|')
        else:
            line = line.replace('content:"', 'content:"' + content_buffer + '|3a 20|')
        if "startswith;" in line:
            line = line.replace('startswith;', '')
        if "depth:" in line:
            line = re.sub('depth:([^;]+);', '', line)
    if 'bsize:' in line:
        if 'content:!"' in line:
            line = line.replace('content:!"', 'content:!"' + content_buffer + '|3a 20|')
        else:
            line = line.replace('content:"', 'content:"' + content_buffer + '|3a 20|')
        has_bsize = True
        has_nothing = False
        line = re.sub('bsize:([^;]+);', '', line)
    if 'endswith;' in line or 'isdataat:!1,relative;' in line or has_bsize is True:
        has_end = True
        content_search = re.search(r'^.*content:\!?"([^"]+)";((?!content:\!?).+$)', line)
        old_line = content_search.group(0)
        content_initial = content_search.group(1)
        content = content_initial + "|0d 0a|"
        new_line = old_line.replace(content_initial, content)
        if 'endswith;' in new_line:
            new_line = new_line.replace('endswith;', '')
        if 'isdataat:!1,relative;' in new_line:
            new_line = new_line.replace('isdataat:!1,relative;', '')
    else:
        new_line = line
    if '||' in new_line:
        new_line = new_line.replace('||', ' ')
    if has_nothing:
        content_search = re.search(r'^.*content:\!?"([^"]+)";((?!content:\!?).*$)', line)
        content_initial = content_search.group(1)
    if has_nothing or (has_end and not has_start):
        if has_bsize is False:
            new_line = new_line + " http_header; "
            pcre_content = content_initial
            pcre_content = pcre_content.replace('/', r'\/')
            pcre_content = pcre_content.replace('\\', r'\/')
            if '|' in pcre_content:
                the_hex = re.findall(r'\|[a-fA-F0-9\s]+\|', pcre_content)
                for match in the_hex:
                    original_match = match
                    match = match.replace('|', '')
                    match = match.replace(' ', '')
                    match = re.sub('([a-fA-F0-9]{2})', r'\\x\1', match)
                    pcre_content = pcre_content.replace(original_match, match)
            pcre_content = pcre_content.replace('.', r'\.')
            pcre_content = pcre_content.replace('?', r'\?')
            pcre_content = pcre_content.replace(' ', '\\x20')
            pcre_content = pcre_content.replace('(', r'\(')
            pcre_content = pcre_content.replace(')', r'\)')
            pcre_content = pcre_content.replace(']', r'\]')
            pcre_content = pcre_content.replace('[', r'\[')
            new_line = buffer_reordering(new_line, "http_header;")
            new_line = new_line + ' pcre:"/^' + content_buffer + '\\x3a\\x20[^\\r\\n]+' + pcre_content + '/Hmi\";'
            return "".join(new_line)
        #else:
            #return "".join(new_line)
        return "".join(new_line)
    #else:
        #return "".join(new_line) + " http_header;"
    return "".join(new_line) + " http_header;"

def snort_tls(rule):

    try:
        snort_rule_begin = re.search('^alert.+flow:[^;]+;', rule.strip())
    except Exception as e:
        raise Exception(f"Unable to parse the rule beginning - {e}")

    snort_rule_end = re.search('(?:reference:.+)?classtype:.+$', rule)

    snort_rule_front = snort_rule_begin.group(0)
    snort_rule_backend = snort_rule_end.group(0)

    tls_rule_guts = rule.replace(snort_rule_front, '')
    tls_rule_guts = tls_rule_guts.replace(snort_rule_backend, '')

    #edit the port var statement
    if 'alert tls $HOME_NET any -> $EXTERNAL_NET any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls $HOME_NET any -> $EXTERNAL_NET any', 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443')
    elif 'alert tls any any -> any any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls any any -> any any', 'alert tcp any any -> any any')
    elif 'alert tls $HOME_NET any -> $EXTERNAL_NET 443' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls $HOME_NET any -> $EXTERNAL_NET 443', 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443')
    elif 'alert tls $EXTERNAL_NET any -> $HOME_NET any' in snort_rule_front:
        snort_rule_front = snort_rule_front.replace('alert tls $EXTERNAL_NET any -> $HOME_NET any', 'alert tcp $EXTERNAL_NET 443 -> $HOME_NET any')
    else:
        snort_rule_front = snort_rule_front.replace('alert tls', 'alert tcp')

#   get the sticky buffers
    snort_sticky = re.findall(r'(?:http[\._](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body|uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file[\._]data|dns[\._]query|tls[\._](?:sni|cert_subject|cert_issuer|cert_serial))(?:(?!http[\._](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body|uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file[\._]data|dns[\._]query|tls[\._](?:sni|cert_subject|cert_issuer|cert_serial)).)+', tls_rule_guts)
    if snort_sticky:
        #rip them out of the blob
        tls_rule_guts = re.sub(r'(?:http[.](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body)|(?:http[.](?:uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file[.]data|dns[._]query|tls[.](?:sni|cert_subject|cert_issuer|cert_serial)))(?:(?! http[.](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body)|(?:http[.](?:uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file[.]data|dns[.]query|tls[.](?:sni|cert_subject|cert_issuer|cert_serial))).)+', '', tls_rule_guts)

    _subject = ''
    _issuer = ''
    _serial = ''

    #sticky buffers
    for item in snort_sticky:
        #tls.cert_subject
        if "tls.cert_subject;" in item or "tls_cert_subject;" in item:
            subject_found = re.sub(r'\s*tls[._]cert_subject;\s*', '', item)
            _subject += subject_found
        #tls.cert_issuer
        if "tls.cert_issuer;" in item or "tls_cert_issuer;" in item:
            issuer_found = re.sub(r'\s*tls[._]cert_issuer;\s*', '', item)
            _issuer += issuer_found
        #tls.cert_serial
        if "tls.cert_serial;" in item or "tls_cert_serial;" in item:
            serial_found = re.sub(r'\s*tls[._]cert_serial;\s*', '', item)
            _serial += serial_found

    #empty array for rule contents to go in
    snort_new_content=[]

    if _serial:
        serial_split = _serial.split("content:")
        del serial_split[0]
        for item in serial_split:
            item = "content:" + item
            things_to_do = re.search('content:"([^"]+)";', item)
            new_and_nice = things_to_do.group(0)
            convert_this = things_to_do.group(1)
            convert_this = convert_this.replace(":", " ")
            old_and_stupid = 'content:"|' + convert_this + '|";'
            item = item.replace(new_and_nice, old_and_stupid)
            if 'bsize:' in item:
                item = re.sub(r'bsize:\d+; ', '', item)
            if 'startswith;' in item:
                item = item.replace('startswith;', '')
            if 'endswith;' in item:
                item = item.replace('endswith;', '')
            snort_new_content.append(item)

    if _subject:
        subject_split = _subject.split("content:")
        del subject_split[0]
        for item in subject_split:
            item = "content:" + item
            things_to_do = re.search('content:"([^"]+)";', item)
            new_and_nice = things_to_do.group(0)
            convert_this = things_to_do.group(1)
            old_and_stupid = cert_items(convert_this)
            item = item.replace(new_and_nice, old_and_stupid)
            if 'bsize:' in item:
                item = re.sub(r'bsize:\d+; ', '', item)
            if 'startswith;' in item:
                item = item.replace('startswith;', '')
            if 'endswith;' in item:
                item = item.replace('endswith;', '')
            snort_new_content.append(item)

    if _issuer:
        issuer_split = _issuer.split("content:")
        del issuer_split[0]
        for item in issuer_split:
            item = "content:" + item
            things_to_do = re.search('content:"([^"]+)";', item)
            new_and_nice = things_to_do.group(0)
            convert_this = things_to_do.group(1)
            old_and_stupid = cert_items(convert_this)
            item = item.replace(new_and_nice, old_and_stupid)
            if 'bsize:' in item:
                item = re.sub(r'bsize:\d+; ', '', item)
            if 'startswith;' in item:
                item = item.replace('startswith;', '')
            if 'endswith;' in item:
                item = item.replace('endswith;', '')
            snort_new_content.append(item)

    #compile it
    snort_rule_guts = " ".join(snort_new_content)

    #check for any double spaces
    snort_rule_guts = re.sub(r';\s{2,}', '; ', snort_rule_guts)

    #build the new rule
    fresh_rule = snort_rule_front + ' content:"|16|"; content:"|0b|"; within:8; ' + snort_rule_guts + ' ' + snort_rule_backend

    #dotprefix TODO
    if 'dotprefix;' in fresh_rule:
        ### TODO: LOG AS WARNING
        print("This script does not yet support the dotprefix tag")

    #check the rule again for any double spaces
    fresh_rule = re.sub(r';\s{2,}', '; ', fresh_rule)

    #check the rule again for any double quote semi
    fresh_rule = re.sub('";";', '";', fresh_rule)

    #clean up some spaces for readability for whitespace
    if '| ' in fresh_rule:
        fresh_rule = fresh_rule.replace("| ", " 20|")
    if ' ";' in fresh_rule:
        fresh_rule = fresh_rule.replace(' ";', '|20|";')
    if 'content:" ' in fresh_rule:
        fresh_rule = fresh_rule.replace('content:" ', 'content:"|20|')

    proback_rule = re.sub('msg:"[^"]+"; ','', fresh_rule) #remove message
    proback_rule = re.sub(r'\s*classtype:.+$',')', proback_rule) #remove end starting with classtype
    proback_rule = re.sub(r'\s*reference:.+$',')', proback_rule) #remove end starting with reference
    proback_rule = re.sub(r'\s*metadata:.+$',')', proback_rule) #remove metadata

    return proback_rule

def convert5_to_snort(rule):

    debug_mode=False
    #this var is unused.
    #review_this_rule=False

    #form up the suri4 rule
    snort_base = rule

    #grab the start and end
    if "dns.query;" in snort_base or 'dns_query;' in snort_base:
        fresh_rule = snort_dns(snort_base)
        return fresh_rule
    if "tls.sni;" in snort_base or 'tls_sni;' in snort_base:
        fresh_rule = snort_tls_sni(snort_base)
        return fresh_rule
    if "tls.cert_subject" in snort_base or "tls_cert_subject" in snort_base:
        fresh_rule = snort_tls(snort_base)
        return fresh_rule
    #else:
        #try:
            #snort_rule_begin = re.search(r'^alert.+flow:[^;]+;', snort_base)
            #if debug_mode:
                #print(bcolors.HEADER + "\nRule beginning: " + bcolors.WARNING + snort_rule_begin.group(0) + bcolors.ENDC)
        #except Exception:
            #try:
                #snort_rule_begin = re.search(r'^alert.+msg:[^;]+;', snort_base)
                #if debug_mode:
                    #print(bcolors.HEADER + "\nEXCEPTION - Rule beginning: " + bcolors.WARNING + snort_rule_begin.group(0) + bcolors.ENDC)
            #except Exception:
                #print(bcolors.FAIL + "Unable to parse the rule beginning." + bcolors.ENDC)
                #return False
    try:
        snort_rule_begin = re.search(r'^alert.+flow:[^;]+;', snort_base)
        if debug_mode:
            print(bcolors.HEADER + "\nRule beginning: " + bcolors.WARNING + snort_rule_begin.group(0) + bcolors.ENDC)
    except Exception:
        try:
            snort_rule_begin = re.search(r'^alert.+msg:[^;]+;', snort_base)
            if debug_mode:
                print(bcolors.HEADER + "\nEXCEPTION - Rule beginning: " + bcolors.WARNING + snort_rule_begin.group(0) + bcolors.ENDC)
        except Exception:
            print(bcolors.FAIL + "Unable to parse the rule beginning." + bcolors.ENDC)
            return False

    snort_rule_end = re.search(r'(?:reference:.+)?classtype:.+$', snort_base)
    if debug_mode:
        print(bcolors.HEADER + "Rule end: " + bcolors.WARNING + snort_rule_end.group(0) + bcolors.ENDC)

    snort_rule_front = snort_rule_begin.group(0)
    snort_rule_backend = snort_rule_end.group(0)

    #headers
    if "alert http" in snort_rule_front:
        #print("1")
        #alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
        if 'alert http $HOME_NET any -> $EXTERNAL_NET any' in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert http $HOME_NET any -> $EXTERNAL_NET any', 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS')
        #alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any
        elif 'alert http $EXTERNAL_NET any -> $HOME_NET any' in snort_rule_front:
            #print("2")
            snort_rule_front = snort_rule_front.replace('alert http $EXTERNAL_NET any -> $HOME_NET any', 'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any')
        elif 'alert http any any -> any any' in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert http any any -> any any', 'alert tcp any any -> any $HTTP_PORTS')
        elif 'alert http any any -> $HOME_NET any' in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert http any any -> $HOME_NET any', 'alert tcp any any -> $HOME_NET $HTTP_PORTS')
        else:
            snort_rule_front = snort_rule_front.replace('alert http', 'alert tcp')

    #alert tls
        #alert tcp $HOME_NET any -> $EXTERNAL_NET 443
        #alert tcp $EXTERNAL_NET 443 -> $HOME_NET any

    if 'alert smb' in snort_rule_front:
        if 'alert smb any any -> $HOME_NET any' in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert smb any any -> $HOME_NET any', 'alert tcp any any -> $HOME_NET [139,445]')
        elif 'alert smb $HOME_NET any -> $HOME_NET any' in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert smb $HOME_NET any -> $HOME_NET any', 'alert smb $HOME_NET any -> $HOME_NET any', 'alert tcp $HOME_NET any -> $HOME_NET [139,445]')
        elif 'alert smb $HOME_NET any -> any any' in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert smb $HOME_NET any -> any any', 'alert tcp $HOME_NET [139,445] -> any any')
        else:
            snort_rule_front = snort_rule_front.replace('alert smb', 'alert tcp')

    if "alert ftp" in snort_rule_front:
        if "alert ftp-data $HOME_NET any -> $EXTERNAL_NET any" in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert ftp-data $HOME_NET any -> $EXTERNAL_NET any', 'alert tcp $HOME_NET any -> $EXTERNAL_NET 1024:')
        elif "alert ftp $HOME_NET any -> $EXTERNAL_NET any" in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert ftp $HOME_NET any -> $EXTERNAL_NET any', 'alert tcp $HOME_NET any -> $EXTERNAL_NET 21')
        elif "alert ftp $EXTERNAL_NET any -> $HOME_NET any" in snort_rule_front:
            snort_rule_front = snort_rule_front.replace('alert ftp $EXTERNAL_NET any -> $HOME_NET any', 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21')
        else:
            snort_rule_front = snort_rule_front.replace('alert ftp', 'alert tcp')

    #rip out the middle
    snort_content_blob = re.sub(r'^alert.+flow:[^;]+; ', '', snort_base)
    snort_content_blob = re.sub(r' (?:reference:.+)?classtype:.+$', '', snort_content_blob)
    snort_content_blob = re.sub(r'\s*metadata:[^;]+;','', snort_content_blob) #remove metadata

    #clean up any double spaces
    snort_content_blob = re.sub(r';\s{2,}', '; ', snort_content_blob)

    if debug_mode:
        print(bcolors.HEADER + "Rule contents: " + bcolors.WARNING + snort_content_blob + bcolors.ENDC)

    extra_rule_contents=[]
    trailer_rule_contents = []
    has_extra_rule_contents=False
    if 'stream_size:' in snort_content_blob:
        has_extra_rule_contents=True
        stream_size_found = re.search(r'stream_size:[^;]+;', snort_content_blob)
        extra_rule_contents.append(stream_size_found.group(0))
        snort_content_blob = re.sub(r'\s*stream_size:[^;]+;', '', snort_content_blob)
    if 'dsize:' in snort_content_blob:
        has_extra_rule_contents=True
        dsize_found = re.search(r'dsize:[^;]+;', snort_content_blob)
        extra_rule_contents.append(dsize_found.group(0))
        snort_content_blob = re.sub(r'\s*dsize:[^;]+;', '', snort_content_blob)
    if 'flowbits:' in snort_content_blob:
        has_extra_rule_contents=True
        flowbit_found = re.findall(r'flowbits:[^;]+;', snort_content_blob)
        for item in flowbit_found:
            extra_rule_contents.append(item)
            snort_content_blob = re.sub(item, '', snort_content_blob)
    if 'xbits:' in snort_content_blob:
        has_extra_rule_contents=True
        xbit_found = re.findall(r'xbits:[^;]+;', snort_content_blob)
        for item in xbit_found:
            extra_rule_contents.append(item)
            snort_content_blob = re.sub(item, '', snort_content_blob)
    # make urilen the last thing
    if 'urilen:' in snort_content_blob:
        has_extra_rule_contents=True
        urilen_found = re.search(r'urilen:[^;]+;', snort_content_blob)
        extra_rule_contents.append(urilen_found.group(0))
        snort_content_blob = re.sub(r'\s*urilen:[^;]+;', '', snort_content_blob)
    # Threshold will be considered a "trailer"
    if 'threshold:' in snort_content_blob:
        threshold_found = re.findall(r'threshold:[^;]+;', snort_content_blob)
        for item in threshold_found:
            trailer_rule_contents.append(item)
            snort_content_blob = re.sub(item, '', snort_content_blob)

    #get the sticky buffers
    snort_sticky = re.findall(r'(?:http[\._](?:header_names\;|location\;|referer\;|accept(?:_lang|_enc)?\;|request_line\;|connection\;|content_(?:type|len)\;|start\;|protocol\;|response_line\;|server\;|request_body\;|response_body\;|uri\;|uri\.raw\;|method\;|header\;|header\.raw\;|cookie\;|user_agent\;|host\;|host\.raw\;|stat_msg\;|stat_code\;|server_body\;)|file[\._]data\;|dns[\._]query\;|tls[\._](?:sni\;|cert_subject\;|cert_issuer\;|cert_serial\;))(?:(?!http[\._](?:header_names\;|location\;|referer\;|accept(?:_lang|_enc)?\;|request_line\;|connection\;|content_(?:type|len)\;|start\;|protocol\;|response_line\;|server\;|request_body\;|response_body\;|uri\;|uri\.raw\;|method\;|header\;|header\.raw\;|cookie\;|user_agent\;|host\;|host\.raw\;|stat_msg\;|stat_code\;|server_body\;)|file[\._]data\;|dns[\._]query\;|tls[\._](?:sni\;|cert_subject\;|cert_issuer\;|cert_serial\;)).)+', snort_content_blob)
    if debug_mode:
        print(bcolors.HEADER + "Rule sticky buffer contents: " + bcolors.WARNING + str(snort_sticky) + bcolors.ENDC)
    # the if statement below does nothing since the no_sticky_buffers
    # is not set (because the var is never used)
    # so we're changing it to 'snort_sticky != []:'
    #if snort_sticky == []:
        #this variable isn't used
        #no_sticky_buffers=True
    #else:
        #this variable isn't used
        #no_sticky_buffers=False
        #rip them out of the blob
    #    snort_content_blob = re.sub(r'(?:http[.](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body)|(?:http[.](?:uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file_data|file\.data|dns[._]query|tls[.](?:sni|cert_subject|cert_issuer|cert_serial)))(?:(?! http[.](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body)|(?:http[.](?:uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file_data|file\.data|dns[.]query|tls[.](?:sni|cert_subject|cert_issuer|cert_serial))).)+', '', snort_content_blob)
    #    if debug_mode:
    #        print(bcolors.HEADER + "Rule without sticky buffer contents: " + bcolors.WARNING + snort_content_blob + bcolors.ENDC)
    if snort_sticky != []:
        #rip them out of the blob
        snort_content_blob = re.sub(r'(?:http[.](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body)|(?:http[.](?:uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file_data|file\.data|dns[._]query|tls[.](?:sni|cert_subject|cert_issuer|cert_serial)))(?:(?! http[.](?:header_names|location|referer|accept(?:_lang|_enc)?|request_line|connection|content_(?:type|len)|start|protocol|response_line|server\;|request_body|response_body)|(?:http[.](?:uri|uri\.raw|method|header|header\.raw|cookie|user_agent|host|host\.raw|stat_msg|stat_code|server_body)|file_data|file\.data|dns[.]query|tls[.](?:sni|cert_subject|cert_issuer|cert_serial))).)+', '', snort_content_blob)
        if debug_mode:
            print(bcolors.HEADER + "Rule without sticky buffer contents: " + bcolors.WARNING + snort_content_blob + bcolors.ENDC)

    #get the modifiers
    snort_content=re.findall(r'content:\s?\!?\"(?:(?!\s?content:\s?\!?\").)+', snort_content_blob)
    if debug_mode:
        print(bcolors.HEADER + "Rule modifier contents: " + bcolors.WARNING + str(snort_content) + bcolors.ENDC)

    #this variable isn't used.
    #contains_modifier=False
    #because contains_modifier isn't used, this if statement can be commented out
    #for item in snort_content:
        #if re.search(r'(?:http_(?:(?:raw_)?uri|method|client_body|server_body|(?:raw_)?header|(?:raw_)?host|stat_(?:code|msg)|cookie|user_agent)|file_data)', item):
            #this variable isn't used.
            #contains_modifier=True

    #if no_sticky_buffers is True and contains_modifier is False:
    #    if debug_mode:
    #        print(bcolors.OKBLUE + "This rule does not appear to contain any buffers and #therefore does not require translation." + bcolors.ENDC)
    #    return snort_rule_front + snort_rule_guts + snort_rule_end

    #need to add more buffers here
    #if "http." not in snort_base and "tls." not in snort_base and "file.data" not in snort_base and "dns." not in snort_base and "http_header_names" not in snort_base and "http_referer" not in snort_base and "http_accept" not in snort_base and "tls_" not in snort_base and "dns_" not in snort_base and "http_content" not in snort_base:
    #    if debug_mode:
    #        print(bcolors.OKBLUE + "This rule appears to already be compatible with snort" + bcolors.ENDC)
        #halt_5 = input("Review and press [ENTER]...")
    #    return False

    _uri = ''
    _raw_uri = ''
    _method = ''
    _request_line = ''
    _client_body = ''
    _header = ''
    _raw_header = ''
    _cookie = ''
    _user_agent = ''
    _host = ''
    _raw_host = ''
    _accept = ''
    _accept_lang = ''
    _accept_enc = ''
    _referer = ''
    _connection = ''
    _content_type = ''
    _content_len = ''
    _start = ''
    _protocol = ''
    _header_names = ''
    _stat_msg = ''
    _stat_code = ''
    _response_line = ''
    _server_body = ''
    _data = ''
    _server = ''
    _location = ''
    _unbuffered = []
    _orphaned_pcre = []

    for item in snort_content:
        if "startswith;" in item:
            item = startswith_convert(item)
        _unbuffered.append(item)

    #sticky buffers
    for item in snort_sticky:
        #http.accept -> http_accept
        if "http_accept;" in item or "http.accept;" in item:
            accept_found = re.sub(r'\s*http[._]accept;\s*', '', item)
            _accept += accept_found
        #http_accept_lang -> http.accept_lang
        elif "http_accept_lang;" in item or "http.accept_lang" in item:
            accept_lang_found = re.sub(r'\s*http[._]accept_lang;\s*', '', item)
            _accept_lang += accept_lang_found
        #http_accept_enc -> http.accept_enc
        elif "http_accept_enc;" in item or "http.accept_enc;" in item:
            accept_enc_found = re.sub(r'\s*http[._]accept_enc;\s*', '', item)
            _accept_enc += accept_enc_found
        #http_referer -> http.referer
        elif "http_referer;" in item or "http.referer;" in item:
            referer_found = re.sub(r'\s*http[._]referer;\s*', '', item)
            _referer += referer_found
        #http_connection -> http.connection
        elif "http_connection;" in item or "http.connection;" in item:
            connection_found = re.sub(r'\s*http[._]connection;\s*', '', item)
            _connection += connection_found
        #http_content_type -> http.content_type
        elif "http_content_type;" in item or "http.content_type" in item:
            content_type_found = re.sub(r'\s*http[._]content_type;\s*', '', item)
            _content_type += content_type_found
        #http_content_len -> http.content_len
        elif "http_content_len;" in item or "http.content_len;" in item:
            content_len_found = re.sub(r'\s*http[._]content_len;\s*', '', item)
            _content_len += content_len_found
        #http_start -> http.start
        elif "http_start;" in item or "http.start;" in item:
            start_found = re.sub(r'\s*http[._]start;\s*', '', item)
            _start += start_found
        #http_location -> http.location
        elif "http_location;" in item or "http.location;" in item:
            location_found = re.sub(r'\s*http[._]location;\s*', '', item)
            _location += location_found
        #http_protocol -> http.protocol
        elif "http_protocol;" in item or "http.protocol;" in item:
            protocol_found = re.sub(r'\s*http[._]protocol;\s*', '', item)
            _protocol += protocol_found
        #http_header_names -> http.header_names
        elif "http_header_names;" in item or "http.header_names;" in item:
            header_names_found = re.sub(r'\s*http[._]header_names;\s*', '', item)
            _header_names += header_names_found
        #http_request_line -> http.request_line
        elif "http_request_line;" in item or "http.request_line;" in item:
            request_line_found = re.sub(r'\s*http[._]request_line;\s*', '', item)
            _request_line += request_line_found
        #http_response_line -> http.response_line
        elif "http_response_line;" in item or "http.response_line;" in item:
            response_line_found = re.sub(r'\s*http[._]response_line;\s*', '', item)
            _response_line += response_line_found
        elif "file_data;" in item or "file.data;" in item:
            if "file.data;" in item:
                data_found = re.sub(r'\s*file\.data;', 'file_data;', item)
            else:
                data_found = item
            _data += data_found
        elif "http.uri;" in item:
            item = re.sub(r'http\.uri;\s*', '', item)
            _uri += item
        elif "http.server;" in item:
            item = re.sub(r'http\.server;\s*', '', item)
            _server += item
        elif "http.uri.raw;" in item:
            item = re.sub(r'http\.uri\.raw;\s*', '', item)
            _raw_uri += item
        elif "http.method;" in item:
            item = re.sub(r'http\.method;\s*', '', item)
            _method += item
        elif "http.header;" in item:
            item = re.sub(r'http\.header;\s*', '', item)
            _header += item
        elif "http.header.raw;" in item:
            item = re.sub(r'http\.header\.raw;\s*', '', item)
            _raw_header += item
        elif "http.cookie;" in item:
            item = re.sub(r'http\.cookie;\s*', '', item)
            _cookie += item
        elif "http.user_agent;" in item:
            item = re.sub(r'http\.user_agent;\s*', '', item)
            _user_agent += item
        elif "http.host;" in item:
            item = re.sub(r'http\.host;\s*', '', item)
            _host += item
        elif "http.host.raw;" in item:
            item = re.sub(r'http\.host\.raw;\s*', '', item)
            _raw_host += item
        elif "http.stat_msg;" in item:
            item = re.sub(r'http\.stat_msg;\s*', '', item)
            _stat_msg += item
        elif "http.stat_code;" in item:
            item = re.sub(r'http\.stat_code;\s*', '', item)
            _stat_code += item
        elif "http.location;" in item:
            _location += item
        elif "http.response_body;" in item:
            item = re.sub(r'http\.response_body;\s*', '', item)
            _server_body += item
        elif "http.request_body;" in item:
            item = re.sub(r'http.request_body;\s*', '', item)
            _client_body += item
        else:
            if debug_mode:
                print(bcolors.FAIL + "This looks like a sticky buffer i haven't accounted for: " + bcolors.WARNING + item + bcolors.ENDC)
                #this var never gets used.
                #sticky_halt = input("Review this and press [ENTER] to continue...")
            _unbuffered.append(item)

    #empty array for rule contents to go in
    snort_new_content=[]

    #add in the non buffer things (dsize, flowbits, etc)
    if has_extra_rule_contents:
        for item in extra_rule_contents:
            snort_new_content.append(item)
        #review_this_rule=True

    #add in contents without a buffer
    #if _unbuffered != []:
    if _unbuffered:
        for item in _unbuffered:
            if "startswith;" in item:
                item = startswith_convert(item)

            # unbuffered items can support endswith/isdataat
            if "endswith;" in item:
                item = re.sub(r'endswith;', 'isdataat:!1,relative;', item)

            snort_new_content.append(buffer_reordering(item, ""))
        #review_this_rule=True

    #modifiers
    if _stat_code:
        snort_new_content.append(_stat_code + " http_stat_code; ")
        if debug_mode:
            print(bcolors.HEADER + "http_stat_code: " + bcolors.WARNING + str(_stat_code) + bcolors.ENDC)
    if _stat_msg:
        snort_new_content.append(_stat_msg + " http_stat_msg; ")
        if debug_mode:
            print(bcolors.HEADER + "http_stat_msg: " + bcolors.WARNING + str(_stat_msg) + bcolors.ENDC)
    if _method:
        snort_new_content.append(_method + " http_method; ")
        if debug_mode:
            print(bcolors.HEADER + "http_method: " + bcolors.WARNING + str(_method) + bcolors.ENDC)
    if _uri:
        #if not 'content:' in _uri:
        if 'content:' not in _uri:
            pcre_flag_search = re.search(r'(\/[a-zA-Z]*";)$', _uri.strip())
            the_old_flags = re.search(r'\/([a-zA-Z]*)', pcre_flag_search.group(0))
            the_new_flags = "/" + 'U' + the_old_flags.group(1) + '";'
            new_line = _uri.replace(pcre_flag_search.group(0), the_new_flags)
            snort_new_content.append(new_line)
        else:
            if "startswith;" in _uri:
                _uri = startswith_convert(_uri)
            uri_split = _uri.split("content:")
            del uri_split[0]
            for item in uri_split:
                item = "content:" + item
                if "endswith;" in item or 'isdataat:!1,relative;' in item:
                    do_nocase = False
                    if "nocase;" in item:
                        do_nocase = True
                    grab_this = re.search(r'content:\!?"([^"]+)";', item)
                    the_content = grab_this.group(1)
                    the_content = the_content.replace(r'?', r'\?')
                    the_content = the_content.replace(r'.', r'\.')
                    the_content = the_content.replace(r' ', r'\x20')
                    the_content = the_content.replace(r'/', r'\x2f')
                    if do_nocase:
                        the_pcre = 'pcre:"/' + the_content + '$/i";'
                    else:
                        the_pcre = 'pcre:"/' + the_content + '$/";'
                    if "endswith;" in item:
                        item = item.replace('endswith;', the_pcre)
                    else:
                        item = item.replace('isdataat:!1,relative;', the_pcre)
                if 'pcre:"' in item:
                    the_pcres = []
                    pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
                    for hit in pcre_search:
                        item = item.replace(hit, '')
                        hit = pcre_fix(hit, "U")
                        if '/UR' in hit:
                            grab_this = re.search(r'content:\!?"([^"]+)";', item)
                            the_content = grab_this.group(1)
                            the_content = the_content.replace(r'?', r'\?')
                            the_content = the_content.replace(r'.', r'\.')
                            the_content = the_content.replace(r'/', r'\x2f')
                            if '|' in the_content:
                                the_hex_list = re.findall(r'\|[^\|]+\|', the_content)
                                for match in the_hex_list:
                                    original_match = match
                                    match = match.replace(' ', '')
                                    match = match.replace('|', '')
                                    match = re.sub(r'([a-fA-F0-9][a-fA-F0-9])', r'\\x\1', match)
                                    the_content = the_content.replace(original_match, match)
                            the_content = the_content.replace(r' ', r'\\x20')
                            hit = hit.replace('pcre:"/^', 'pcre:"/' + the_content)
                            hit = hit.replace('/UR', '/U')
                        the_pcres.append(hit)
                    if re.search(r'bsize:\d+;', item):
                        if 'urilen:' in rule:
                            item = re.sub(r'bsize:\d+;', '', item)
                        else:
                            new_urilen_search = re.search(r'bsize:(\d+);', item)
                            new_urilen = new_urilen_search.group(1)
                            snort_new_content.insert(0, 'urilen:' + new_urilen + '; ')
                            item = re.sub(r'bsize:\d+;', '', item)
                    snort_new_content.append(buffer_reordering(item, " http_uri;") + " " + " ".join(the_pcres))
                    #snort_new_content.append(item + " http_uri; " + " ".join(the_pcres) + " ")
                else:
                    if re.search(r'bsize:\d+;', item):
                        if 'urilen:' in rule:
                            item = re.sub(r'bsize:\d+;', '', item)
                        else:
                            new_urilen_search = re.search(r'bsize:(\d+);', item)
                            new_urilen = new_urilen_search.group(1)
                            snort_new_content.insert(0, 'urilen:' + new_urilen + '; ')
                            item = re.sub(r'bsize:\d+;', '', item)
                    snort_new_content.append(buffer_reordering(item, " http_uri;"))
        if debug_mode:
            print(bcolors.HEADER + "http_uri: " + bcolors.WARNING + str(_uri) + bcolors.ENDC)
    if _raw_uri:
        if "startswith;" in _raw_uri:
            _raw_uri = startswith_convert(_raw_uri)
        raw_uri_split = _raw_uri.split("content:")
        del raw_uri_split[0]
        for item in raw_uri_split:
            item = "content:" + item
            if "endswith;" in item or 'isdataat:!1,relative;' in item:
                do_nocase = False
                if "nocase;" in item:
                    do_nocase = True
                grab_this = re.search(r'^"([^"]+)";', item)
                the_content = grab_this.group(1)
                the_content = the_content.replace(r'?', r'\?')
                the_content = the_content.replace(r'.', r'\.')
                the_content = the_content.replace(r' ', r'\\x20')
                if do_nocase:
                    the_pcre = 'pcre:"/' + the_content + '$/i";'
                else:
                    the_pcre = 'pcre:"/' + the_content + '$/";'
                if "endswith;" in item:
                    item = item.replace('endswith;', the_pcre)
                else:
                    item = item.replace('isdataat:!1,relative;', the_pcre)
            if 'pcre:"' in item:
                the_pcres = []
                pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
                for hit in pcre_search:
                    item = item.replace(hit, '')
                    hit = pcre_fix(hit, "I")
                    if '/IR' in hit:
                        grab_this = re.search(r'content:\!?"([^"]+)";', item)
                        the_content = grab_this.group(1)
                        the_content = the_content.replace(r'?', r'\?')
                        the_content = the_content.replace(r'.', r'\.')
                        the_content = the_content.replace(r'/', r'\/')
                        if '|' in the_content:
                            the_hex_list = re.findall(r'\|[^\|]+\|', the_content)
                            for match in the_hex_list:
                                original_match = match
                                match = match.replace(' ', '')
                                match = match.replace('|', '')
                                match = re.sub(r'([a-fA-F0-9][a-fA-F0-9])', r'\\x\1', match)
                                the_content = the_content.replace(original_match, match)
                        the_content = the_content.replace(r' ', r'\\x20')
                        hit = hit.replace('pcre:"/^', 'pcre:"/' + the_content)
                        hit = hit.replace('/IR', '/I')
                    the_pcres.append(hit)
                snort_new_content.append(buffer_reordering(item, " http_raw_uri;") + " " + " ".join(the_pcres)) # Snort barfing when header reordering is combined with PCRE
            else:
                snort_new_content.append(buffer_reordering(item, " http_raw_uri;"))
        if debug_mode:
            print(bcolors.HEADER + "http_raw_uri: " + bcolors.WARNING + str(_raw_uri) + bcolors.ENDC)
    if _header:
        if "startswith;" in _header:
            _header = startswith_convert(_header)
        header_split = _header.split("content:")
        del header_split[0]
        for item in header_split:
            item = "content:" + item
            if 'pcre:"' in item:
                the_pcres = []
                pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
                for hit in pcre_search:
                    item = item.replace(hit, '')
                    hit = pcre_fix(hit, "H")
                    if '/HR' in hit:
                        grab_this = re.search(r'content:\!?"([^"]+)";', item)
                        the_content = grab_this.group(1)
                        the_content = the_content.replace(r'?', r'\?')
                        the_content = the_content.replace(r'.', r'\.')
                        the_content = the_content.replace(r'/', r'\/')
                        if '|' in the_content:
                            the_hex_list = re.findall(r'\|[^\|]+\|', the_content)
                            for match in the_hex_list:
                                original_match = match
                                match = match.replace(' ', '')
                                match = match.replace('|', '')
                                match = re.sub(r'([a-fA-F0-9][a-fA-F0-9])', r'\\x\1', match)
                                the_content = the_content.replace(original_match, match)
                        the_content = the_content.replace(r' ', r'\\x20')
                        hit = hit.replace('pcre:"/^', 'pcre:"/' + the_content)
                        hit = hit.replace('/HR', '/H')
                    the_pcres.append(hit)
                snort_new_content.append(buffer_reordering(item, " http_header;") + " " + " ".join(the_pcres))
            else:
                snort_new_content.append(buffer_reordering(item, " http_header;"))
        if debug_mode:
            print(bcolors.HEADER + "http_header: " + bcolors.WARNING + str(_header) + bcolors.ENDC)
    if _raw_header:
        if "startswith;" in _raw_header:
            _raw_header = startswith_convert(_raw_header)
        raw_header_split = _raw_header.split("content:")
        del raw_header_split[0]
        for item in raw_header_split:
            if 'pcre:"' in item:
                the_pcres = []
                pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
                for hit in pcre_search:
                    item = item.replace(hit, '')
                    hit = pcre_fix(hit, "D")
                    the_pcres.append(hit)
                snort_new_content.append(buffer_reordering(item, " http_raw_header;") + " " + " ".join(the_pcres))
            else:
                snort_new_content.append(buffer_reordering(item, "http_raw_header;")) # jec edit 29/04/2021, buffer reordering
        if debug_mode:
            print(bcolors.HEADER + "http_uri: " + bcolors.WARNING + str(_raw_header) + bcolors.ENDC)
    if _user_agent:
        new_line = do_snort_header_buffer(_user_agent, "User-Agent")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(buffer_reordering(new_line, " http_header;"))
        if debug_mode:
            print(bcolors.HEADER + "http_user_agent: " + bcolors.WARNING + str(_user_agent) + bcolors.ENDC)
    if _host:
        #if not 'content:' in _host:
        if 'content:' not in _host:
            #this looks like a pcre-only deal
            if _host.startswith('pcre:"/^'):
                _host = _host.replace('pcre:"/^', 'pcre:"/^Host\\x3a\\x20')
            else:
                _host = _host.replace('pcre:"/', 'pcre:"/^Host\\x3a\\x20[^\\r\\n]+')
            #fixup the flags
            pcre_flag_search = re.search(r'(\/[a-zA-Z]*";)$', _host.strip())
            the_old_flags = re.search(r'\/([a-zA-Z]*)', pcre_flag_search.group(0))
            if '^' in _host:
                the_new_flags = "/" + 'Hm' + the_old_flags.group(1) + '";'
            else:
                the_new_flags = "/" + 'H' + the_old_flags.group(1) + '";'
            new_line = _host.replace(pcre_flag_search.group(0), the_new_flags)
        else:
            new_line = do_snort_header_buffer(_host, "Host")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            #snort_new_content.append(buffer_reordering(item, " http_header;"))
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_host: " + bcolors.WARNING + str(_host) + bcolors.ENDC)
    if _raw_host:
        new_line = do_snort_header_buffer(_raw_host, "Host")
        snort_new_content.append(new_line)
        if debug_mode:
            print(bcolors.HEADER + "http_host_raw: " + bcolors.WARNING + str(_host) + bcolors.ENDC)
    if _cookie:
        if "startswith;" in _cookie:
            _cookie = startswith_convert(_cookie)
        cookie_split = _cookie.split("content:")
        del cookie_split[0]
        for item in cookie_split:
            if "endswith;" in item or 'isdataat:!1,relative;' in item:
                do_nocase = False
                if "nocase;" in item:
                    do_nocase = True
                grab_this = re.search(r'^"([^"]+)";', item)
                the_content = grab_this.group(1)
                the_content = the_content.replace(r'?', r'\?')
                the_content = the_content.replace(r'.', r'\.')
                the_content = the_content.replace(r' ', r'\\x20')
                if do_nocase:
                    the_pcre = 'pcre:"/' + the_content + '$/i";'
                else:
                    the_pcre = 'pcre:"/' + the_content + '$/";'
                if "endswith;" in item:
                    item = item.replace('endswith;', the_pcre)
                else:
                    item = item.replace('isdataat:!1,relative;', the_pcre)
            if 'pcre:"' in item:
                the_pcres = []
                pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
                for hit in pcre_search:
                    item = item.replace(hit, '')
                    hit = pcre_fix(hit, "C")
                    the_pcres.append(hit)
                snort_new_content.append(buffer_reordering(item, " http_cookie;") + " " + " ".join(the_pcres))
            else:
                snort_new_content.append(buffer_reordering(item, " http_cookie;"))
        if debug_mode:
            print(bcolors.HEADER + "http_cookie: " + bcolors.WARNING + str(_cookie) + bcolors.ENDC)
    if _client_body:
        #if not 'content:' in _client_body:
        if 'content:' not in _client_body:
            pcre_flag_search = re.search(r'(\/[a-zA-Z]*";)$', _client_body.strip())
            the_old_flags = re.search(r'\/([a-zA-Z]*)', pcre_flag_search.group(0))
            the_new_flags = "/" + 'P' + the_old_flags.group(1) + '";'
            new_line = _client_body.replace(pcre_flag_search.group(0), the_new_flags)
            snort_new_content.append(new_line)
        else:
            if "startswith;" in _client_body:
                _client_body = startswith_convert(_client_body)
           # client_body can support endswith/isdataat
            if "endswith;" in _client_body:
                _client_body = _client_body.replace('endswith;', 'isdataat:!1,relative;')
            client_body_split = _client_body.split("content:")
            del client_body_split[0]
            for item in client_body_split:
                item = "content:" + item
                if 'pcre:"' in item:
                    the_pcres = []
                    pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
                    for hit in pcre_search:
                        item = item.replace(hit, '')
                        hit = pcre_fix(hit, "P")
                        if '/PR' in hit:
                            grab_this = re.search(r'content:\!?"([^"]+)";', item)
                            the_content = grab_this.group(1)
                            the_content = the_content.replace(r'?', r'\?')
                            the_content = the_content.replace(r'.', r'\.')
                            the_content = the_content.replace(r'/', r'\\/')
                            if '|' in the_content:
                                the_hex_list = re.findall(r'\|[^\|]+\|', the_content)
                                for match in the_hex_list:
                                    original_match = match
                                    match = match.replace(' ', '')
                                    match = match.replace('|', '')
                                    match = re.sub(r'([a-fA-F0-9][a-fA-F0-9])', r'\\x\1', match)
                                    the_content = the_content.replace(original_match, match)
                            the_content = the_content.replace(r' ', r'\\x20')
                            hit = hit.replace('pcre:"/^', 'pcre:"/' + the_content)
                            hit = hit.replace('/PR', '/P')
                        the_pcres.append(hit)
                    snort_new_content.append(buffer_reordering(item, " http_client_body;") + " " + " ".join(the_pcres))
                else:
                    snort_new_content.append(buffer_reordering(item, " http_client_body;"))
        if debug_mode:
            print(bcolors.HEADER + "http_client_body: " + bcolors.WARNING + str(_client_body) + bcolors.ENDC)
# BSM - Combine all this into _data to make it part of file_data as there is not http_server_body for snort
# doing so removes the need for snort modifiers on the pcre
# file_data example shows a PCRE without a PCRE modifer for the buffer
# http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004528200000000000000
#    if _server_body:
#        #file.data or http.response_body -> file_data
#        if "startswith;" in _server_body:
#            _server_body = startswith_convert(_server_body)
#        server_body_split = _server_body.split("content:")
#        del server_body_split[0]
#        for item in server_body_split:
#            if 'pcre:"' in item:
#                the_pcres = []
#                pcre_search = re.findall(r'(pcre:"[^;]+;)', item)
#                for hit in pcre_search:
#                    item = item.replace(hit, '')
#                    hit = pcre_fix(hit, "Q")
#                    the_pcres.append(hit)
#                snort_new_content.append(buffer_reordering(item, " http_server_body;") + " " + " ".join(the_pcres) + " ")
#            else:
#                snort_new_content.append(buffer_reordering(item, " http_server_body;"))
#        if debug_mode:
#            print(bcolors.HEADER + "http_server_body: " + bcolors.WARNING + str(_server_body) + bcolors.ENDC)

    #sticky
    if _request_line:
        request_line_has_bsize = False
        if "startswith;" in _request_line:
            _request_line = startswith_convert(_request_line)
        if 'bsize:' in _request_line:
            request_line_has_bsize = True
            _request_line = re.sub(r'bsize:([^;]+);', 'depth:\\1;', _request_line)
        if 'endswith;' in _request_line or 'isdataat:!1,relative;' in _request_line or request_line_has_bsize is True:
            request_line_content_search = re.search(r'^.*content:"([^"]+)";((?!content:).+$)', _request_line)
            old_line = request_line_content_search.group(0)
            request_line_content_initial = request_line_content_search.group(1)
            request_line_content = request_line_content_initial + "|0d 0a|"
            new_line = old_line.replace(request_line_content_initial, request_line_content)
        else:
            new_line = _request_line
        snort_new_content.append(new_line)
        if debug_mode:
            print(bcolors.HEADER + "http_request_line: " + bcolors.WARNING + str(_request_line) + bcolors.ENDC)
    if _accept:
        new_line = do_snort_header_buffer(_accept, "Accept")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_accept: " + bcolors.WARNING + str(_accept) + bcolors.ENDC)
    if _accept_lang:
        new_line = do_snort_header_buffer(_accept_lang, "Accept-Language")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_accept_lang: " + bcolors.WARNING + str(_accept_lang) + bcolors.ENDC)
    if _accept_enc:
        new_line = do_snort_header_buffer(_accept_enc, "Accept-Encoding")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_accept_enc: " + bcolors.WARNING + str(_accept_enc) + bcolors.ENDC)
    if _referer:
        new_line = do_snort_header_buffer(_referer, "Referer")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_referer: " + bcolors.WARNING + str(_referer) + bcolors.ENDC)
    if _connection:
        new_line = do_snort_header_buffer(_connection, "Connection")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_connection: " + bcolors.WARNING + str(_connection) + bcolors.ENDC)
    if _content_type:
        new_line = do_snort_header_buffer(_content_type, "Content-Type")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_content_type: " + bcolors.WARNING + str(_content_type) + bcolors.ENDC)
    if _content_len:
        if 'byte_test:' in _content_len:
            count_byte_test = re.findall(r'byte_test', _content_len)
            if len(count_byte_test) > 1:
                print("THERES NO MULTIPLE BYTE TESTS IN SNORT LAND")
            else:
                #its easy if theres a static number we are checking against
                if re.search(r'byte_test:0,=,\d+,0,string,dec;', _content_len):
                    _content_len = re.sub(r'byte_test:0,=,(\d+),0,string,dec;', 'content:"Content-Length|3a 20|\\1|0d 0a|"; http_header; ', _content_len)
                    snort_new_content.append(_content_len)

                elif 'byte_test:0,>,' in _content_len:

                    byte_num_search = re.search(r'byte_test:0,>,(\d+),', _content_len)
                    byte_num = byte_num_search.group(1)
                    pcre_front = 'pcre:"/^Content-Length\\x3a\\x20(?:'
                    pcre_back = ',}$)/Hmi";'
                    minimum_content_len = int(byte_num) + 1
                    num_list = list(str(minimum_content_len))
                    new_pcre_num1 = []
                    new_pcre_num2 = []
                    max_whatever = len(num_list) + 1

                    #we need to create a total of 3 statements to properly form up the pcre
                    #if the number we are trying to match from byte_test is 800
                    # we need things like 801, 899, 901 and numbers that are much bigger, like 4 or more digits

                    #first round
                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            new_pcre_num1.append(str(num))
                            the_count = the_count - 1
                        else:
                            if int(num) == 9:
                                new_pcre_num1.append('9')
                                the_count = the_count - 1
                            else:
                                new_pcre_num1.append("[" + num + "-9]")
                                the_count = the_count - 1
                    pcre_range_section1 = "".join(new_pcre_num1)

                    #second round
                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            if int(num)+1 == 9:
                                new_pcre_num2.append('9')
                                the_count = the_count - 1
                            else:
                                new_pcre_num2.append("[" + str(int(num)+1) + "-9]")
                                the_count = the_count - 1
                        else:
                            new_pcre_num2.append("[0-9]")
                            the_count = the_count - 1
                    pcre_range_section2 = "".join(new_pcre_num2)

                    pcre_range_section = pcre_range_section1 + "$|" + pcre_range_section2 + "$"
                    snort_new_content.append(pcre_front + pcre_range_section + "|\\d{" + str(max_whatever) + pcre_back)
                elif 'byte_test:0,>=,' in _content_len:

                    byte_num_search = re.search(r'byte_test:0,>=,(\d+),', _content_len)
                    byte_num = byte_num_search.group(1)
                    pcre_front = 'pcre:"/^Content-Length\\x3a\\x20(?:'
                    pcre_back = ',}$)/Hmi";'
                    minimum_content_len = int(byte_num)
                    num_list = list(str(minimum_content_len))
                    new_pcre_num1 = []
                    new_pcre_num2 = []
                    max_whatever = len(num_list) + 1

                    #first round
                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            new_pcre_num1.append(str(num))
                            the_count = the_count - 1
                        else:
                            if int(num) == 9:
                                new_pcre_num1.append('9')
                                the_count = the_count - 1
                            else:
                                new_pcre_num1.append("[" + num + "-9]")
                                the_count = the_count - 1
                    pcre_range_section1 = "".join(new_pcre_num1)

                    #second round
                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            new_pcre_num2.append("[" + str(int(num)+1) + "-9]")
                            the_count = the_count - 1
                        else:
                            new_pcre_num2.append("[0-9]")
                            the_count = the_count - 1
                    pcre_range_section2 = "".join(new_pcre_num2)

                    pcre_range_section = pcre_range_section1 + "$|" + pcre_range_section2 + "$"
                    snort_new_content.append(pcre_front + pcre_range_section + "|\\d{" + str(max_whatever) + pcre_back)

                elif 'byte_test:0,<,' in _content_len:

                    byte_num_search = re.search(r'byte_test:0,<,(\d+),', _content_len)
                    byte_num = byte_num_search.group(1)
                    pcre_front = 'pcre:"/^Content-Length\\x3a\\x20(?:'
                    pcre_back = '$)/Hmi";'
                    minimum_content_len = int(byte_num) - 1
                    num_list = list(str(minimum_content_len))
                    new_pcre_num1 = []
                    new_pcre_num2 = []
                    max_whatever = len(num_list) - 1

                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            new_pcre_num1.append(str(num))
                            the_count = the_count - 1
                        else:
                            if int(num) == 0:
                                new_pcre_num1.append("[0-9]")
                                the_count = the_count - 1
                            else:
                                new_pcre_num1.append("[0-" + num + "]")
                                the_count = the_count - 1
                    pcre_range_section1 = "".join(new_pcre_num1)

                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            if int(num)-1 > 1:
                                new_pcre_num2.append("[1-" + str(int(num)-1) + "]?")
                                the_count = the_count - 1
                            else:
                                new_pcre_num2.append("1?")
                                the_count = the_count - 1
                        elif the_count == 0:
                            new_pcre_num2.append("[0-9]")
                            the_count = the_count - 1
                        else:
                            new_pcre_num2.append("[0-9]?")
                            the_count = the_count - 1
                    pcre_range_section2 = "".join(new_pcre_num2)

                    pcre_range_section = pcre_range_section1 + "$|" + pcre_range_section2

                    if max_whatever > 1:
                        snort_new_content.append(pcre_front + pcre_range_section + pcre_back)
                    else:
                        snort_new_content.append(pcre_front + pcre_range_section + ')/Hmi";')

                elif re.search(r'byte_test:0,<=', _content_len):

                    byte_num_search = re.search(r'byte_test:0,<=,(\d+),', _content_len)
                    byte_num = byte_num_search.group(1)
                    pcre_front = 'pcre:"/^Content-Length\\x3a\\x20(?:'
                    pcre_back = '$)/Hmi";'
                    minimum_content_len = int(byte_num)
                    num_list = list(str(minimum_content_len))
                    new_pcre_num1 = []
                    new_pcre_num2 = []
                    max_whatever = len(num_list)

                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    pcre_range_section1 = "".join(byte_num)

                    the_count = len(num_list)
                    the_count = the_count - 1
                    initial_count = the_count
                    for num in num_list:
                        if the_count == initial_count:
                            if int(num)-1 > 1:
                                new_pcre_num2.append("[1-" + str(int(num)-1) + "]?")
                                the_count = the_count - 1
                            else:
                                new_pcre_num2.append("1?")
                                the_count = the_count - 1
                        elif the_count == 0:
                            new_pcre_num2.append("[0-9]")
                            the_count = the_count - 1
                        else:
                            new_pcre_num2.append("[0-9]?")
                            the_count = the_count - 1
                    pcre_range_section2 = "".join(new_pcre_num2)

                    pcre_range_section = pcre_range_section1 + "$|" + pcre_range_section2

                    if max_whatever > 1:
                        snort_new_content.append(pcre_front + pcre_range_section + pcre_back)
                    else:
                        snort_new_content.append(pcre_front + pcre_range_section + ')/Hmi";')

                else:
                    print(bcolors.WARNING + "I don't know what this is." + bcolors.ENDC)
        else:
            new_line = do_snort_header_buffer(_content_len, "Content-Length")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_content_len: " + bcolors.WARNING + str(_content_len) + bcolors.ENDC)
    if _start:
        if "startswith;" in _start:
            _start = startswith_convert(_start)
        snort_new_content.append("".join(_start))
        if debug_mode:
            print(bcolors.HEADER + "http_start: " + bcolors.WARNING + str(_start) + bcolors.ENDC)
    if _protocol:
        if "startswith;" in _protocol:
            _protocol = startswith_convert(_protocol)
        snort_new_content.append("".join(_protocol))
        if debug_mode:
            print(bcolors.HEADER + "http_protocol: " + bcolors.WARNING + str(_protocol) + bcolors.ENDC)

    ####### HEADER NAMES SUCKS
    if _header_names:
        header_names_endswith = False
        header_names_startswith = False
        if 'fast_pattern;' in _header_names:
            #print bcolors.WARNING + "Well this fast_pattern cant go here anymore, gonna have to find a new place for snort." + bcolors.ENDC)
            _header_names = _header_names.replace('fast_pattern;', '')
        if 'nocase;' in _header_names:
            header_names_nocase = True
            _header_names = _header_names.replace('nocase;', '')
        else:
            header_names_nocase = False
        content_search = re.findall("content:", _header_names)
        if len(content_search) == 0:
            print(bcolors.WARNING + "There is no content in this...something is wrong" + _header_names + bcolors.ENDC)

        hn_split = _header_names.split("content:")
        del hn_split[0]
        for item in hn_split:
            item = "content:" + item
            is_negation = False
            if 'content:!' in item:
                is_negation = True
            null_count_search = re.findall(r"\|?0[dD]\s*0[aA]\|?", item)
            if len(null_count_search) == 0:
                if 'Accept";' in item:
                    item = item + " http_header; "
                else:
                    item = re.sub(r'";', '|3a 20|"; http_header; ', item)
            elif len(null_count_search) == 1:
                if re.search(r'^content:\!"\|0[dD]\s*0[aA]\|', item) or re.search(r'^content:"\|0[dD]\s*0[aA]\|', item):
                    item = item.strip() + " http_header;"
                elif re.search(r'\|0[dD]\s*0[aA]\|";', item):
                    item = re.sub(r'\|0[dD]\s*0[aA]\|', '|3a 20|', item)
                    item = item.strip() + " http_header;"
                else:
                    item = re.sub(r'\|0[dD]\s*0[aA]\|', '\\x3a\\x20[^\\r\\n]+\\r\\n', item)
                    item = re.sub(r'^content:"', 'pcre:"/', item)
                    if header_names_nocase:
                        item = re.sub(r'";', '/Hi";', item)
                    else:
                        item = re.sub(r'";', '/H";', item)
            elif len(null_count_search) == 2:
                # when it's one, it takes things like
                # http.header_names; content:!"|0d 0a|User-Agent|0d 0a|";
                # and turns it into a couple different options
                if re.search(r'^content:\!"\|0[dD]\s*0[aA]\|', item) or re.search(r'^content:"\|0[dD]\s*0[aA]\|', item):
                    # when the content starts with |0d 0a|
                    # turn it into content:"|0d 0a|User-Agent"; http_header;
                    item = item.strip() + " http_header;"
                    # replace the first |0d 0a| with nothing
                    item = re.sub(r'\|0[dD]\s*0[aA]\|', '', item, count=1)
                # replace the last one with |3a 20|
                if re.search(r'\|0[dD]\s*0[aA]\|";', item):
                    item = re.sub(r'\|0[dD]\s*0[aA]\|";', '|3a 20|";', item)
                    if not item.endswith(' http_header;'):
                        item = item + " http_header;"
                # now we need to add a pcre to make sure it's an exact header match
                # take the exact content
                # we shouldn't do this if it's a negation
                #if is_negation == False:
                if is_negation is False:
                    extract_content = re.search(r'content:\!?"([^"]+)"', item).group(1)
                    # strip any hex from the content
                    extract_content = re.sub(r'\|[^\|]+\|', '', extract_content)
                    item = item.strip() + ' pcre:"/^' + extract_content + '\\x3a\\x20[^\\r\\n]+[\\r\\n]+'
                    if header_names_nocase:
                        item = item + '$/Hmi";'
                    else:
                        item = item + '$/Hm";'
            else:
                extract_content = re.search(r'content:\!?"([^"]+)"', item)
                header_names_content = extract_content.group(1)
                #print("header_names_content: " + header_names_content)
                header_names_initial_content = header_names_content
                #print("header_names_initial_content: " + header_names_initial_content)
                #take care of the beginning
                if 'depth:' in item or 'startswith;' in item or 'bsize:' in item:
                    header_names_startswith = True
                    header_names_content = re.sub(r'content:\!?"\|0[dD]\s*0[aA]\|', 'pcre:"/^', item)
                #take care of the end if there is some kind of anchor
                if 'endswith;' in item or r'isdataat:\!1,relative:' in item or re.search(r"\|0d 0a 0d 0a\|", header_names_content):
                    if header_names_nocase:
                        header_names_content = re.sub(
                            r'\|0[dD]\s*0[aA]\|$', r'\\x3a\\x20[^\\r\\n]+\\r\\n/Hmi', header_names_content, count=1
                        )
                    else:
                        header_names_content = re.sub(
                            r'\|0[dD]\s*0[aA]\|$', r'\\x3a\\x20[^\\r\\n]+\\r\\n/Hm', header_names_content, count=1
                        )                #take care of the end if there is no anchor
                if re.search(r'\|0[dD]\s*0[aA]\|', header_names_content) and not header_names_endswith:
                    if header_names_nocase:
                        header_names_content = header_names_content.replace('|0d 0a|"', '\\x3a\\x20[^\\r\\n]+\\r\\n/Hmi')
                    else:
                        header_names_content = header_names_content.replace('|0d 0a|"', '\\x3a\\x20[^\\r\\n]+\\r\\n/Hm')
                    # print "OK THIS IS 3 " + header_names_content
                #replace the ones in the middle
                if re.search(r'\|0[dD]\s*0[aA]\|', header_names_content):
                    # in doing this replacement often the first |0d 0a| becomes a bit of a mess,
                    header_names_content = header_names_content.replace('|0d 0a|', '\\x3a\\x20[^\\r\\n]+\\r\\n')
                    # if header_names_content now startswith the previous crap, trim it up
                    if header_names_content.startswith('\\x3a\\x20[^\\r\\n]+\\r\\n'):
                        header_names_content = re.sub(r'\\x3a\\x20\[\^\\r\\n\]\+\\r\\n', '', header_names_content, count=1)
                item = item.replace(header_names_initial_content, header_names_content)
                if '/Hm' in item:
                    item = re.sub(r'^content:"', 'pcre:"/^', item)
                else:
                    item = re.sub(r'^content:"', 'pcre:"/', item)
                item = item.replace('content:', 'pcre:')
                item = item.replace('content:"pcre:', 'pcre:')
                item = item.replace('pcre:"pcre:', 'pcre:')

            if re.search(r'(startswith;|depth:|bsize:|endswith;|isdataat:\!1,relative;)', item):
                item = re.sub(r'(\s*startswith;\s*|\s*depth:\d+;\s*|\s*bsize:\d+;\s*|\s*endswith;\s*|\s*isdataat:\!1,relative;\s*)', '', item)

            if '";";' in item:
                item = item.replace('";";', '";')

            if ';";' in item:
                item = item.replace(';";', '";')

            if item.endswith('\\r\\n";'):
                if header_names_startswith:
                    if header_names_nocase:
                        item = item.replace('\\r\\n";', '\\r\\n/Hi";')
                    else:
                        item = item.replace('\\r\\n";', '\\r\\n/H";')
                else:
                    if header_names_nocase:
                        item = item.replace('\\r\\n";', '\\r\\n/Hmi";')
                    else:
                        item = item.replace('\\r\\n";', '\\r\\n/Hm";')
            snort_new_content.append(item)
        if debug_mode:
            print(bcolors.HEADER + "http_header_names: " + bcolors.WARNING + str(_header_names) + bcolors.ENDC)

    if _response_line:
        if "startswith;" in _response_line:
            _response_line = startswith_convert(_response_line)
        snort_new_content.append("".join(_response_line))
        if debug_mode:
            print(bcolors.HEADER + "http_response_line: " + bcolors.WARNING + str(_response_line) + bcolors.ENDC)
    if _server:
        new_line = do_snort_header_buffer(_server, "Server")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http.server: " + bcolors.WARNING + str(_server) + bcolors.ENDC)
    if _location:
        new_line = do_snort_header_buffer(_location, "Location")
        if "http_header;" in new_line:
            snort_new_content.append(new_line)
        else:
            snort_new_content.append(new_line + " http_header; ")
        if debug_mode:
            print(bcolors.HEADER + "http_location: " + bcolors.WARNING + str(_location) + bcolors.ENDC)
    if _data or _server_body:
        if "startswith;" in _data:
            _data = startswith_convert(_data)

        if "startswith;" in _server_body:
            _server_body = startswith_convert(_server_body)

        # file_data can support endswith via isdataat:!1,relative
        if "endswith;" in _data:
            _data = _data.replace('endswith;', 'isdataat:!1,relative;')

        if "endswith;" in _server_body:
            _server_body = _server_body.replace('endswith;', 'isdataat:!1,relative;')

        if _data and _server_body:
            if 'file_data' in _data:
                # and then shove the contents into _data
                _data = _data + " " + _server_body
            else:
                _data = "file_data; " + _data + " " + _server_body

        elif _server_body and not _data:
            # response_body has already been stripped out, so  then shove it all into data
            _data = "file_data; " + _server_body

        # if we only have _data, then we just shove it in down below.
        snort_new_content.append(_data)
        if debug_mode:
            print(bcolors.HEADER + "file_data: " + bcolors.WARNING + str(_data) + bcolors.ENDC)

    ## Add the Trailers
    for item in trailer_rule_contents:
        snort_new_content.append(item)

    #compile it
    snort_rule_guts = " ".join(snort_new_content)
    #check for any double spaces
    snort_rule_guts = re.sub(r';\s{2,}', '; ', snort_rule_guts)

    #print the new rule
    fresh_rule = snort_rule_front + " " + snort_rule_guts + " " + snort_rule_backend

    #suri4 rule rollback - update endswith;
    if 'endswith;' in fresh_rule:
        fresh_rule = fresh_rule.replace('endswith;', 'isdataat:!1,relative; ')

    #suri4 rule rollback - update bsize;
    if 'bsize:' in fresh_rule:
        fresh_rule = re.sub(r'bsize:(\d+);', 'depth:\\1; isdataat:!1,relative;', fresh_rule)

    #dotprefix TODO
    if 'dotprefix;' in fresh_rule:
        print(bcolors.WARNING + "This script does not yet support the dotprefix tag" + bcolors.ENDC)

    #check the rule again for any double spaces
    fresh_rule = re.sub(r';\s{2,}', '; ', fresh_rule)

    #clean up some spaces for readability for whitespace
    if '| ' in fresh_rule:
        fresh_rule = fresh_rule.replace("| ", " 20|")
    if ' ";' in fresh_rule:
        fresh_rule = fresh_rule.replace(' ";', '|20|";')
    if 'content:" ' in fresh_rule:
        fresh_rule = fresh_rule.replace('content:" ', 'content:"|20|')

    #print bcolors.OKGREEN + "\n==== Suricata 5 ====" + bcolors.ENDC)
    #print suri5_rule

    #print bcolors.OKGREEN + "\n==== Snort 2.9 ====" + bcolors.ENDC)
    #print fresh_rule

    proback_rule = re.sub(r'msg:"[^"]+"; ','', fresh_rule) #remove message
    proback_rule = re.sub(r'\s*classtype:.+$',')', proback_rule) #remove end starting with classtype
    proback_rule = re.sub(r'\s*reference:.+$',')', proback_rule) #remove end starting with reference
    proback_rule = re.sub(r'\s*metadata:.+$',')', proback_rule) #remove metadata
    #print bcolors.OKGREEN + "\n==== Proback ====" + bcolors.ENDC)
    #print proback_rule
    #because the var below is never used, this if statement can be commented out.
    #if review_this_rule:
        #this var is never used.
        #halt = input("Review this and press [ENTER] to continue...")

    return proback_rule, fresh_rule


def startswith_convert(the_thing):
    the_content = re.search(r'content:"([^"]+)".+startswith;', the_thing)
    content_guts = the_content.group(1)
    no_hex = re.sub(r'\|[^|]+\|', '', content_guts)
    ascii_len = len(no_hex)
    hex_byte_things = re.findall(r'\|\s*(?:[a-fA-F0-9][a-fA-F0-9]\s*)+\|', content_guts)
    hex_byte_count = []
    for item1 in hex_byte_things:
        hex_byte_item = re.findall(r'[a-fA-F0-9][a-fA-F0-9]', item1)
        for item2 in hex_byte_item:
            hex_byte_count.append(item2)
    hex_len = len(hex_byte_count)
    bsize_len = hex_len + ascii_len
    the_depth = "depth:" + str(bsize_len) + ";"
    the_thing = the_thing.replace('startswith;', the_depth)
    return the_thing
##End stapled musketeer logic.

# Define the vendor name for the msg keyword
# Menu users are given a list of options
# If the user specified an input file, we try to grab the value from the vendor column
# If that fails (either for being an invalid integer value, or ValueError), fall back to manual input.
# Manual entry loops if the integer input is greater than 8, or if ValueError is thrown.
# Manual entry also includes a default option of "8", which will exit the script on empty input.
def rule_loop_vendor_name(row):
    if args.infile:
        try:
            arg = int(row.get('vendor'))
            if arg > 8 or arg <= 0:
                print("\n"+bcolors.FAIL+"Invalid value detected. Must be an integer value between 1 and 7. Fix your CSV file, please. Falling back to manual input."+bcolors.ENDC+"\n")
                print("What is the Vendor Name (Default = 8)?\n")
                choices = {
                "1":"Asus" ,
                "2":"D-Link" ,
                "3":"Linksys" ,
                "4":"Tenda" ,
                "5":"Totolink" ,
                "6":"TP-Link" ,
                "7":"Other"  ,
                "8":"*Exit"
                }
                while True:
                    try:
                        for k,v in choices.items():
                            print(str(k)+': ' + str(v))
                        arg = int(input("Please Choose: ") or 8)
                        break
                    except ValueError:
                        print("Please enter a number for the vendor, or hit Enter to exit.")
        except Exception as e:
            print("\n"+bcolors.FAIL+"Exception Encountered:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.FAIL+"Falling back to manual selection for vendor. Fix your CSV file, please."+bcolors.ENDC+"\n")
            print("What is the Vendor Name (Default = 8)?\n")
            choices = {
            "1":"Asus" ,
            "2":"D-Link" ,
            "3":"Linksys" ,
            "4":"Tenda" ,
            "5":"Totolink" ,
            "6":"TP-Link" ,
            "7":"Other"  ,
            "8":"*Exit"
            }
            while True:
                try:
                    for k,v in choices.items():
                        print(str(k)+': ' + str(v))
                    arg = int(input("Please Choose: ") or 8)
                    break
                except ValueError:
                    print("Please enter a number for the vendor, or hit Enter to exit.")
    else:
        print("What is the Vendor Name (Default = 8)?\n")
        choices = {
            "1":"Asus" ,
            "2":"D-Link" ,
            "3":"Linksys" ,
            "4":"Tenda" ,
            "5":"Totolink" ,
            "6":"TP-Link" ,
            "7":"Other"  ,
            "8":"*Exit"
        }
        while True:
            try:
                for k,v in choices.items():
                    print(str(k)+': ' + str(v))
                arg = int(input("Please Choose: ") or 8)
                break
            except ValueError:
                print("Please enter a number for the vendor, or hit Enter to exit.")
    while True:
        if arg == 1:
            vendor = "Asus"
            return vendor
        if arg == 2:
            vendor = "D-Link"
            return vendor
        if arg == 3:
            vendor = "Linksys"
            return vendor
        if arg == 4:
            vendor = "Tenda"
            return vendor
        if arg == 5:
            vendor = "Totolink"
            return vendor
        if arg == 6:
            vendor = "TP-Link"
            return vendor
        if arg == 7:
            if args.infile:
                try:
                    if int(row.get('vendor')) == 7 and str(row.get('vendor_custom')) != "":
                        vendor = str(row.get('vendor_custom'))
                        return vendor
                    print("\n"+bcolors.FAIL+"vendor_custom Cannot be blank. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    while True:
                        vendor = input("What is the Name of the IoT Vendor? ")
                        if vendor == "":
                            print("\n"+bcolors.FAIL+"Cannot be blank. Please enter a value."+bcolors.ENDC+"\n")
                        else:
                            return vendor
                    break
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.FAIL+"Falling back to manual input for IoT Vendor name. Next time, please fix your CSV file."+bcolors.ENDC+"\n")
                    while True:
                        vendor = input("What is the Name of the IoT Vendor? ")
                        if vendor == "":
                            print("\n"+bcolors.FAIL+"Cannot be blank. Please enter a value."+bcolors.ENDC+"\n")
                        else:
                            return vendor
                    break
            else:
                while True:
                    vendor = input("What is the Name of the IoT Vendor? ")
                    if vendor == "":
                        print("\n"+bcolors.FAIL+"Cannot be blank. Please enter a value."+bcolors.ENDC+"\n")
                    else:
                        return vendor
                break
        if arg == 8:
            sys.exit()
        else:
            print("Invalid value.\n")

# The user is given the option of inputting a URL to serve as a reference.
# This function only supports URL references, and strips 'http://', 'https://', and 'reference:url,' from the start of the string.
# We also remove semicolons (;) from the end of the string, if present.
# Same as the previous function, there's some try/catch logic to capture errors and falls back to manual input
# This function will accept any input as a valid url, and I'm not willing to pour the effort in to do URL validation.
def rule_reference(row):
    if args.infile:
        try:
            reference = str(row.get('reference_url'))
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.FAIL+"Falling back to manual input for reference_url. Next time, please fix your CSV file."+bcolors.ENDC+"\n")
            print("\nWhat is the reference URL?\n")
            reference = input("Insert your reference value: ")
    else:
        print("\nWhat is the reference URL?\n")
        reference = input("Insert your reference value: ")
    reference = reference.strip()
    if reference.startswith('reference:url,'):
        reference = reference[14:]
    if reference.startswith('https://'):
        reference = reference[8:]
    if reference.startswith('http://'):
        reference = reference[7:]
    if reference.endswith(";"):
        reference = reference.rstrip(";")
    return reference

# I want to give users the option of submitting their urls to the wayback machine
# For CSV users, if extracting the integer value fails, we fall back to NOT archiving urls.
# For manual entry, the default is also not to archive urls.
# If url archive is picked, and users haven't input valid wayback machine API creds
# The script gives them a chance to enter their creds, or skip the archive attempt entirely.
# Note that we do NOT validate the credentials. That's the user's responsibility to give this thing the right credentials.
def wayback_machine_submit(rule_ref, wayback_machine_creds, row):
    if rule_ref != "":
        if args.infile:
            try:
                arg = int(row.get('wbm_archive'))
                if arg > 2 or arg <= 0:
                    print("\n"+bcolors.WARNING+"Invalid value detected. Must be an integer value between 1 and 2. Defaulting to option 1 (no archive). Next time, fix your CSV please."+bcolors.ENDC+"\n")
                    arg = 1
            except Exception as e:
                print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                print(e)
                print("\n"+bcolors.WARNING+"Defaulting to option 1 (no archive). Next time, fix your CSV please."+bcolors.ENDC+"\n")
                arg = 1
        else:
            print("\nWould you like to submit the URL to the internet archive (Default = 1)?\n")
            choices = {
                "1":"*No" ,
                "2":"Yes"
            }
            while True:
                try:
                    for k,v in choices.items():
                        print(str(k)+': ' + str(v))
                    arg = int(input("Please Choose: ") or 1)
                    break
                except ValueError:
                    print("\n"+bcolors.WARNING+"Please Enter a valid Number, or hit Enter to use the default setting (don't archive)."+bcolors.ENDC+"\n")
        if arg == 2:
            if wayback_machine_creds in ('', '[access_key]:[secret_key]'):
                print("\n"+bcolors.WARNING+"You didn't supply a valid \"[access_key]:[secret_key]\" string.\nThis is absolutely necessary for us to submit archive requests.\nIf you haven't already, create an account on archive.org, then visit:\nhttps://archive.org/account/s3.php to acquire your Access and Secret keys."+bcolors.ENDC+"\n")
                while True:
                    try:
                        print("\nWould you like to enter your creds now?\n")
                        choices = {
                            "1":"*No" ,
                            "2":"Yes"
                        }
                        for k,v in choices.items():
                            print(str(k)+': ' + str(v))
                        wayback_api_creds_catch = int(input("Please choose: ") or 1)
                        break
                    except ValueError:
                        print("Please Enter a valid Number, or hit Enter to use the default setting (don't archive).")
                while True:
                    if wayback_api_creds_catch == 1:
                        print("Skipping archive.")
                        return
                    if wayback_api_creds_catch == 2:
                        print("\nPlease input your wayback machine S3 Api creds in the format: [access_key]:[secret_key]\n")
                        wayback_machine_creds = input("Please enter your [access_key]:[secret_key] combo: ")
                        if wayback_machine_creds == "":
                            print("\n"+bcolors.WARNING+"Entry cannot be blank."+bcolors.ENDC+"\n")
                        else:
                            break
            url = "https://web.archive.org/save"
            headers = {
            "User-Agent" : "IoT-Hunter"  ,
            "Authorization" : "LOW "+wayback_machine_creds  ,
            "X-Accept-Reduced-Priority" : "1"
            }
            data = {
            "url" : "https://"+rule_ref  ,
            "capture_all" : "1"  ,
            "delay_wb_availability" : "1"  ,
            "skip_first_archive" : "1"  ,
            "capture_outlinks" : "1"  ,
            "capture_screenshot" : "1"
            }
            #try to make a regular SSL request. But if there's a certificate error, don't bomb out.
            try:
                r = requests.post(url, headers=headers, data=data, timeout=20)
            except requests.exceptions.SSLError:
                r = requests.post(url, headers=headers, data=data, verify=False, timeout=20)
            if r.status_code == 200:
                html = r.text
                try:
                    save_page_dialog = re.search(r'Saving Page', html)
                    if "Saving page" in save_page_dialog.group():
                        try:
                            time_delay_dialog = re.search(r'The capture will start', html)
                            if "The capture will start" in time_delay_dialog.group():
                                print("API request Successful. "+time_delay_dialog.group())
                        except TypeError:
                            print("API Request Successful, however I wasn't able to find the time delay dialogue to determine when the wayback machine would archive the page.")
                            m = re.findall(r'\<p\>.*?\<\/', r.text)
                            print("Here are the paragraph tags I could find:\n")
                            print(*m, sep = '\n\n')
                except AttributeError:
                    print("Couldn't find the Saving page dialogue. Here are all the paragraph tags I could find in the HTML:\n")
                    try:
                        m = re.findall(r'\<p\>.*?\<\/', r.text)
                        print(*m, sep = '\n\n')
                    except TypeError:
                        print("Just kidding, I can't even do that. Here's the http status code: "+str(r.status_code))
                        print("This archival request probably failed.")
            else:
                print("API Request threw HTTP status code: "+str(r.status_code))
                print("This archival request very likely failed.")

# Incldue the option to record a CVE number, if present as a reference and in the rule msg
# If the value starts with 'CVE-', 'cve-', or 'reference:cve,', or ends with a semicolon, those values are stripped from the input.
def cve_reference(row):
    if args.infile:
        try:
            cve_n = str(row.get('reference_cve'))
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.FAIL+"Falling back to manual input for reference_cve. Next time, please fix your CSV file."+bcolors.ENDC+"\n")
            print("\nWhat is the reference URL?")
            cve_n = input("Insert your reference value: ")
    else:
        print("\nWhat is the CVE number? (Format:XXXX-XXXX)")
        cve_n = input("Insert your CVE number: ")
    cve_n = cve_n.strip()
    if cve_n.startswith("reference:cve,"):
        cve_n = cve_n[14:]
    if cve_n.startswith("CVE-") or cve_n.startswith("cve-"):
        cve_n = cve_n[4:]
    if cve_n.endswith(";"):
        cve_n = cve_n.rstrip(";")
    return cve_n

#Need to know what HTTP param to use for the http.method
def rule_loop_http_method(row):
    if args.infile:
        try:
            arg = int(row.get('http_meth'))
            if arg > 6 or arg <= 0:
                print("\n"+bcolors.WARNING+"Invalid value detected. Must be an integer value between 1 and 2. Defaulting to option 1 (POST). Next time, fix your CSV, please."+bcolors.ENDC+"\n")
                arg = 1
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.WARNING+"Invalid value detected. Defaulting to option 1 (POST). Next time, fix your CSV, please."+bcolors.ENDC+"\n")
            arg = 1
    else:
        print("\nWhat is the HTTP Method (Default = 1)?\n")
        choices = {
            "1":"*POST" ,
            "2":"GET" ,
            "3":"PUT" ,
            "4":"PATCH" ,
            "5":"HEAD" ,
            "6":"DELETE"
        }
        for k,v in choices.items():
            print(str(k)+': ' + str(v))
        while True:
            try:
                arg = int(input("Please Choose: ") or 1)
                break
            except ValueError:
                print("Please enter a number for the HTTP method, or hit Enter for the default value of POST.")
    while True:
        if arg == 1:
            http_method = "POST"
            return http_method
        if arg == 2:
            http_method = "GET"
            return http_method
        if arg == 3:
            http_method = "PUT"
            return http_method
        if arg == 4:
            http_method = "PATCH"
            return http_method
        if arg == 5:
            http_method = "HEAD"
            return http_method
        if arg == 6:
            http_method = "DELETE"
        print("Invalid/Unsupported value.\n")

# We want to know what the URI structure is for the vuln. Does it use boafrm, goform, cstecgi.cgi, or something entirely different?
# CSV use will try to extract uri_struct. If it's not present or invalid, fall back to manual, menu-driven input.
# If option 4 is selected, pull the URI from uri_struct_custom, and use that to build the http uri content match, and message.
# if that's empty/invalid, or CSV input isn't being used, fallback to manual input.
def rule_loop_http_framework(row):
    if args.infile:
        try:
            arg = int(row.get('uri_struct'))
            if arg > 4 or arg <= 0:
                print("\n"+bcolors.FAIL+"Invalid value detected. Must be an integer value between 1 and 4. Falling back to manual entry for uri_struct. Next time, fix your CSV, please."+bcolors.ENDC+"\n")
                print("\nWhat is the IoT POST/GET URI structure (Default = 4)?\n")
                choices={
                    "1":"/boafrm/" ,
                    "2":"/goform/" ,
                    "3":"/cgi-bin/cstecgi.cgi" ,
                    "4":"*Custom URI"
                }
                while True:
                    try:
                        for k,v in choices.items():
                            print(str(k)+': ' + str(v))
                        arg = int(input("Please Choose: ") or 4)
                        break
                    except ValueError:
                        print("Please enter a number that indicates the URI pattern for the vulnerability, or hit Enter for the default value of Inputting a Custom URI.")
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.FAIL+"Invalid value detected. Must be an integer value between 1 and 4. Falling back to manual entry for uri_struct. Next time, fix your CSV, please."+bcolors.ENDC+"\n")
            print("\nWhat is the IoT POST/GET URI structure (Default = 4)?\n")
            choices={
                "1":"/boafrm/" ,
                "2":"/goform/" ,
                "3":"/cgi-bin/cstecgi.cgi" ,
                "4":"*Custom URI"
            }
            while True:
                try:
                    for k,v in choices.items():
                        print(str(k)+': ' + str(v))
                    arg = int(input("Please Choose: ") or 4)
                    break
                except ValueError:
                    print("Please enter a number that indicates the URI pattern for the vulnerability, or hit Enter for the default value of Inputting a Custom URI.")
    else:
        print("\nWhat is the IoT POST/GET URI structure (Default = 4)?\n")
        choices={
            "1":"/boafrm/" ,
            "2":"/goform/" ,
            "3":"/cgi-bin/cstecgi.cgi" ,
            "4":"*Custom URI"
        }
        while True:
            try:
                for k,v in choices.items():
                    print(str(k)+': ' + str(v))
                arg = int(input("Please Choose: ") or 4)
                break
            except ValueError:
                print("Please enter a number that indicates the URI pattern for the vulnerability, or hit Enter for the default value of Inputting a Custom URI.")
        #If boafrm or goform, are chosen, We need to know the vulnerable URI endpoint to create the full vulnerable URI. Then for the rule message, we strip out /boafrm/ or /goform/ to make a cleaner rule msg.
    while True:
        if arg == 1:
            if args.infile:
                try:
                    if int(row.get('uri_struct')) == 1 and str(row.get('uri_struct_end')) != "":
                        http_f = str(row.get('uri_struct_end'))
                    else:
                        print("\n"+bcolors.FAIL+"Invalid value for uri_struct_end. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        http_f = str(input("Please input the Rest of the URI: "))
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.WARNING+"Invalid value detected. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    http_f = str(input("Please input the Rest of the URI: "))
            else:
                print("\nPlease input the rest of the vulnerable URI, after \"/boafrm/\".\n")
                http_f = str(input("Please input the Rest of the URI: "))
            http_frame = "/boafrm/"+http_f.strip()
            http_frame_msg = http_frame.replace ("/boafrm/", "")
            return http_frame, http_frame_msg
        if arg == 2:
            if args.infile:
                try:
                    if int(row.get('uri_struct')) == 2 and str(row.get('uri_struct_end')) != "":
                        http_f = str(row.get('uri_struct_end'))
                    else:
                        print("\n"+bcolors.FAIL+"Invalid value for uri_struct_end. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        http_f = str(input("Please input the Rest of the URI: "))
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.WARNING+"Invalid value detected. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    http_f = str(input("Please input the Rest of the URI: "))
            else:
                print("\nPlease input the rest of the vulnerable URI, after \"/goform/\".\n")
                http_f = str(input("Please input the Rest of the URI: "))
            http_frame = "/goform/"+http_f.strip()
            http_frame_msg = http_frame.replace ("/goform/", "")
            return http_frame, http_frame_msg
        if arg == 3:
            #just like with options 1 and 2, we stript out the start of the url, only this time, we create a list with .split on "/" chars, and print the last string in the list (-1)
            http_frame = "/cgi-bin/cstecgi.cgi"
            http_frame_msg = http_frame
            http_frame_msg = http_frame_msg.rsplit('/', maxsplit=1)[-1]
            return http_frame, http_frame_msg
        if arg == 4:
            if args.infile:
                try:
                    if int(row.get('uri_struct')) == 4 and str(row.get('uri_struct_custom')) != "":
                        http_frame = str(row.get('uri_struct_custom'))
                    else:
                        print("\n"+bcolors.FAIL+"Invalid value for uri_struct_custom. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        http_frame = str(input("What is the custom URI struct? (from the first \"/\" to the first \"?\", or last \"/\" CASE SENSITIVE!: "))
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.WARNING+"Invalid value detected for uri_struct_custom. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    http_frame = str(input("What is the custom URI struct? (from the first \"/\" to the first \"?\", or last \"/\" CASE SENSITIVE!: "))
            else:
                http_frame = str(input("\nWhat is the custom URI struct? (from the first \"/\" to the first \"?\", or last \"/\" CASE SENSITIVE!: "))
            http_frame = http_frame.strip()
            http_frame_m1 = http_frame
            if http_frame_m1.endswith("/"):
                http_frame_m1 = http_frame_m1.rstrip("/")
            http_frame_msg = http_frame_m1.rsplit('/', maxsplit=1)[-1]
            if http_frame_msg.endswith("?"):
                http_frame_msg = http_frame_msg.rstrip("?")
            if http_frame.endswith("?"):
                http_frame = http_frame.replace("?", "|3f|")
            return http_frame, http_frame_msg
        print("\n"+bcolors.FAIL+"Invalid/Unsupported value. Try again."+bcolors.ENDC+"\n")

#If the rule is a GET request, the parameter goes in the URI
#this function extracts the paramter from the uri_parameter field
#if the CSV value is blank, otherwise throws an exception, or csv input isn't being used, fall back to the manual menu
def rule_loop_uri_param_get(row):
    if args.infile:
        try:
            if str(row.get('uri_parameter')) != "":
                uri_param_g = str(row.get('uri_parameter'))
            else:
                print("\n"+bcolors.FAIL+"Invalid value detected for uri_parameter. Falling back to manual entry. Next time, fix your CSV, please."+bcolors.ENDC+"\n")
                print("\nYou've chosen GET, HEAD or DELETE as your HTTP Method and a URI that isn't /cgi-bin/cstecgi.cgi.\nWhat is the vulnerable URI parameter? CASE SENSITIVE!\n")
                while True:
                    uri_param_g = input("Please input the vulnerable parameter: ")
                    if uri_param_g == "":
                        print("\n"+bcolors.FAIL+"Parameter cannot be blank. Please enter the vulnerable URI parameter."+bcolors.ENDC+"\n")
                    else:
                        break
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.WARNING+"Invalid value detected. Falling back to manual entry. Next time, please fix your CSV."+bcolors.ENDC+"\n")
            print("\nYou've chosen GET, HEAD, or DELETE as your HTTP Method and a URI that isn't /cgi-bin/cstecgi.cgi.\nWhat is the vulnerable URI parameter? CASE SENSITIVE!\n")
            while True:
                uri_param_g = input("Please input the vulnerable parameter: ")
                if uri_param_g == "":
                    print("\n"+bcolors.FAIL+"Parameter cannot be blank. Please enter the vulnerable URI parameter."+bcolors.ENDC+"\n")
                else:
                    break
    else:
        print("\nYou've chosen GET, HEAD, or DELETE as your HTTP Method and a URI that isn't /cgi-bin/cstecgi.cgi.\nWhat is the vulnerable URI parameter? CASE SENSITIVE!\n")
        while True:
            uri_param_g = input("Please input the vulnerable parameter: ")
            if uri_param_g == "":
                print("\n"+bcolors.FAIL+"Parameter cannot be blank. Please enter the vulnerable URI parameter."+bcolors.ENDC+"\n")
            else:
                break
    uri_param_g = uri_param_g.strip()
    if not uri_param_g.endswith("="):
        uri_param_g = uri_param_g+"="
    uri_param_g = uri_param_g.replace("=", "|3d|")
    uri_param_msg = uri_param_g.rstrip("=")
    uri_param_msg = re.sub(r'(?:\||3d|22|3a)', '', uri_param_msg)
    return uri_param_g, uri_param_msg

# Need to know if request body vars are key/value pairs using an equal sign (=), or if they use JSON.
# For CSV users, we try to extract the value in the colum p_body_param_type
# if that fails, or for non-csv users, we'll ask users to choose the parameter type.
def body_parameter_type(row):
    if args.infile:
        try:
            arg = int(row.get('p_body_param_type'))
            if arg > 2 or arg <= 0:
                print("\n"+bcolors.WARNING+"Invalid value detected. Must be an integer value between 1 and 2. Defaulting to option 1 (Equal Sign Key/Value Pair). Next time, fix your CSV, please."+bcolors.ENDC+"\n")
                arg = 1
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.WARNING+"Invalid value detected. Non-integer value. Defaulting to option 1 (Equal Sign Key/Value Pair). Next time, fix your CSV, please."+bcolors.ENDC+"\n")
            arg = 1
    else:
        print("\nWhat type of HTTP Parameter is vulnerable (Default = 1)?\n")
        choices = {
            "1":"*Equal sign (=) Key/Value pair (e.g., vuln=aaaaaaaaaaaaaaaaaa)" ,
            "2":"JSON  Key/Value pair (e.g., \"vuln\":\"aaaaaaaaaaaaaaaa\")"
        }
        while True:
            try:
                for k,v in choices.items():
                    print(str(k)+': ' + str(v))
                arg = int(input("Please Choose: ") or 1)
                break
            except ValueError:
                print("Please enter a number, or hit Enter for the default value of Equal sign (=) Key/Value Pairing.")
    while True:
        if arg == 1:
            body_param_type = "Equal"
            return body_param_type
        if arg == 2:
            body_param_type = "JSON"
            return body_param_type
        print("Invalid/Unsupported value.\n")

#If the rule is a POST/PUT/PATCH (or sometimes DELETE) request, the parameter goes in the request body
#this function extracts the paramter either via CSV input (p_body_param column) or manual input.
#if the CSV value is blank, otherwise throws an exception, or csv input isn't being used, fall back to the manual menu
def rule_loop_body_param(p_type, row):
    if args.infile:
        try:
            if str(row.get('p_body_param')) != "":
                body_param_p = str(row.get('p_body_param'))
            else:
                print("\n"+bcolors.FAIL+"Invalid value detected for p_body_param. Falling back to manual entry. Next time, fix your CSV please."+bcolors.ENDC+"\n")
                print("\nYou've chosen POST, PUT, PATCH or DELETE as your HTTP Method.\nWhat is the vulnerable request body parameter?\n ")
                print("CASE SENSITIVE, with the trailing \"=\" sign! or, if JSON, WITH quotation marks (\") around the parameter!\n")
                while True:
                    body_param_p = input("Please input the vulnerable parameter: ")
                    if body_param_p == "":
                        print("Parameter cannot be blank. Please enter the vulnerable request body parameter")
                    else:
                        body_param_p= body_param_p.strip()
                        break
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.FAIL+"Invalid value detected for p_body_param. Falling back to manual entry. Next time, fix your CSV please."+bcolors.ENDC+"\n")
            print("\nYou've chosen POST, PUT, PATCH, or DELETE as your HTTP Method.\nWhat is the vulnerable request body parameter?\n ")
            print("CASE SENSITIVE, with the trailing \"=\" sign! or, if JSON, WITH quotation marks (\") around the parameter!\n")
            while True:
                body_param_p = input("Please input the vulnerable parameter: ")
                if body_param_p == "":
                    print("Parameter cannot be blank. Please enter the vulnerable request body parameter")
                else:
                    body_param_p= body_param_p.strip()
                    break
    else:
        print("\nYou've chosen POST, PUT, PATCH, or DELETE as your HTTP Method.\nWhat is the vulnerable request body parameter?\n ")
        print("CASE SENSITIVE, with the trailing \"=\" sign! or, if JSON, WITH quotation marks (\") around the parameter!\n")
        while True:
            body_param_p = input("Please input the vulnerable parameter: ")
            if body_param_p == "":
                print("Parameter cannot be blank. Please enter the vulnerable request body parameter")
            else:
                body_param_p= body_param_p.strip()
                break
    #If the http body is JSON formatted, We have to normalize the content match, and we have to hex escape the double quotes for Suricata.
    if p_type == "JSON":
        if "=" in body_param_p:
            body_param_p = body_param_p.replace("=", "")
        if not body_param_p.startswith("\""):
            body_param_p = "\""+body_param_p
        if not body_param_p.endswith("\""):
            body_param_p = body_param_p+"\""
        body_param_p = re.sub('(?:\x3a$|\x3a\x22$|\x3a\x20\x22$)', '', body_param_p)
        body_param_p = body_param_p.replace("\"", "|22|")
        body_param_msg = body_param_p
    if p_type == "Equal":
        if "\"" in body_param_p:
            body_param_p = body_param_p.replace("\"", "")
        if ":" in body_param_p:
            body_param_p = body_param_p.replace(":", "")
        if not body_param_p.endswith("="):
            body_param_p = body_param_p+"="
        body_param_p = body_param_p.replace("=", "|3d|")
        body_param_msg = body_param_p.rstrip("=")
    body_param_msg = re.sub(r'(?:\||3d|22|3a)', '', body_param_msg)
    return body_param_p, body_param_msg

# rules that use cstecgi.cgi are slightly different.
# We want to utilize the topicurl JSON parameter for the fast_pattern, the rule msg, and apply a within statement to the actual topicurl parameter.
# We want to use the within modifier. Sometimes the parameter includes spaces in the JSON, sometimes it doesn't:
# "topicurl" : "
# "topicurl":"
# "topicurl": "
# to catch all these variations, I add 5 to the length of the topicurl parameter, and use that for the within keyword
def topicurl_set(p_type, row):
    if args.infile:
        try:
            if str(row.get('topicurl')) != "":
                topicurl_param = str(row.get('topicurl'))
            else:
                print("\n"+bcolors.FAIL+"Invalid value detected for topicurl. Falling back to manual entry. Next time, fix your CSV please."+bcolors.ENDC+"\n")
                print("You have selected /cgi-bin/cstecgi.cgi as the uri, and POST, PUT, PATCH, or DELETE as the HTTP method. Please enter the topicurl parameter value: ")
                while True:
                    topicurl_param = input("Please input the vulnerable topicurl parameter: ")
                    if topicurl_param == "":
                        print("\n"+bcolors.WARNING+"topicurl parameter value cannot be blank."+bcolors.ENDC+"\n")
                    else:
                        break
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.FAIL+"Invalid value detected for topicurl. Falling back to manual entry. Next time, fix your CSV please."+bcolors.ENDC+"\n")
            print("\nYou've chosen POST, PUT, PATCH, or DELETE as your HTTP Method and a URI that isn't /cgi-bin/cstecgi.cgi.\nWhat is the vulnerable URI parameter? CASE SENSITIVE!\n")
            while True:
                topicurl_param = input("Please input the vulnerable topicurl parameter: ")
                if topicurl_param == "":
                    print("\n"+bcolors.WARNING+"topicurl parameter value cannot be blank."+bcolors.ENDC+"\n")
                else:
                    break
    else:
        print("You have selected /cgi-bin/cstecgi.cgi as the uri, and POST, PUT, PATCH, or DELETE as the HTTP method. Please enter the topicurl parameter's value: ")
        while True:
            topicurl_param = input("Please input the vulnerable topicurl parameter: ")
            if topicurl_param == "":
                print("\n"+bcolors.WARNING+"topicurl parameter value cannot be blank."+bcolors.ENDC+"\n")
            else:
                break
    if p_type == "JSON":
        if topicurl_param.endswith("="):
            topicurl_param = topicurl_param.replace("=", "")
        if topicurl_param.endswith(":"):
            topicurl_param = topicurl_param.replace(":", "")
        if topicurl_param.endswith(":\""):
            topicurl_param = topicurl_param.replace(":\"", "\"")
        if not topicurl_param.startswith("\""):
            topicurl_param = "\""+topicurl_param
        if not topicurl_param.endswith("\""):
            topicurl_param = topicurl_param+"\""
        topicurl_within = str(len(topicurl_param) + 5)
        topicurl_param = topicurl_param.replace("\"", "|22|")
        topicurl_msg = topicurl_param.replace("|22|", "").strip()
        topicurl_param = "content:\"|22|topicurl|22|\"; content:\""+topicurl_param.strip()+"\"; fast_pattern; within:"+topicurl_within+";"
    elif p_type == "Equal":
        if "=" in topicurl_param:
            topicurl_param = topicurl_param.replace("=", "")
        if "\"" in topicurl_param:
            topicurl_param = topicurl_param.replace("\"", "")
        if ":" in topicurl_param:
            topicurl_param = topicurl_param.replace(":", "")
        topicurl_msg = topicurl_param
        topicurl_param = "content:\"topicurl|3d|"+topicurl_param.strip()+"\"; fast_pattern;"
    return topicurl_param, topicurl_msg

# This function defines the PCRE we insert into the rule, the value of the classtype keyword, the vulnerability type portrayed in the msg keyword, and most of the metadata tags.
# The metadata affected_product tag for ET rules have a certain format for some of the default vendors. Additionally, the affected_product line seems to replace dashes (-) with underscores (_)
# so to maintain confirmity, we'll doing that too.
# we'll also be adding the created_at metadata tag using a datetime strftime to format that metadata field correctly.
# We attempt to extract the value of vuln_type from the csv, if that fails, we just fall back to option 1 (buffer overflow) as being the default.
# Option 6 allows users to manually define the pcre, type of vulnerability, and classtype. As such, CSV users need to have try/except clauses for each value in case its empty or invalid.
# this script will not validate whether the regex, or classtype is valid, that responsibility lies with the user.
def rule_loop_pcre(p_type, row, ven, cve_number):
    meta_target = "target:dest_ip;"
    ts_createdat = str(datetime.now().strftime("%Y_%m_%d"))
    if ven == "Asus":
        metadata_ven = "Asus"
    elif ven == "D-Link":
        metadata_ven = "D_Link"
    elif ven == "Linksys":
        metadata_ven = "Linksys"
    elif ven == "Totolink":
        metadata_ven = "TOTOLINK"
    elif ven == "TP-Link":
        metadata_ven = "TPLINK"
    elif "-" in ven:
        metadata_ven = ven.replace("-", "_")
    else:
        metadata_ven = ven
    if cve_number.strip() == "":
        meta_cve = ""
    elif "-" in cve_number.strip():
        meta_cve = "cve "+cve_number.replace("-", "_").upper()+","
    if args.infile:
        try:
            arg = int(row.get('vuln_type'))
            if arg > 7 or arg <= 0:
                print("\n"+bcolors.WARNING+"Invalid value detected. Must be an integer value between 1 and 2. Defaulting to option 1 (Buffer Overflow). Next time, fix your CSV, please."+bcolors.ENDC+"\n")
                arg = 1
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.WARNING+"Invalid value detected. Non-integer value. Defaulting to option 1 (Buffer Overflow). Next time, fix your CSV, please."+bcolors.ENDC+"\n")
            arg = 1
    else:
        print("\nWhat vulnerability are you writing coverage for (Default = 1)?")
        choices = {
            "1":"*Buffer Overflow" ,
            "2":"Command Injection" ,
            "3":"Cross Site Scripting" ,
            "4":"Directory Traversal" ,
            "5":"SQL Injection" ,
            "6":"Custom PCRE, Custom Vulnerability Type, Custom classtype" ,
            "7":"No PCRE, Custom Vulnerability Type, Custom classtype"
        }
        while True:
            try:
                for k,v in choices.items():
                    print(str(k)+': ' + str(v))
                arg = int(input("Please Choose: ") or 1)
                break
            except ValueError:
                print("Please enter a to select the vulnerability type to cover with the generated rule. Or hit enter to accept the default of Buffer Overflow.")
    while True:
        if arg == 1:
            if p_type == "JSON":
                param_regex = "pcre:\"/^(?:\\x3a(?:\\x20\\x22|\\x22))?[^\\x2c\\x7d$]{100,}(?:\\x2c|\\x7d|$)/R\";"
            else:
                param_regex = "pcre:\"/^[^&]{100,}(?:&|$)/R\";"
            vul_string = "Buffer Overflow Attempt"
            classtype = "web-application-attack"
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service; "+str(meta_target)
            return param_regex, vul_string, classtype, metadata
        if arg == 2:
            if p_type == "JSON":
                param_regex = "pcre:\"/^(?:\\x3a(?:\\x20\\x22|\\x22))?[^\\x2c\\x7d$]*?(?:(?:\\x3b|%3[Bb])|(?:\\x0a|%0[Aa])|(?:\\x60|%60)|(?:\\x7c|%7[Cc])|(?:\\x24|%24))+/R\";"
            else:
                param_regex = "pcre:\"/^[^\\x26]*?(?:(?:\\x3b|%3[Bb])|(?:\\x0a|%0[Aa])|(?:\\x60|%60)|(?:\\x7c|%7[Cc])|(?:\\x24|%24))+/R\";"
            vul_string = "Command Injection Attempt"
            classtype = "attempted-admin"
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1210, mitre_technique_name Exploitation_Of_Remote_Services; "+str(meta_target)
            return param_regex, vul_string, classtype, metadata
        if arg == 3:
            param_regex = "pcre:\"/^.*(?:on(?:(?:error)|(?:s(?:elec|ubmi)|rese)t|d(?:blclick|ragdrop)|(?:mouse|key)[a-z]|c(?:hange|lick)|(?:un)?load|focus|blur)|s(?:cript|tyle))(?:=|%3[dD])?/Ri\";"
            vul_string = "Cross Site Scripting Attempt"
            classtype = "web-application-attack"
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1210, mitre_technique_name Exploitation_Of_Remote_Services; "+str(meta_target)
            return param_regex, vul_string, classtype, metadata
        if arg==4:
            if p_type == "JSON":
                param_regex = "pcre:\"/^(?:\\x3a(?:\\x20\\x22|\\x22))?[^\\x2c\\x7d$]*?(?:(?:\\x2e|%2[Ee]){1,2}(?:\\x2f|\\x5c|%5[Cc]|%2[Ff]){1,}){2,}/R\";"
            else:
                param_regex = "pcre:\"/^[^\\x26]*?(?:(?:\\x2e|%2[Ee]){1,2}(?:\\x2f|\\x5c|%5[Cc]|%2[Ff]){1,}){2,}/R\";"
            vul_string = "Directory Traversal Attempt"
            classtype = "attempted-admin"
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1210, mitre_technique_name Exploitation_Of_Remote_Services; "+str(meta_target)
            return param_regex, vul_string, classtype, metadata
        if arg==5:
            param_regex = "pcre:\"/^[^<]*?(?:'|%27|-{2}|%2d%2d)?(?:(?:S(?:HOW.+(?:C(?:UR(?:DAT|TIM)E|HARACTER.+SET)|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER|SLEEP|CONCAT|CASE))|U(?:NION SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO)|S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|(?:NULL(?:,|%2[cC])){2,}|(?:/|%2[fF])(?:*|%2[aA]).+(?:*|%2[aA]).+(?:/|%2[fF])|CONCAT.+SELECT|EXTRACTVALUE|UNION.+ALL)/Ri\";"
            vul_string = "SQL Injection Attempt"
            classtype = "web-application-attack"
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1210, mitre_technique_name Exploitation_Of_Remote_Services; "+str(meta_target)
            return http_get_param_regex, vul_string, classtype, metadata
        if arg==6:
            if args.infile:
                try:
                    if str(row.get('custom_pcre')) != "":
                        param_regex = "pcre:\""+str(row.get('custom_pcre'))+"\";"
                    else:
                        print("\n"+bcolors.FAIL+"The value in custom_pcre is blank. Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        while True:
                            param_regex = "pcre:\""+str(input("What is the custom regex?\nInput the expression only (everything that would typically be inside the double quotes of the pcre keyword, escape hex-encoded characters escapes (e.g. \\x20 would become \\\\x20 instead)): "))+"\";"
                            if param_regex == "":
                                print("\n"+bcolors.WARNING+"regex cannot be blank. Try again."+bcolors.ENDC+"\n")
                            else:
                                break
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.FAIL+"Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    while True:
                        param_regex = "pcre:\""+str(input("What is the custom regex?\nInput the expression only (everything that would typically be inside the double quotes of the pcre keyword, escape hex-encoded characters escapes (e.g. \\x20 would become \\\\x20 instead)): "))+"\";"
                        if param_regex == "":
                            print("\n"+bcolors.WARNING+"regex cannot be blank. Try again."+bcolors.ENDC+"\n")
                        else:
                            break
                try:
                    if str(row.get('custom_vulntype')) != "":
                        vul_string = str(row.get('custom_vulntype'))
                    else:
                        print("\n"+bcolors.FAIL+"The value in custom_vulntype is blank. Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        while True:
                            vul_string = str(input("What type of vulnerability string should go in the rule msg? (e.g., SQL Injection Attempt, Cross Site Scripting Attempt, etc.): "))
                            if vul_string == "":
                                print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                            else:
                                break
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.FAIL+"Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    while True:
                        vul_string = str(input("What type of vulnerability string should go in the rule msg? (e.g., SQL Injection Attempt, Cross Site Scripting Attempt, etc.): "))
                        if vul_string == "":
                            print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                        else:
                            break
                try:
                    if str(row.get('custom_classtype')) != "":
                        classtype = str(row.get('custom_classtype'))
                    else:
                        print("\n"+bcolors.FAIL+"The value in custom_classtype is blank. Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        print("Please enter a valid classtype. Consult your classification.config file to determine valid classtypes.")
                        while True:
                            classtype = str(input("What value should be used for the classtype keyword (e.g., attempted-admin, web-application-attack, etc.)?"))
                            if classtype == "":
                                print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                            else:
                                break
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.FAIL+"Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    print("Please enter a valid classtype. Consult your classification.config file to determine valid classtypes.")
                    while True:
                        classtype = str(input("What value should be used for the classtype keyword (e.g., attempted-admin, web-application-attack, etc.)?"))
                        if classtype == "":
                            print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                        else:
                            break
            else:
                while True:
                    param_regex = "pcre:\""+str(input("What is the custom regex?\nInput the expression only (everything that would typically be inside the double quotes of the pcre keyword, escape hex-encoded characters escapes (e.g. \\x20 would become \\\\x20 instead)): "))+"\";"
                    if param_regex == "":
                        print("\n"+bcolors.WARNING+"regex cannot be blank. Try again."+bcolors.ENDC+"\n")
                    else:
                        break
                while True:
                    vul_string = str(input("What type of vulnerability string should go in the rule msg? (e.g., SQL Injection Attempt, Cross Site Scripting Attempt, etc.): "))
                    if vul_string == "":
                        print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                    else:
                        break
                while True:
                    classtype = str(input("What value should be used for the classtype keyword (e.g., attempted-admin, web-application-attack, etc.)?"))
                    if classtype == "":
                        print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                    else:
                        break
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major; "+str(meta_target)
            return param_regex, vul_string, classtype, metadata
        if arg == 7:
            print("\nNo regular expression has been chosen.\n")
            param_regex = ""
            if args.infile:
                try:
                    if str(row.get('custom_vulntype')) != "":
                        vul_string = str(row.get('custom_vulntype'))
                    else:
                        print("\n"+bcolors.FAIL+"The value in custom_vulntype is blank. Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        while True:
                            vul_string = str(input("What type of vulnerability string should go in the rule msg? (e.g., SQL Injection Attempt, Cross Site Scripting Attempt, etc.): "))
                            if vul_string == "":
                                print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                            else:
                                break
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.FAIL+"Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    while True:
                        vul_string = str(input("What type of vulnerability string should go in the rule msg? (e.g., SQL Injection Attempt, Cross Site Scripting Attempt, etc.): "))
                        if vul_string == "":
                            print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                        else:
                            break
                try:
                    if str(row.get('custom_classtype')) != "":
                        classtype = str(row.get('custom_classtype'))
                    else:
                        print("\n"+bcolors.FAIL+"The value in custom_classtype is blank. Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                        print("Please enter a valid classtype. Consult your classification.config file to determine valid classtypes.")
                        while True:
                            classtype = str(input("What value should be used for the classtype keyword (e.g., attempted-admin, web-application-attack, etc.)?"))
                            if classtype == "":
                                print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                            else:
                                break
                except Exception as e:
                    print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
                    print(e)
                    print("\n"+bcolors.FAIL+"Falling back to manual input. Next time, please fix your CSV."+bcolors.ENDC+"\n")
                    print("Please enter a valid classtype. Consult your classification.config file to determine valid classtypes.")
                    while True:
                        classtype = str(input("What value should be used for the classtype keyword (e.g., attempted-admin, web-application-attack, etc.)?"))
                        if classtype == "":
                            print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                        else:
                            break
            else:
                while True:
                    vul_string = str(input("What type of vulnerability string should go in the rule msg? (e.g., SQL Injection Attempt, Cross Site Scripting Attempt, etc.): "))
                    if vul_string == "":
                        print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                    else:
                        break
                while True:
                    classtype = str(input("What value should be used for the classtype keyword (e.g., attempted-admin, web-application-attack, etc.)?"))
                    if classtype == "":
                        print("\n"+bcolors.WARNING+"Value cannot be blank. Try again."+bcolors.ENDC+"\n")
                    else:
                        break
            metadata = "metadata:affected_product "+str(metadata_ven)+", tls_state plaintext, created_at "+ts_createdat+",  "+meta_cve+" deployment Perimeter, deployment Internal, confidence High, signature_severity Major; "+str(meta_target)
            break
        print("Invalid option selected")
    return param_regex, vul_string, classtype, metadata

# HTTP DELETE requests seem to support parameters being defined in the URI or parameters being specified in the client request body.
# So we need to ask the user, where is the vulnerable parameter, when the DELETE method is used.
# If empty, or invalid, defaults to option 1 (Parameter in client request body)
def param_loc(row):
    if args.infile:
        try:
            arg = int(row.get('param_loc'))
            if arg > 2 or arg <= 0:
                print("\n"+bcolors.WARNING+"Invalid value detected. Must be an integer value between 1 and 2. Defaulting to option 1 (no archive). Next time, fix your CSV please."+bcolors.ENDC+"\n")
                arg = 1
        except Exception as e:
            print("\n"+bcolors.FAIL+"You've hit some sort of an exception:"+bcolors.ENDC+"\n")
            print(e)
            print("\n"+bcolors.WARNING+"Defaulting to option 1 (no archive). Next time, fix your CSV please."+bcolors.ENDC+"\n")
            arg = 1
    else:
        print("\nYou have selected DELETE as your http method. Is the vulnerable parameter in the URI, or HTTP client request body (Default = Client Request Body)?\n")
        choices = {
            "1":"*Client Request Body" ,
            "2":"URI"
        }
        while True:
            try:
                for k,v in choices.items():
                    print(str(k)+': ' + str(v))
                arg = int(input("Please Choose: ") or 1)
                break
            except ValueError:
                print("\n"+bcolors.WARNING+"Please Enter a valid Number, or hit Enter to use the default setting (don't archive)."+bcolors.ENDC+"\n")
    while True:
        if arg == 1:
            param_location = 1
            return param_location
        if arg == 2:
            param_location = 2
            return param_location
        print("Invalid/Unsupported value.\n")

def main(args,row):
    ven = rule_loop_vendor_name(row)
    rule_ref = rule_reference(row)
    wayback_machine_submit(rule_ref, wayback_machine_creds, row)
    cve_number = cve_reference(row)
    http_meth = rule_loop_http_method(row)
    http_frm, http_frm_msg = rule_loop_http_framework(row)
    # If the method is DELETE, and the URI selected is /cgi-bin/cstecgi.cgi, I'm assuming the DELETE method has to have the parameter in the client body.
    # Otherwise, if the method is DELETE and not that particular URI, I need to know where the parameter is located (URI or client body)
    if (http_meth == "DELETE") and (http_frm == "/cgi-bin/cstecgi.cgi"):
        p_loc = 1
    elif http_meth == "DELETE":
        p_loc = param_loc(row)
    #set the rule url reference value if its a nonblank value, otherwise set it to blank.
    if rule_ref != "":
        rule_ref_msg = "reference:url,"+rule_ref.strip()+";"
    else:
        rule_ref_msg = ""
    #same for the CVE number. Set the value if not blank, otherwise set it to blank.
    if cve_number != "":
        cve_ref_msg = "reference:cve,"+cve_number.strip()+";"
        if not cve_number.startswith("CVE-"):
            cve_number = "CVE-"+cve_number.strip()
    else:
        cve_ref_msg = ""
        cve_ref_msg = cve_ref_msg.strip()
        cve_number = cve_number.strip()
    #catch people choosing GET or HEAD method and /cgi-bin/cstecgi.cgi
    if (http_frm == "/cgi-bin/cstecgi.cgi") and (http_meth in ('GET', 'HEAD')):
        print("\n"+bcolors.FAIL+"GET method and /cgi-bin/cstecgi.cgi is not a valid combination. Try again."+bcolors.ENDC+"\n")
    #logic for simple GET/HEAD request vulns
    if (http_frm != "/cgi-bin/cstecgi.cgi") and (http_meth in ('GET', 'HEAD')):
        p_type = "Equal"
        if http_frm.startswith("/"):
            frm_startswith = "startswith;"
        uri_param_get, uri_msg_get = rule_loop_uri_param_get(row)
        uri_param_pcre, vuln_string, classtype, m_data = rule_loop_pcre(p_type, row, ven, cve_number)
        get_rule_string = "alert http any any -> $HOME_NET any (msg:\"ET WEB_SPECIFIC_APPS "+ven+" "+http_frm_msg+" "+uri_msg_get+" Parameter "+vuln_string+" ("+cve_number.strip()+")\"; flow:established,to_server; http.method; content:\""+http_meth+"\"; http.uri; content:\""+http_frm+"\"; "+frm_startswith+" fast_pattern; content:\""+uri_param_get+"\"; distance:0; "+uri_param_pcre.strip()+" "+rule_ref_msg.strip()+" "+cve_ref_msg.strip()+" classtype:"+classtype.strip()+"; sid:"+str(args.sid_number)+"; rev:1; "+m_data+")"
        get_rule_string = str(get_rule_string)
        get_rule_string = get_rule_string.strip("  ")
        get_rule_string = re.sub(r"(?:\x28\x29|reference\:url,\x3b)", '', get_rule_string)
        get_rule_string = re.sub(r' "', r'"', get_rule_string)
        get_rule_string = re.sub(r" {2,}", r" ", get_rule_string)
        print(bcolors.OKGREEN + "\nSuricata Rule:\n" + bcolors.ENDC)
        print(get_rule_string+"\n")
        suri5_rule = get_rule_string
        try:
            snort29_rule_proback, snort29_rule_fresh = convert5_to_snort(suri5_rule)
        except Exception as e:
            print("There was an error converting the 5 to snort")
            print(e)
        #the target metadata tag is _not_ available in snort, and will cause validation errors, so we have to remove it.
        snort29_rule_fresh = snort29_rule_fresh.replace("; target:dest_ip;", ";")
        print(bcolors.OKGREEN + "Snort 2.9 rule, plain:\n" + bcolors.ENDC)
        print(str(snort29_rule_fresh)+"\n")
        print(bcolors.OKGREEN + "Snort 2.9 rule, proback:\n" + bcolors.ENDC)
        print(str(snort29_rule_proback)+"\n")
    #Logic for POST/PUT/PATCH request vulns
    if (http_meth in ('POST', 'PUT', 'PATCH')) and (http_frm != "/cgi-bin/cstecgi.cgi"):
        bsz = str(len(http_frm))
        p_type = body_parameter_type(row)
        http_body_param, http_body_param_msg = rule_loop_body_param(p_type, row)
        param_body_post, vuln_string, classtype, m_data = rule_loop_pcre(p_type, row, ven, cve_number)
        get_rule_string = "alert http any any -> $HOME_NET any (msg:\"ET WEB_SPECIFIC_APPS "+ven+" "+http_frm_msg+" "+http_body_param_msg+" Parameter "+vuln_string+" ("+cve_number.strip()+")\"; flow:established,to_server; http.method; content:\""+http_meth+"\"; http.uri; bsize:"+bsz+"; content:\""+http_frm+"\"; fast_pattern; http.request_body; content:\""+http_body_param+"\"; "+param_body_post.strip()+" "+rule_ref_msg.strip()+" "+cve_ref_msg.strip()+" classtype:"+classtype.strip()+"; sid:"+str(args.sid_number)+"; rev:1; "+m_data+")"
        get_rule_string = str(get_rule_string)
        get_rule_string = get_rule_string.strip("  ")
        get_rule_string = re.sub(r"(?:\x28\x29|reference\:url,\x3b)", '', get_rule_string)
        get_rule_string = re.sub(r' "', r'"', get_rule_string)
        get_rule_string = re.sub(r" {2,}", r" ", get_rule_string)
        print(bcolors.OKGREEN + "\nSuricata Rule:\n" + bcolors.ENDC)
        print(get_rule_string+"\n")
        suri5_rule = get_rule_string
        try:
            snort29_rule_proback, snort29_rule_fresh = convert5_to_snort(suri5_rule)
        except Exception as e:
            print("There was an error converting the 5 to snort")
            print(e)
        #the target metadata tag is _not_ available in snort, and will cause validation errors, so we have to remove it.
        snort29_rule_fresh = snort29_rule_fresh.replace("; target:dest_ip;", ";")
        print(bcolors.OKGREEN + "Snort 2.9 rule, plain:\n" + bcolors.ENDC)
        print(str(snort29_rule_fresh)+"\n")
        print(bcolors.OKGREEN + "Snort 2.9 rule, proback:\n" + bcolors.ENDC)
        print(str(snort29_rule_proback)+"\n")
    #cstecgi.cgi, mainly seen in Totolink routers, has the same URI string, but the topicurl in the post body is used to figure out which page is being targeted.
    #we use the value of the topicurl (which we get from an if/then below) to set the message string and fast_pattern for rules that use cstecgi.cgi
    if (http_meth in ('POST', 'PUT', 'PATCH', 'DELETE')) and (http_frm == "/cgi-bin/cstecgi.cgi"):
        p_type = body_parameter_type(row)
        turl_param, turl_msg = topicurl_set(p_type, row)
        http_body_param, http_body_param_msg = rule_loop_body_param(p_type, row)
        param_body_post, vuln_string, classtype, m_data = rule_loop_pcre(p_type, row, ven, cve_number)
        get_rule_string = "alert http any any -> $HOME_NET any (msg:\"ET WEB_SPECIFIC_APPS "+ven+" "+turl_msg+" "+http_body_param_msg+" Parameter "+vuln_string+" ("+cve_number.strip()+")\"; flow:established,to_server; http.method; content:\""+http_meth+"\"; http.uri; bsize:20; content:\"/cgi-bin/cstecgi.cgi\"; http.request_body; "+turl_param+" content:\""+http_body_param+"\"; "+param_body_post.strip()+" "+rule_ref_msg.strip()+" "+cve_ref_msg.strip()+" classtype:"+classtype.strip()+"; sid:"+str(args.sid_number)+"; rev:1; "+m_data+")"
        get_rule_string = str(get_rule_string)
        get_rule_string = get_rule_string.strip("  ")
        get_rule_string = re.sub(r"(?:\x28\x29|reference\:url,\x3b)", '', get_rule_string)
        get_rule_string = re.sub(r' "', r'"', get_rule_string)
        get_rule_string = re.sub(r" {2,}", r" ", get_rule_string)
        print(bcolors.OKGREEN + "\nSuricata Rule:\n" + bcolors.ENDC)
        print(get_rule_string+"\n")
        suri5_rule = get_rule_string
        try:
            snort29_rule_proback, snort29_rule_fresh = convert5_to_snort(suri5_rule)
        except Exception as e:
            print("There was an error converting the 5 to snort")
            print(e)
        #the target metadata tag is _not_ available in snort, and will cause validation errors, so we have to remove it.
        snort29_rule_fresh = snort29_rule_fresh.replace("; target:dest_ip;", ";")
        print(bcolors.OKGREEN + "Snort 2.9 rule, plain:\n" + bcolors.ENDC)
        print(str(snort29_rule_fresh)+"\n")
        print(bcolors.OKGREEN + "Snort 2.9 rule, proback:\n" + bcolors.ENDC)
        print(str(snort29_rule_proback)+"\n")
    #I've seen cases where http DELETE method can either have a client body, or just be entirely reliant on URL parameters.
    #So we need to handled those cases. use param_loc() to determine if we're looking at a vulnerable parameter in the URI or client body.
    if (http_meth == "DELETE") and (http_frm != "/cgi-bin/cstecgi.cgi"):
        if p_loc == 1:
            bsz = str(len(http_frm))
            p_type = body_parameter_type(row)
            param, param_msg = rule_loop_body_param(p_type, row)
            param_body_pcre, vuln_string, classtype, m_data = rule_loop_pcre(p_type, row, ven, cve_number)
            get_rule_string = "alert http any any -> $HOME_NET any (msg:\"ET WEB_SPECIFIC_APPS "+ven+" "+http_frm_msg+" "+param_msg+" Parameter "+vuln_string+" ("+cve_number.strip()+")\"; flow:established,to_server; http.method; content:\""+http_meth+"\"; http.uri; bsize:"+bsz+"; content:\""+http_frm+"\"; fast_pattern; http.request_body; content:\""+param+"\"; "+param_body_pcre.strip()+" "+rule_ref_msg.strip()+" "+cve_ref_msg.strip()+" classtype:"+classtype.strip()+"; sid:"+str(args.sid_number)+"; rev:1; "+m_data+")"
        elif p_loc == 2:
            p_type = "Equal"
            if http_frm.startswith("/"):
                frm_startswith = "startswith;"
            param, param_msg = rule_loop_uri_param_get(row)
            param_uri_pcre, vuln_string, classtype, m_data = rule_loop_pcre(p_type, row, ven, cve_number)
            get_rule_string = "alert http any any -> $HOME_NET any (msg:\"ET WEB_SPECIFIC_APPS "+ven+" "+http_frm_msg+" "+param_msg+" Parameter "+vuln_string+" ("+cve_number.strip()+")\"; flow:established,to_server; http.method; content:\""+http_meth+"\"; http.uri; content:\""+http_frm+"\"; "+frm_startswith+" fast_pattern; content:\""+param+"\"; distance:0; "+param_uri_pcre.strip()+" "+rule_ref_msg.strip()+" "+cve_ref_msg.strip()+" classtype:"+classtype.strip()+"; sid:"+str(args.sid_number)+"; rev:1; "+m_data+")"
        get_rule_string = str(get_rule_string)
        get_rule_string = get_rule_string.strip("  ")
        get_rule_string = re.sub(r"(?:\x28\x29|reference\:url,\x3b)", '', get_rule_string)
        get_rule_string = re.sub(r' "', r'"', get_rule_string)
        get_rule_string = re.sub(r" {2,}", r" ", get_rule_string)
        print(bcolors.OKGREEN + "\nSuricata Rule:\n" + bcolors.ENDC)
        print(get_rule_string+"\n")
        suri5_rule = get_rule_string
        try:
            snort29_rule_proback, snort29_rule_fresh = convert5_to_snort(suri5_rule)
        except Exception as e:
            print("There was an error converting the 5 to snort")
            print(e)
        #the target metadata tag is _not_ available in snort, and will cause validation errors, so we have to remove it.
        snort29_rule_fresh = snort29_rule_fresh.replace("; target:dest_ip;", ";")
        print(bcolors.OKGREEN + "Snort 2.9 rule, plain:\n" + bcolors.ENDC)
        print(str(snort29_rule_fresh)+"\n")
        print(bcolors.OKGREEN + "Snort 2.9 rule, proback:\n" + bcolors.ENDC)
        print(str(snort29_rule_proback)+"\n")
    args.sid_number += 1
    if args.outfile:
        with open(args.outfile, 'a+', encoding='UTF-8') as o:
            o.write("Suricata:")
            o.write("\n\n")
            o.write(str(get_rule_string))
            o.write("\n\n")
            o.write("Snort (full):")
            o.write("\n\n")
            o.write(str(snort29_rule_fresh))
            o.write("\n\n")
            o.write("Snort (proback):")
            o.write("\n\n")
            o.write(str(snort29_rule_proback))
            o.write("\n\n")
    if args.outfile_suricata_only:
        with open(args.outfile_suricata_only, 'a+', encoding='UTF-8') as suri:
            suri.write(str(get_rule_string))
            suri.write("\n\n")
    if args.outfile_snort_only:
        with open(args.outfile_snort_only, 'a+', encoding='UTF-8') as snort:
            snort.write(str(snort29_rule_fresh))
            snort.write("\n\n")
    if args.outfile_proback_only:
        with open(args.outfile_proback_only, 'a+', encoding='UTF-8') as pb:
            pb.write(str(snort29_rule_proback))
            pb.write("\n\n")




if __name__ == "__main__":
    parser = argparse.ArgumentParser(
    formatter_class = argparse.RawDescriptionHelpFormatter,
    description = textwrap.dedent('''
                    IoT_hunter
                Brought to you by ...
                    @da_667
                ---------------------
Generates Suricata 5+, and Snort 2.9.x rules to detect basic vulnerabilities, either via a menu-driven interface, or csv input.
Usage: IoT_hunter.py [-i <infile>] [-o <outfile>] [-s <sid number>]
'''))

    parser.add_argument('-i', '--infile', dest = "infile", required = False, help = "The name of the csv file to generate rules from")
    parser.add_argument('-o', '--outfile', dest = "outfile", required = False, help = "The name of the file to output generated rules to")
    parser.add_argument('-osu', '--output-suricata', dest = "outfile_suricata_only", required = False, help = "Name of the file to output Suricata rules to. Only writes Suricata rules to this file")
    parser.add_argument('-osn', '--output-snort', dest = "outfile_snort_only", required = False, help = "Name of the file to output Completed Snort rules to. Only writes Snort rules to this file")
    parser.add_argument('-opb', '--output-proback', dest = "outfile_proback_only", required = False, help = "Name of the file to output Proback (minimal) formatted Snorted rules to. Only writes proback formatted rules to this file")
    parser.add_argument('-s', '--sid_number', dest = "sid_number", type = int, required = False, default = 1000000, help = "The starting sid number to assign to generated rules. If a sid number is not supplied, defaults to 1000000 (local rules range)")
    args = parser.parse_args()
    if args.infile:
        with open(args.infile, 'r', encoding='UTF-8') as f:
            reader=csv.DictReader(f, quoting = csv.QUOTE_NONE)
            for row in reader:
                main(args,row)
    else:
        while True:
            row = ""
            main(args,row)
