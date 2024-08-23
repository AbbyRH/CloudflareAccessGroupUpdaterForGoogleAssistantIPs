import CloudFlare
import requests
import logging
from netaddr import IPNetwork, IPSet

def get_google_ips():
    """Get list of CIDR-notation Google subnets not assigned to GCP customers (and therefore used for google's APIs and services)"""
    logging.debug('Getting Google API IPs')
    all_ips = get_ip_set("https://www.gstatic.com/ipranges/goog.json")
    customer_ips = get_ip_set("https://www.gstatic.com/ipranges/cloud.json")
    api_ips = all_ips - customer_ips
    return [{"ip": str(ip)} for ip in api_ips.iter_cidrs()]

def get_ip_set(url):
    try:
        json_data = requests.get(url).json()
    except:
        logging.exception(f"Error getting JSON data from '{url}'")
        raise
    try:
        return IPSet([next(iter(i.values())) for i in json_data['prefixes']])
    except:
        logging.exception(f"Error adding CIDR blocks to IPSet")
        raise

def get_google_addresses():
    r = requests.get("https://www.gstatic.com/ipranges/goog.json")
    r.raise_for_status()
    ips = [ entry['ipv4Prefix'] for entry in r.json()['prefixes'] if 'ipv4Prefix' in entry ]
    ips = ips + [ entry['ipv6Prefix'] for entry in r.json()['prefixes'] if 'ipv6Prefix' in entry ]
    return ips
    
def update_access_group(token, account_id, ip_list, group_id, ips):
    cf = CloudFlare.CloudFlare(token=token)
    
    data = [{"ip": ip} for ip in ips]

    print("ip_list_id", ip_list[:4])
    print("group_id", group_id[:4])
    
    cf.accounts.rules.lists.items.put(account_id, ip_list, data=ips)
    
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description = "CloudFlare Google Assistant Access Group updater")
    parser.add_argument("--account", required=True, help="CF account ID")
    parser.add_argument("--token",   required=True, help="CF API key")
    parser.add_argument("--group",   required=True, help="ID of CF Access group that needs to be updated")
    parser.add_argument("--iplist",  required=True, help="ID of ip list")
    args = parser.parse_args()

    ips = get_google_ips()
    update_access_group(args.token, args.account, args.iplist, args.group, ips)
  
