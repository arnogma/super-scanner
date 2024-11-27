import re
import os
import subprocess
import argparse #for CLI
import asyncio
import aiohttp
import ssl
from OpenSSL import crypto
##########incase original fetch certs func does not work
#from cryptography import x509
#from cryptography.hazmat.backends import default_backend

class SSLChecker:
    #constructor
    def __init__(self, ips_file, masscan_results_file, masscan_rates, target_port, chunk_size, timeout, sslport, MAX_CONCURRENT, semaphore_limit, protocols):
        self.masscan_results_file = masscan_results_file
        self.ips_file = ips_file
        self.masscan_rates = masscan_rates #num of ips scanned at once --> NOTE: Don't put in too much, you'll miss a lot if you put in an absurdly high number (rec: 10,000 for laptops)
        self.target_port = target_port
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.sslport = sslport
        self.MAX_CONCURRENT = MAX_CONCURRENT
        self.semaphore = asyncio.Semaphore(semaphore_limit)
        self.protocols = protocols

    #fetching ssl certificates
    async def fetch_certs(self, ip):
        try:
            ############## IF BELOW DOESN'T WORK
            # cert_data = await asyncio.to_thread(ssl.get_server_certificate, (ip, 443), ssl_version=ssl.PROTOCOL_TLS)
            # x509_cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
            # common_name = x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            #runs get server cert in separate thread
            cert=await asyncio.to_thread(ssl.get_server_certificate,(ip, self.sslport), timeout=self.timeout) #because get_server_cert will wait for response

            #create x509 cert
            x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert) #loads cert, returns representation of cert --> decodes PEM format (base64) 
            subject = x509_cert.get_subject() #return subject of cert --> ex. common name, org
            common_name = subject.CN

            return ip, common_name

        except Exception as e:
            print(f"Error for {ip}: {e}")
            return ip,"" #for cases where IP does not have a cert attached (ex. http - port 80)

    #check of given common name is a valid domain name
    def is_valid_domain(self, common_name):
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" # regex for 1+ chars (that are letters, numbers, dots, or hyphens) + . + 2+ chars (only letters)
        return re.match(domain_pattern,common_name) is not None #returns value if common name is a valid domain name

    async def check_site(self, session, ip, common_name):
        try:
            #use semaphores to limit num of requests
            async with self.semaphore:
                temp_dict = {}

                # make request to IP, if no valid domain
                if "*" in common_name or not self.is_valid_domain(common_name):
                    for protocol in self.protocols:
                        dict_res=await self.GETrequestToDomain(session, protocol, ip, common_name, True) #if invalid domain name, make request to IP
                        temp_dict[f'{protocol.replace("://","")}_responseForIP'] = dict_res #remove :// from (ex.) https://exampledomain.com
                
                #make request using domain name AND IP, if domain name is valid
                else:
                    for protocol in self.protocols:
                        dict_res=await self.GETrequestToDomain(session, protocol, ip, common_name, False)
                        temp_dict[f'{protocol.replace("://","")}_responseForDomainName'] = dict_res
                    for protocol in self.protocols:
                        dict_res=await self.GETrequestToDomain(session, protocol, ip, common_name, True)
                        temp_dict[f'{protocol.replace("://","")}_responseForIP'] = dict_res

                #filtering out None values    
                temp_dict = {k: v for k, v in temp_dict.items() if v is not None}
                if temp_dict:
                    return temp_dict

        except Exception as e:
            print(f"Error for {ip}: {e}")

    #extracting domains
    async def extract_domains():
        try:
            #open extracted ips (from ip ranges file)
            with open(self.masscan_results_file, "r") as f:
                content=f.read()

            #for regex lookup
            ipv4_pattern = r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}" #ex. 192.168.123.22
            ip_addrs_ipv4 = re.findall(ipv4_pattern, content)
           
            #ipv6_pattern = r""

            #splitting ip addr into chunks of 2,000 addrs, avoid RAM overload + more efficient
            for i in range(0, len(ip_addrs_ipv4), self.chunksize):
                #making concurrent requests           
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.MAX_CONCURRENT, ssl=False)) as session: #ignore ssl when making requests
                    ipaddr_chunk = ip_addrs_ipv4[i:i+self.chunksize]
                    #ip addrs and common names from certs
                    ip_and_common_names = []

                    #make multiple parallel request at the same time
                    ip_and_common_names = await asyncio.gather(*[self.fetch_certs(ip) for ip in ipaddr_chunk]) #gather all requests into a single thread --> Does NOT wait for server response
                    # ip, common_name (OR empty str)

                    #calling new function - check common names and ips for website 
                    await asyncio.gather(*[self.check_site(session, ip, common_name) for ip, common_name in ip_and_common_names]) #making requests to IP (in case where no common name) or domain name


    #running masscan
    def run_masscan(self):
        try:
            command = f"sudo masscan -p{self.target_port} --rate {self.masscan_rates} --wait 0 -iL {self.ips_file} -oH {self.masscan_results_file}" #target port 443
            subprocess.run(command, shell=True, check=True) #creates process to run external apps (masscan)
        except subprocess.CalledProcessError as e:
            print(f"Error running masscan: {e}")
        except FileNotFoundError:
            print("Error: Masscan executable not found")
        except Exception as e:
            print(f"Unexpected error: {e}")

    #creates a masscanresults.txt file and ips.txt file if it does not exist in the directory
    def check_create_files(self,*file_paths):
        for file_path in file_paths: #loop through each file
            #if file does not exist --> create file
            if not os.path.exists(file_path):
                with open(file_path, 'w') as file:
                    pass
                print(f'File "{file_path}" has been created')

    async def main(self):
        self.check_create_files(self.masscan_results_file, self.ips_file)
        #self.run_masscan() #WARNING: Use a VPN before running this
        await self.extract_domains()

#for inputting cli arguments
def cli_arguments():
    parser = argparse.ArgumentParser(description="A scanner that searches through active hosts in a given IP subnet")
    parser.add_argument("-i", "--input", type=str, nargs=1, metavar="path", default=['ips.txt'], help="Opens and reads specified IPs file")
    parser.add_argument("-o", "--output", type=str, nargs=1, metavar="path", default=['masscan_results.txt'], help="File/Path for program output to be saved in")
    parser.add_argument("--rate", type=int, nargs=1, metavar="number", default=[10000], help="Determine number of IPs scanned at once")
    parser.add_argument("-p", "--ports", type=str, nargs=1, metavar="port", default=['443'], help="Targeted port(s) as a comma-separated string, e.g., '443,80,8080'")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports (overrides --port if specified)")
    parser.add_argument("--chunk-size", type=int, nargs=1, metavar="size", default=[2000], help="Number of IP addresses processed at once")
    parser.add_argument("--timeout", type=int, nargs=1, metavar="time", default=[2], help="Number of seconds for timeout")
    parser.add_argument("--ssl-port", type=int, nargs=1, metavar="port", default=[443], help="Define SSL port number (default 443)")
    parser.add_argument("--max-concurrent", type=int, nargs=1, metavar="int", default=[100], help="Limit maximum number of concurrent connections (default = 100)")
    parser.add_argument("--semaphore-limit", type=int, nargs=1, metavar="int", default=[70], help="Number of semaphores for limiting number of requests made")
    parser.add_argument("--https-only", action="store_true", help="Only scan through HTTPS protocol")
    
    args = parser.parse_args()
    #if all-ports arg is used, override ports arg
    ports = '0-65535' if args.all_ports else args.port[0]

    protocol_arg = ["https://"] if args.https_only else ["http://", "https://"]

    return args.input[0], args.output[0], args.rate[0], ports, args.chunk_size[0], args.timeout[0], args.ssl_port[0], args.max_concurrent[0], arg.semaphore_limit[0], protocol_arg

if __name__ == "__main__":
    inputfile, outputfile, rates, t_port, size, timeout_arg, sslport_arg, max_concur_arg, sem_lim_arg, protocol_cli_arg = cli_arguments()
    ssl_checker = SSLChecker(inputfile, outputfile, rates, t_port, size, timeout_arg, sslport_arg, max_concur_arg, sem_lim_arg, protocol_cli_arg)
    asyncio.run(ssl_checker.main()) #create event loop