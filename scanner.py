import os
import subprocess
import argparse #for CLI

class SSLChecker:
    #constructor
    def __init__(self, ips_file, masscan_results_file, masscan_rates, target_port):
        self.masscan_results_file = masscan_results_file
        self.ips_file = ips_file
        self.masscan_rates = masscan_rates #num of ips scanned at once --> NOTE: Don't put in too much, you'll miss a lot if you put in an absurdly high number (rec: 10,000 for laptops)
        self.target_port = target_port

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

    def main(self):
        self.check_create_files(self.masscan_results_file, self.ips_file)
        self.run_masscan() #WARNING: Use a VPN before running this

#for inputting cli arguments
def cli_arguments():
    parser = argparse.ArgumentParser(description="A scanner that searches through active hosts in a given IP subnet")
    parser.add_argument("-i", "--input", type=str, nargs=1, metavar="path", default=['ips.txt'], help="Opens and reads specified IPs file")
    parser.add_argument("-o", "--output", type=str, nargs=1, metavar="path", default=['masscan_results.txt'], help="File/Path for program output to be saved in")
    parser.add_argument("--rate", type=int, nargs=1, metavar="number", default=[10000], help="Determine number of IPs scanned at once")
    parser.add_argument("-p", "--port", type=str, nargs=1, metavar="port", default=['443'], help="Targeted port(s) as a comma-separated string, e.g., '443,80,8080'")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports (overrides --port if specified)")
    
    args = parser.parse_args()
    ports = '0-65535' if args.all_ports else args.port[0]

    return args.input[0], args.output[0], args.rate[0], ports

if __name__ == "__main__":
    inputfile, outputfile, rates, t_port = cli_arguments()
    ssl_checker = SSLChecker(inputfile, outputfile, rates, t_port)
    ssl_checker.main()