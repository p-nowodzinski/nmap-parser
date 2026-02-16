import subprocess
import csv, json, xml.etree.ElementTree as ET
import argparse
from pathlib import Path
import os, shutil, sys, platform
from dataclasses import dataclass
from urllib.parse import urlparse, unquote
from urllib.request import url2pathname
from typing import Tuple, List, Dict, Optional

##TODO
#


####################################
##### Constants and data model #####
####################################

SCRIPT_DIR = Path(__file__).resolve().parent
PWS_SCRIPT = SCRIPT_DIR / "xml_html.ps1"
BUNDLED_XSL = Path(SCRIPT_DIR.parent / "assets" / "nmap.xsl").as_uri()
HOST_OS = platform.system()
NMAP_WEB_XSL = "https://nmap.org/svn/docs/nmap.xsl"

CSV_FIELDS = [
    "IP", "Host Status", "Port", "Name", 
    "State", "Protocol", "Product", "Version", 
    "OS", "OS accuracy", "Script ID", "Script output"
]

SCAN_PRESETS = {
    "default": [
        "-sS",
        "-T3",
        "-Pn",
        "-F"

    ],

    "quick": [
        "-T4",
        "--top-ports", "20",
        "-Pn"
    ],

    "full-tcp": [
        "-sS",
        "-p-",
        "-T4",
        "-Pn"
    ],

    "service": [
        "-sS",
        "-sV",
        "-T3",
        "-Pn"
    ],

    "script": [
        "-sS",
        "-sC",
        "-T3",
        "-Pn"
    ],

    "service-script": [
        "-sS",
        "-sV",
        "-sC",
        "-T3",
        "-Pn"
    ],

    "udp": [
        "-sU",
        "--top-ports", "100",
        "-T3",
        "-Pn"
    ],

    "aggressive": [
        "-A",
        "-T4",
        "-Pn"
    ]
}



@dataclass
class Config:
    paths: Dict[str, Path]        
    verbose: int                  
    format: Optional[str]         
    auto_open: Optional[str]      
    command: List[str]            
    target: Optional[str]         
    dry_run: bool                



###############################
##### logging and helpers #####
###############################

def info(msg: str, config: Config, level: int = 1) -> None:
    """
    Script output control based on the verbosity level set by the user (default = 0).
    If level is specified as 0, the message will be ouputted regardless of the verbosity set by the user. Otherwise:
    -v  --> level 1
    -vv --> level 2
    
    @param msg: Take the scripts output and filter against the specified verbosity level.
    @param level: The specified verbosity level.
    """
    if config.verbose >= level:
        print(msg)




def open_file(path: Path) -> None:
    if HOST_OS == "Windows":
        os.startfile(path)
    elif HOST_OS == "Linux":           
        subprocess.run(["xdg-open", path], check=False)
    else:  
        subprocess.run(["open", path], check=False)




def path_builder(output_dir: Path) -> Dict[str, Path]:
    return {
        "dir": output_dir,
        "xml": output_dir / "nmap_out.xml",
        "csv": output_dir / "nmap_out.csv",
        "json": output_dir / "nmap_out.json",
        "html": output_dir / "nmap_out.html",
    }




def get_attrib(elem: ET.Element, path: str, attrib: str) -> str:
    tag = elem.find(path)
    return tag.get(attrib, "N/A") if tag is not None else "N/A"




def get_best_os(host: ET.Element) -> Tuple[str, str]:
    best_name = "N/A"
    best_accuracy = -1

    for osmatch in host.findall("os/osmatch"):
        acc = osmatch.get("accuracy")
        if acc is None:
            continue

        acc = int(acc)
        if acc > best_accuracy:
            best_accuracy = acc
            best_name = osmatch.get("name", "N/A")

    return best_name, (best_accuracy if best_accuracy != -1 else "N/A")




def get_scripts(port: ET.Element) -> List[Dict[str, str]]:
    scripts = []

    for script in port.findall("script"):
        scripts.append({
            "id": script.get("id", "N/A"),
            "output": script.get("output", "N/A")
        })

    return scripts



def build_processing_instruction(path: str) -> str:
    return f'<?xml-stylesheet href="{path}" type="text/xsl"?>\n'



##############################
##### Resolve Dependencies #####
##############################

def find_nmap(custom_path: Optional[str]) -> Path:
    """
    Attempts to find the Nmap path by checking three various ways:

    1. Checks if an Nmap path was manually provided, assigns path object, and then checks if it exists.
    2. Checks system PATH by running shutil.which("nmap").
    3. Checks environment variable by running the equivalent of 'Write-Host $ENV:NMAP_PATH' or 'echo %NMAP_PATH%'

    @param custom_path: A potential path to Nmap provided by the user
    @returns nmap_path: The file path to the Nmap executable
    """
    
    if custom_path:
        nmap_path = Path(custom_path)
        if nmap_path.exists():
            return nmap_path
        raise FileNotFoundError(f"[ERROR] Provided nmap path does not exist:\n\t{custom_path}")

    
    nmap_path = shutil.which("nmap")
    if nmap_path:
        return Path(nmap_path)
    

    nmap_path = os.getenv("NMAP_PATH")
    if nmap_path and Path(nmap_path).exists():
        return Path(nmap_path)
    

    raise FileNotFoundError("""
[ERROR] Nmap executable not found.

Please install Nmap or specify the path manually using the --nmap-path/-n flags.

You can download Nmap from here: https://nmap.org/download.html

Options:
    --nmap-path "C:\\Program Files (x86)\\Nmap\\nmap.exe"
or  
    setx NMAP_PATH "C:\\Program Files (x86)\\Nmap\\nmap.exe"
""")




def user_selection(config: Config, pi_exists: bool) -> str | None:
    try:
        user_input = int(input("""
Please enter an integer that corresponds with your decision from the list of options provided below: 
        1. Use the bundled stylesheet provided while keeping the proccessing instruction intact. [Recommended]
        2. Replace the processing instruction path with the bundled stylesheet.
        3. Replace the processing instruction path with Nmap's web stylesheet. (Results in the same XML processing instruction as Nmap's --webxml command)    
        4. Exit    
                               
    Option: """))
        
    except ValueError:
        info("Invalid selection. Exiting...", config, level=0)
        sys.exit(1)
        

    if user_input == 1:
        config.paths["xsl"] = BUNDLED_XSL
        return None
                        
    elif user_input == 4:
        info("Exiting...", config, level=0)
        sys.exit(1)


    if pi_exists:
        if user_input == 2:
            return "modify_pi_bundled"
            
        elif user_input == 3:
            return "modify_pi_web"               
            
    else:
        if user_input == 2:
            return "inject_pi_bundled"
            
        elif user_input == 3:
            return "inject_pi_web"
        
    info("Invalid selection. Exiting...", config, level=0)
    sys.exit(1)
 
 
    
def apply_xsl_user_choice(config: Config, file_content: str, line_location: int, user_choice: str):

    if user_choice == "modify_pi_bundled":
        file_content[line_location] = build_processing_instruction(BUNDLED_XSL)
        config.paths["xsl"] = BUNDLED_XSL
    
    elif user_choice == "modify_pi_web":
        file_content[line_location] = build_processing_instruction(NMAP_WEB_XSL)
        config.paths["xsl"] = NMAP_WEB_XSL
    
    elif user_choice == "inject_pi_bundled":
        file_content.insert(line_location, build_processing_instruction(BUNDLED_XSL))
        config.paths["xsl"] = BUNDLED_XSL
    
    elif user_choice == "inject_pi_web":
        file_content.insert(line_location, build_processing_instruction(NMAP_WEB_XSL)) 

        if HOST_OS == "Linux":
            try:
                user_confirmation = str(input("""
Processing instruction has been modified. However, this script uses xsltproc which does not support external links. 
This means that the bundled xsl will be used instead.
Please enter y/n if you would like to continue: """)).upper()
                if "Y" in user_confirmation:
                    config.paths["xsl"] = BUNDLED_XSL
                else:
                    info("Exiting...", config, level=0)
                    sys.exit(1)

            except ValueError:
                    info("Invalid selection. Exiting...", config, level=0)
                    sys.exit(1)     
        else:
            config.paths["xsl"] = NMAP_WEB_XSL
    
    
    with open(config.paths["xml"], "w") as file:
        file.writelines(file_content)    






def xsl_not_found(config: Config, file_content: str, line_location: int, pi_exists: bool) -> None:
        if pi_exists:
            info("[WARNING] Invalid XSL file path specified in the XML processing instruction!", config, level=0)
        else:
            info("""
[WARNING] No valid processing instruction was found in the XML file provided!
Options 2 and 3 will attempt to inject the processing instruction if selected.
                 """, config, level=0)
        
        info("To be able to convert the XML file to HTML, you will need to use Nmaps xsl stylesheet.", config, level=0)
        user_choice = user_selection(config, pi_exists)
        if user_choice:
            apply_xsl_user_choice(config, file_content, line_location, user_choice)





def find_xsl(config: Config) -> None:                                    
    with open(config.paths["xml"], "r") as xml:
        file_content = xml.readlines()
    
    line_location = -1

    for index, line in enumerate(file_content):
        if ("?xml-stylesheet") in line:   
            line_location = index
            break

        
    if line_location != -1: #if pi exists
        xsl_path_line = str(file_content[line_location]) 
        index = xsl_path_line.find("href=\"")
        result = xsl_path_line[index:]
        result = result.split("\"", 2)
        result = str(result[1])
        
        
        if result.startswith("file"): #if os path
            parsed = urlparse(result)
            host = "{0}{0}{mnt}{0}".format(os.path.sep, mnt=parsed.netloc)
            result = os.path.normpath(os.path.join(host, url2pathname(unquote(parsed.path))))

            if Path(result).exists(): #if os path exist
                config.paths["xsl"] = result
            else:
                xsl_not_found(config, file_content, line_location, pi_exists=True)
            
        else: #if url in pi
            info("[WARNING] External path detected. Internet connection required!", config, level=0)
            if HOST_OS == "Linux":
                info("[Warning] Linux OS detected. This script uses xsltproc to transform the XML scan results which will not work with external xsl path.")
                user_choice = user_selection(config, pi_exists=True)
                if user_choice:
                    apply_xsl_user_choice(config, file_content, line_location, user_choice)
            else:
                config.paths["xsl"] = result


    else:   #if pi doesn't exist
        xsl_not_found(config, file_content, line_location=2, pi_exists=False)










#######################
#####SCRIPT STARTS#####
#######################

def run_command(config: Config) -> None:
    xml_result = targeted_nmap_scan(config)
    scan_data, csv_rows = parse_xml(xml_result)
    export_results(scan_data, csv_rows, config)


def parse_command(config: Config) -> None:
    root = ET.parse(config.paths["xml"]).getroot()
    scan_data, csv_rows = parse_xml(root)
    export_results(scan_data, csv_rows, config)






def targeted_nmap_scan(config: Config) -> ET.Element:
    nmap_command = config.command
    xml_file_path = config.paths["xml"]
    command = " ".join([str(x) for x in config.command])

    info(f"Executing the following Nmap commands:\n\t{command}", config, level=2)
    n_scan = subprocess.run(
        nmap_command,
        capture_output=True,
        text=True
    )
    if n_scan.returncode != 0:
        raise RuntimeError(n_scan.stderr)
    
    info(f"Nmap successfully scanned the following ip: {config.target}", config)
    clean_xml = n_scan.stdout[n_scan.stdout.find("<"):]

    root = ET.fromstring(clean_xml)

    
    with open(xml_file_path, "w") as xml_file:
        xml_file.write(clean_xml)



    info(f"Written Nmap output to xml file located:\n\t{xml_file_path}", config, level=2)
    return root




def parse_xml(root: ET.Element) -> Tuple[List[Dict], List[Dict[str, str]]]:
    hosts_data = []
    csv_rows = []
    
    for host in root.findall(".//host"):
        ports = {}
        status = get_attrib(host, "status", "state")
        
        
        ip = get_attrib(host, "address[@addrtype='ipv4']", "addr")
        ip = get_attrib(host, "address", "addr") if ip == "N/A" else ip

        os_name, os_accuracy = get_best_os(host)

        if status == "down":
            csv_rows.append({
                "IP": ip,
                "Host Status": status,
                "Port": "N/A",
                "Name": "N/A",
                "State": "N/A",
                "Protocol": "N/A",
                "Product": "N/A",
                "Version": "N/A",
                "OS": os_name,
                "OS accuracy": os_accuracy,
                "Script ID": "N/A",
                "Script output": "N/A"
            })

        for port in host.findall(".//port"):
            portid = port.get("portid", "N/A")
            protocol = port.get("protocol", "N/A")
            state = get_attrib(port, "state", "state") 


            name = get_attrib(port, "service", "name")
            product = get_attrib(port, "service", "product")
            version = get_attrib(port, "service", "version")
            service = {
                "name": name,
                "product": product,     
                "version": version
                }

            scripts = get_scripts(port)
            if not scripts:
                scripts = [{"id": "N/A", "output": "N/A"}]

            if portid is not None:
                ports[portid] = {
                    "state": state,
                    "protocol": protocol,
                    "service": service,
                    "scripts": scripts
                }

            for script in scripts:
                csv_rows.append({
                    "IP": ip,
                    "Host Status": status,
                    "Port": portid,
                    "Name": name,
                    "State": state,
                    "Protocol": protocol,
                    "Product": product,
                    "Version": version,
                    "OS": os_name,
                    "OS accuracy": os_accuracy,
                    "Script ID": script.get("id", "N/A"),
                    "Script output": script.get("output", "N/A")
                })
        
        
        hosts_data.append({
            "IP": ip,
            "host status": status,
            "OS": os_name,
            "OS accuracy": os_accuracy,
            "ports": ports
        })

    return hosts_data, csv_rows
    


##############################
##### Outputting Results #####
##############################

def export_results(scan_data: List[Dict], csv_rows: List[Dict], config: Config) -> None:
    if config.format == "all":
        export_csv(csv_rows, config)
        info("Successfully exported to csv", config)
        export_json(scan_data, config)
        info("Successfully exported to json", config)
        export_html(config)
        info("Successfully exported to html", config)
    elif config.format == "csv":
        export_csv(csv_rows, config)
        info("Successfully exported to csv", config)
    elif config.format == "json":
        export_json(scan_data, config)
        info("Successfully exported to json", config)
    else:
        export_html(config) 
        info("Successfully exported to html", config)




def export_csv(csv_rows: List[Dict], config: Config) -> None:
    with open(config.paths["csv"], "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()        
        writer.writerows(csv_rows)

    if config.auto_open in ("both", "csv"):
        info("Opening CSV report...", config)
        try:
            open_file(config.paths["csv"])
        except Exception as error:
            info(f"CSV file failed to open automatically: {error}", config, level=0)




def export_json(scan_data: List[Dict], config: Config) -> None:
    with open(config.paths["json"], "w") as json_file:
        json.dump(scan_data, json_file, indent=4)




def export_html(config: Config) -> None:
    find_xsl(config)
    if HOST_OS == "Windows":

        subprocess.run([
            "powershell",                   
            "-ExecutionPolicy", "Bypass",    
            "-File", PWS_SCRIPT,
            "-XmlPath", config.paths["xml"],
            "-XslPath", config.paths["xsl"],
            "-HtmlOutput", config.paths["html"]
            ],
            check=True
        )

    else:
       subprocess.run([
            "xsltproc",
            config.paths["xsl"],
            config.paths["xml"]
            ],
            stdout=open(config.paths["html"], "w"),
            check=True
        )

    if config.auto_open in ("both", "html"):
        info("Opening HTML report in browser...", config)
        try:
            open_file(config.paths["html"])
        except Exception as error:
            info(f"HTML file failed to open automatically: {error}", config, level=0)



##############################################
##### CLI definition and Config assembly #####
##############################################

def cli_input() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run and parse Nmap scans with structured output formats")

    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    
    run_parser = subparsers.add_parser("run", help="Run an nmap scan")
    run_parser.add_argument("target", help="Specify the target IP")
    run_parser.add_argument("--format", "-f", choices=["csv", "json", "html", "all"], help="Output format")
    run_parser.add_argument("--auto-open", "-ao", choices=["csv", "html", "both"], help="Select which files to automatically open upon completion")
    run_parser.add_argument("--output-dir", "-o", help="Choose the directory to write output files, default: output directory")
    run_parser.add_argument("--command", "-c", nargs=argparse.REMAINDER)
    run_parser.add_argument("--nmap-path", "-n", help="Provide the path to nmap manually")
    run_parser.add_argument("--overwrite", "-ow", help="Overwrite existing output files", action="store_true")
    run_parser.add_argument("--verbosity", "-v", action="count", default=0, help="Set the level of verbosity to control the detail in the scripts output (-v, -vv)")
    run_parser.add_argument("--scan-preset", "-sp", choices=SCAN_PRESETS.keys(), help="Select a preset for a set of Nmap commands")
    run_parser.add_argument("--dry-run", "-dr", action="store_true", help="Run a dry run.")

    run_parser.set_defaults(func=run_command)


    parse_parser = subparsers.add_parser("parse", help="Parse existing XML")
    parse_parser.add_argument("xml_file", help="Path to XML file")
    parse_parser.add_argument("--format", "-f", choices=["csv", "json", "html", "all"], help="Output format")
    parse_parser.add_argument("--auto-open", "-ao", choices=["csv", "html", "both"], help="Select which files to automatically open upon completion")
    parse_parser.add_argument("--output-dir", "-o", help="Choose the directory to write output files, default: output directory")
    parse_parser.add_argument("--verbosity", "-v", action="count", default=0, help="Set the level of verbosity to control the detail in the scripts output (-v, -vv)")
    parse_parser.add_argument("--dry-run", "-dr", action="store_true", help="Run a dry run.")
    parse_parser.add_argument("--overwrite", "-ow", help="Overwrite existing output files", action="store_true")

    parse_parser.set_defaults(func=parse_command)
    
    return parser.parse_args()




def set_config(args: argparse.Namespace, paths: Dict[str, Path]) -> Config:

    command = [paths["nmap"]]
    if args.func == run_command:

        if args.scan_preset:
            command += SCAN_PRESETS[args.scan_preset]

        if args.command:
            command += args.command

        if len(command) == 1:
            command += SCAN_PRESETS["default"]

        command += [args.target, "-oX", "-"]

    return Config(
        paths=paths,
        verbose=args.verbosity,
        format=args.format,
        auto_open=args.auto_open,
        command=list(dict.fromkeys(command)),
        target=getattr(args, "target", None),
        dry_run=args.dry_run
    )
    
    


if __name__ == "__main__":
    args = cli_input()

    output_dir = Path(args.output_dir) if args.output_dir else SCRIPT_DIR.parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)    

    paths = path_builder(output_dir)

    if not(args.overwrite) and any(path.exists() for path in paths.values()):
        raise FileExistsError("Output Files exist, use --overwrite")

    nmap_file_path = find_nmap(getattr(args, "nmap_path", None))
    paths["nmap"] = nmap_file_path
    if hasattr(args, "xml_file"):
        paths["xml"] = Path(args.xml_file)

    config = set_config(args, paths)

    info(f"Nmaps file path was found at: \n\t{nmap_file_path}", config, level=2)
    info(f"Output directory set to: \n\t{output_dir}", config)
    
    args.func(config)

