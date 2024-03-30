# nepali
aka NePaLi (Nessus Parser Lite)
nepali is a python script that will parse Nessus scan results and then export the results into a spreadsheet format (Microsoft Excel ".xlsx"). nepali parses Nessus XML output files (by default files are saved with ".nessus" extension).

## Prerequisites
nepali uses the following public modules:
- xml.etree.ElementTree
- xlsxwriter
- argparse
- os
- sys
- datetime
- traceback
- ipaddress
- zipfile
- requests
- bs4
- json

## Usage
The following command line options are supported:
- -h, --help  show this help message and exit
- -d D    Location of the directory in which the Nessus output files are stored.
- -f F    Name of the nessus file you want to parse. Ignored if -d option is used.
- -g      Do not get missing field data (default is to make attempt
- -n      Include "None" severity items in output (default does not include them)

## Author
Matthew Flick
