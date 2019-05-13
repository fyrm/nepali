# nepali
aka NePaLi (Nessus Parser Lite)
nepali is a python script that will parse Nessus scan results and then export the results into a spreadsheet format (Microsoft Excel ".xlsx").

## Prerequisites
nepali uses the following public modules:
- xml.etree.ElementTree
- xlsxwriter
- argparse
- os
- datetime
- dateparser
- decimal
- traceback
- sys
- ipaddress
- re
nepali parses Nessus XML output files (by default files are saved with ".nessus" extension).

## Usage
The following command line options are supported:
- "-d <directory>" : location of Nessus output files to be parsed and output will be saved
- "-f <filename>" : name of the Nessus output file to be parsed (current directory is assumed for location)
- "-i f" : instructs nepali to not include informational (severity=0) plugins in output; "-i false" works too
- "-o <filename_base>" : base of the filename for the output file; "__parsed__(<YYYYMMDD_HHMM>).xlsx" is added automatically

## Author
Matthew Flick
