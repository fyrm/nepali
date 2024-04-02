#!/usr/bin/python3
'''
nepali
	aka NePaLi (Nessus Parser Lite)
	Nessus scan results parser that exports the results into a spreadsheet format.
	Created and distributed by FYRM Associates

	Requirements:
		Python 3 with imported modules listed below (tested with Python 3.9.6)
		One or more Nessus XML scan output files
			(".nessus" format)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import xml.etree.ElementTree as ET
import xlsxwriter
import argparse
import os
import sys
import datetime
import traceback
import ipaddress
import zipfile
import requests
from bs4 import BeautifulSoup
import json

'''

-- Global variables --

'''
nessus_severity_risk_dict = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "None"}
cvss_risk_dict = {"Critical": {"min": 9.0, "max": 10.0}, "High": {"min": 7.0, "max": 8.9},
				  "Medium": {"min": 4.0, "max": 6.9}, "Low": {"min": 0.1, "max": 3.9}, "None": {"min": 0.0, "max": 0.0}}
host_props_to_get = ["operating-system", "host-ip", "hostname", "host-fqdn", "netbios-name", "system-type",
					 "HOST_START", "HOST_END", "Credentialed_Scan"]
#	error_plugin_id_list has plugin IDs for plugins that report scan errors
#		I chose a subset of all possible ones included in this article:
#		https://community.tenable.com/s/article/Useful-plugins-to-troubleshoot-credential-scans?language=en_US
error_plugin_id_list = ["10428", "11149", "21745", "24786", "26917", "35705", "35705", "104410", "110385", "117885"]
#	plugin_missing_fields_default has keys for data fields that are sometimes not included in scan exports
#		so there's a function to get these values from the tenable web site
#		could add more fields, like the following, but these may not be important to you
#		"cvss3_base_score", "cvss_base_score", "cvss3_temporal_score", "cvss_temporal_score", ...
#	plugin_downloaded_content will hold values for these downloaded field values but only for each nepali run
#	scraping_timeout is the max amount of time (in seconds) to wait for response from the tenable web site
#	if more than scraping_attempts_max timeouts occur, stop future attempts by setting web_scraping_failed = True
plugin_missing_fields_default = ["description", "patch_publication_date", "plugin_publication_date", "synopsis"]
plugin_downloaded_content = {}
scraping_timeout = 3
scraping_attempts_max = 3
web_scraping_failed = False

'''

-- Start of non-main function declarations --

'''

'''

	find_nessus_output
	
		find all Nessus output files, including those in .zip archives

'''
def find_nessus_output(directory):
	try:
		files = []
		print("Searching", directory, "for .nessus files")
		for file in os.listdir(directory):
			if not file.startswith("~$"):
				if file.endswith(".zip"):
					file = extract_nessus_zip(directory, file)
				if file.endswith(".nessus"):
					print("Found:", file)
					filepath = directory
					if not filepath.endswith("/"):
						filepath += "/"
					filepath += file
					files.append(filepath)
				else:
					continue
		print("Finished search for .nessus files")
		return files
	except Exception as e:
		print("==== Exception ====")
		print("find_nessus_output()")
		print(e)
		traceback.print_exc()
		print("===================")
		return []

'''

	extract_nessus_zip
	
		extract a single .nessus file from a zip file and rename it

'''
def extract_nessus_zip(directory, zfile):
	ret_filename = ""
	try:
		if zfile.endswith(".zip"):
			if not directory.endswith("/"):
				directory += "/"
			zfilename, zextension = os.path.splitext(zfile)
			zfilepath = directory + zfile
			print("parsing", zfilepath)
			with zipfile.ZipFile(zfilepath, "r") as zf:
				zf_filename_list = zf.namelist()
				for nfile in zf_filename_list:
					nfilename, nextension = os.path.splitext(nfile)
					if not str(nfilename).startswith("."):
						if nextension == ".nessus":
							zf.extract(nfile, directory)
							print("\textracted", nfile, "from", zfile)
							new_filename = zfilename + "---" + nfile
							new_filepath = directory + new_filename
							nfilepath = directory + nfile
							os.rename(nfilepath, new_filepath)
							print("\trenamed to:", new_filename)
							ret_filename = new_filename
							break
	except Exception as e:
		print("==== Exception ====")
		print("extract_nessus_zip()")
		print(e)
		traceback.print_exc()
		print("===================")
	return ret_filename

'''

	scrape_plugin_data
	
		example page: https://www.tenable.com/plugins/nessus/189356
			<script id="__NEXT_DATA__" nonce="nonce-asdf" type="application/json">
				{"props":{"pageProps":{"plugin":{...}}} </script>

'''
def scrape_plugin_data(plugin_id):
	retval = {}
	try:
		plugin_url_base = "https://www.tenable.com/plugins/nessus/"
		plugin_url = plugin_url_base + str(plugin_id)
		response = ""
		response_attempt_count = 0
		while response == "" and response_attempt_count < scraping_attempts_max:
			try:
				response = requests.get(plugin_url, timeout=scraping_timeout)
			except:
				response_attempt_count += 1
		if response_attempt_count >= scraping_attempts_max:
			web_scraping_failed = True
		else:
			html_code = response.text
			soup = BeautifulSoup(html_code, "html.parser")
			id_marker = "__NEXT_DATA__"
			plugin_data_element = soup.find("script", attrs={"type": "application/json", "id": id_marker})
			if not plugin_data_element is None:
				plugin_data_element_str = plugin_data_element.string
				plugin_data_json = json.loads(plugin_data_element_str)
				if "props" in plugin_data_json.keys():
					if "pageProps" in plugin_data_json["props"].keys():
						if "plugin" in plugin_data_json["props"]["pageProps"].keys():
							#	print for debugging purposes
							if "doc_id" in plugin_data_json["props"]["pageProps"]["plugin"].keys():
								doc_id = plugin_data_json["props"]["pageProps"]["plugin"]["doc_id"]
								print("\tscraping Tenable web site for missing data for plugin ID:", doc_id)
							for field in plugin_missing_fields_default:
								if field in plugin_data_json["props"]["pageProps"]["plugin"].keys():
									retval[field] = plugin_data_json["props"]["pageProps"]["plugin"][field]
	except Exception as e:
		print("==== Exception ====")
		print("scrape_plugin_data()")
		print(e)
		traceback.print_exc()
		print("===================")
	return retval

'''

	get_cred_scan
	
		https://www.tenable.com/plugins/nessus/19506
		
'''
def get_cred_scan(plugin_output):
	default_retval = "false"
	try:
		for line in plugin_output.splitlines():
			if line.startswith("Credentialed_Scan:"):
				if ":" in line:
					cs_val = line.split(":")[1].strip()
					if cs_val.lower() in ["true", "false"]:
						return cs_val
					else:
						print("\nWarning: Credentialed_Scan line is not properly formatted; value is neither true nor false")
				else:
					print("\nWarning: Credentialed_Scan line is not properly formatted; missing the colon character")
	except Exception as e:
		print("==== Exception ====")
		print("get_cred_scan()")
		print(e)
		traceback.print_exc()
		print("===================")
	return default_retval

'''

	fix_spacing_issues
	
		fix spacing issues within a string
		this might seem like overkill, but some plugins include unnecessary whitespace chars inside individual strings
		also this code gives up a little efficiency for easier readability and editability

'''
def fix_spacing_issues(instring):
	try:
		if (instring == None or instring == ""):
			return ""
		instring = instring.strip()
		while "  " in instring:
			instring = instring.replace("  ", " ")
		while "\n " in instring:
			instring = instring.replace("\n ", "\n")
		while " \n" in instring:
			instring = instring.replace(" \n", "\n")
		while " \t" in instring:
			instring = instring.replace(" \t", "\t")
		while "\t " in instring:
			instring = instring.replace("\t ", "\t")
		while "\n\n" in instring:
			instring = instring.replace("\n\n", "\n")
		while "\t\t" in instring:
			instring = instring.replace("\t\t", "\t")
		while "\t\n" in instring:
			instring = instring.replace("\t\n", "\n")
		while "\n;" in instring:
			instring = instring.replace("\n;", ";")
		instring = instring.replace(" :", ":")
		instring = instring.replace(" ;", ";")
		instring = instring.replace(" ,", ",")
		instring = instring.replace("( ", "(")
		instring = instring.replace(" )", ")")
	except Exception as e:
		print("==== Exception ====")
		print("fix_spacing_issues()")
		print(e)
		traceback.print_exc()
		print("===================")
	return instring

'''

	patch_abbreviation_fix
	
		replace abbreviated versions of the word "patch" written by some plugins

'''
def patch_abbreviation_fix(instring):
	try:
		instring = instring.strip()
		instring = instring.replace(" patc.", " patch")
		instring = instring.replace(" pat.", " patch")
		#instring = instring.replace(" pa.", " patch")
		#instring = instring.replace(" p.", " patch")
	except Exception as e:
		print("==== Exception ====")
		print("patch_abbreviation_fix()")
		print(e)
		traceback.print_exc()
		print("===================")
	return instring

'''

	parse_cpe_data
	
		function to parse a CPE list
		
		positions split by ":"
		0	:	1	:	2		:	3		:	4		:	5		:	6		:	7
		cpe:/ {part} : {vendor} : {product} : {version} : {update} : {edition} : {language}
		
		nepali is only including up to the version, so disregarding positions after that

'''
def parse_cpe_data(cpe_data):
	cpe_list = []
	try:
		for all_cpe in cpe_data:
			cpe_list_lines = all_cpe.text.splitlines()
			for cpe_line in cpe_list_lines:
				cpe_words = cpe_line.split(':')
				if len(cpe_words) > 1:
					part = cpe_words[1]
					if len(cpe_words) > 2:
						vendor = cpe_words[2]
						if len(cpe_words) > 3:
							product = cpe_words[3]
							if len(cpe_words) > 4:
								version = cpe_words[4]
								if vendor == product:
									cpe_list.append(vendor + " " + version)
								else:
									cpe_list.append(vendor + " " + product + " " + version)
							else:
								if vendor == product:
									cpe_list.append(vendor)
								else:
									cpe_list.append(vendor + " " + product)
						else:
							cpe_list.append(vendor)
	except Exception as e:
		print('\n==== Exception ====\n\tparse_cpe_data()\n----')
		print(e)
		traceback.print_exc()
		print('\n===================')
	return cpe_list
'''

	parse_host_properties
	
		function to parse a single host properties item

'''
def parse_host_properties(host):
	target_dict = {}
	try:
		target_dict["hostname"] = host.get("name")
		print("\tParsing:", target_dict["hostname"])
		#	only get the specific data from the host properties as defined in host_props_to_get (global variable)
		#	copied here for reference:
		#		host_props_to_get = ["operating-system", "host-ip", "hostname", "host-fqdn", "netbios-name", 
		#							 "system-type", "HOST_START", "HOST_END", "Credentialed_Scan"]
		#	set all of these properties initially to ensure the keys exist in target_dict
		for prop in host_props_to_get:
			target_dict[prop] = ""
		for item in host.iter("HostProperties"):
			for data in item:
				data_name = data.get("name")
				if data_name in host_props_to_get:
					target_dict[data_name] = data.text
		#	do some clean up of host properties since there may be inconsistencies or missing data
		try:
			#	Test if the IP address is in the host "name" field
			test = ipaddress.ip_address(target_dict["hostname"])
			#	If the test passed, then the target IP address is in hostname
			if (not "host-ip" in target_dict.keys() or target_dict["host-ip"] == ""):
				target_dict["host-ip"] = target_dict["hostname"]
			if (not "host-fqdn" in target_dict.keys() or target_dict["host-fqdn"] == ""):
				target_dict["host-fqdn"] = "Unavailable"
		except:
			if (not "hostname" in target_dict.keys() or target_dict["hostname"] == ""):
				target_dict["hostname"] = "Unavailable"
			if (not "host-fqdn" in target_dict.keys() or target_dict["host-fqdn"] == ""):
				target_dict["host-fqdn"] = target_dict["hostname"]
			if (not "host-ip" in target_dict.keys() or target_dict["host-ip"] == ""):
				target_dict["host-ip"] = "x.x.x.x"
		#	create the "Target Name" field
		target_dict["Target Name"] = ""
		if "host-fqdn" in target_dict.keys() and len(target_dict["host-fqdn"]) > 0:
			if "host-ip" in target_dict.keys() and len(target_dict["host-ip"]) > 0:
				if not target_dict["host-fqdn"] == target_dict["host-ip"]:
					target_dict["Target Name"] = target_dict["host-fqdn"] + " (" + target_dict["host-ip"] + ")"
				else:
					target_dict["Target Name"] = target_dict["host-fqdn"]
			else:
				target_dict["Target Name"] = target_dict["host-fqdn"]
		elif "netbios-name" in target_dict.keys() and len(target_dict["netbios-name"]) > 0:
			if "host-ip" in target_dict.keys() and len(target_dict["host-ip"]) > 0:
				if not target_dict["netbios-name"] == target_dict["host-ip"]:
					target_dict["Target Name"] = target_dict["netbios-name"] + " (" + target_dict["host-ip"] + ")"
				else:
					target_dict["Target Name"] = target_dict["netbios-name"]
			else:
				target_dict["Target Name"] = target_dict["netbios-name"]
	except Exception as e:
		print("==== Exception ====")
		print("parse_host_properties()")
		print(e)
		traceback.print_exc()
		print("===================")
	return target_dict

'''

	parse_report_item
	
		parse a single report item ("issue", "vulnerability", or "audit check failure")
		input parameters:
			item = a single report item
			target_dict = the target dictionary associated with this report item
			out_col_dict = output column style dictionary
			ns = Nessus XML Namespace
			get_mfd = whether to obtain missing data (refer to plugin_missing_fields_default)

'''
def parse_report_item(item, target_dict, out_col_dict, ns, get_mfd=True):
	report_item_dict = {}
	try:
		#	initialize all mapped keys used in the output worksheets
		#		out_col_dict["issue"][col_name]["map"]
		for col_name, col_dict in out_col_dict["issue"].items():
			report_item_dict[col_dict["map"]] = ""
		#	now parse the report item for content
		#	"attributes" in the ReportItem tag (common content) first
		report_item_dict["plugin_id"] = item.get("pluginID")
		report_item_dict["plugin_name"] = item.get("pluginName")
		#	plugin name should be stored in 2 places
		#	go with the <plugin_name> field instead of the ReportItem attribute if different
		temp_name = fix_spacing_issues(item.findtext("plugin_name", default=""))
		if report_item_dict["plugin_name"] is None or temp_name != report_item_dict["plugin_name"]:
			report_item_dict["plugin_name"] = temp_name
		report_item_dict["port"] = item.get("port")
		report_item_dict["protocol"] = item.get("protocol")
		report_item_dict["severity"] = item.get("severity")
		if str(report_item_dict["severity"]) in nessus_severity_risk_dict.keys():
			report_item_dict["Nessus Risk"] = nessus_severity_risk_dict[str(report_item_dict["severity"])]
		else:
			print("Warning: severity value is not in nessus_severity_risk_dict.")
		report_item_dict["description"] = fix_spacing_issues(item.findtext("description", default=""))
		report_item_dict["description"] = patch_abbreviation_fix(report_item_dict["description"])
		report_item_dict["plugin_output"] = fix_spacing_issues(item.findtext("plugin_output", default=""))
		if str(report_item_dict["plugin_id"]) == "19506":
			target_dict["Credentialed_Scan"] = get_cred_scan(report_item_dict["plugin_output"])
		cve_list = []
		try:
			all_cves = item.findall("cve")
			for cve in all_cves:
				cve_list.append(cve.text)
		except:
			cve_list.append("N/A")
		report_item_dict["cves"] = ",".join(cve_list)
		cpe_list = []
		try:
			all_cpes = item.findall("cpe")
			cpe_list = parse_cpe_data(cpe_data=all_cpes)
		except:
			cpe_list.append("N/A")
		report_item_dict["Product Name"] = "\n".join(cpe_list)
		report_item_dict["operating-system"] = target_dict.get("operating-system", "Unavailable")
		#
		#	The available fields and field names vary depending on whether the plugin is in the compliance set or not 
		#	First set - deal with plugins that are not compliance checks
		if not "Compliance" in report_item_dict["plugin_name"]:
			report_item_dict["synopsis"] = item.findtext("synopsis", default="")
			report_item_dict["solution"] = item.findtext("solution", default="")
			report_item_dict["patch_publication_date"] = item.findtext("patch_publication_date", default="")
			report_item_dict["plugin_publication_date"] = item.findtext("plugin_publication_date", default="")
			report_item_dict["plugin_modification_date"] = item.findtext("plugin_modification_date", default="")
			report_item_dict["exploit_available"] = item.findtext("exploit_available", default="")
			report_item_dict["see_also"] = item.findtext("see_also", default="")
			report_item_dict["cvss3_base_score"] = item.findtext("cvss3_base_score", default="")
			report_item_dict["cvss3_vector"] = item.findtext("cvss3_vector", default="")
			report_item_dict["cvss3_temporal_score"] = item.findtext("cvss3_temporal_score", default="")
			report_item_dict["cvss3_temporal_vector"] = item.findtext("cvss3_temporal_vector", default="")
			report_item_dict["cvss_base_score"] = item.findtext("cvss_base_score", default="")
			report_item_dict["cvss_vector"] = item.findtext("cvss_vector", default="")
			report_item_dict["cvss_temporal_score"] = item.findtext("cvss_temporal_score", default="")
			report_item_dict["cvss_temporal_vector"] = item.findtext("cvss_temporal_vector", default="")
			#
			#	Plugins will include only v3, only v2, both v3 and v2, or neither CVSS base scores
			#	cvss3or2_base_score opts for v3 when it exists and v2 if not; otherwise leave blank
			report_item_dict["cvss3or2_base_score"] = ""
			if (report_item_dict["cvss3_base_score"] != None and report_item_dict["cvss3_base_score"] != ""):
				report_item_dict["cvss3or2_base_score"] = report_item_dict["cvss3_base_score"]
			elif (report_item_dict["cvss_base_score"] != None and report_item_dict["cvss_base_score"] != ""):
				report_item_dict["cvss3or2_base_score"] = report_item_dict["cvss_base_score"]
			if report_item_dict["cvss3or2_base_score"] != "":
				get_key = lambda x, d: next((key for key, value in d.items() if value["min"] <= x <= value["max"]), "")
				cvss_score_float = float(report_item_dict["cvss3or2_base_score"])
				report_item_dict["CVSS Risk"] = get_key(x=cvss_score_float, d=cvss_risk_dict)
		#
		#	Second set - deal with compliance checks
		elif "Compliance" in report_item_dict["plugin_name"]:
			#	Not all audit compliance checks have each field, so using independent try"s
			try:
				#	use cm:compliance-check-name instead of plugin_name
				report_item_dict["plugin_name"] = fix_spacing_issues(item.find("cm:compliance-check-name", ns).text)
			except:
				pass
			try:
				# use cm:compliance-actual-value instead of plugin_output
				report_item_dict["plugin_output"] = fix_spacing_issues(item.find("cm:compliance-actual-value", ns).text)
			except:
				pass
			try:
				#	use cm:compliance-info instead of synopsis
				report_item_dict["synopsis"] = fix_spacing_issues(item.find("cm:compliance-info", ns).text)
			except:
				pass
			try:
				#	use cm:compliance-solution instead of solution
				report_item_dict["solution"] = fix_spacing_issues(item.find("cm:compliance-solution", ns).text)
			except:
				pass
			try:
				#	use cm:compliance-see-also instead of see_also
				report_item_dict["see_also"] = fix_spacing_issues(item.find("cm:compliance-see-also", ns).text)
			except:
				pass
		#
		#	try to get the static content for missing fields
		#		copied here for reference:
		#		plugin_missing_fields_default = ["description", "patch_publication_date",
		#			"plugin_publication_date", "synopsis", "cvss3_base_score", "cvss_base_score"]
		if get_mfd is True and web_scraping_failed is False:
			for mfd in plugin_missing_fields_default:
				if report_item_dict[mfd] is None or report_item_dict[mfd] == "" or len(
						report_item_dict[mfd]) == 0:
					#	if one field is missing then most likely all of these items are missing, so just get the static content for all of them
					#	first check the current content we have downloaded
					#	if the current plugin_id has not yet been scraped, then scrape it
					this_plugin_id = report_item_dict["plugin_id"]
					if this_plugin_id in plugin_downloaded_content.keys():
						for plugin_key, plugin_val in plugin_downloaded_content[this_plugin_id].items():
							report_item_dict[plugin_key] = plugin_val
					else:
						scraped_plugin_dict = scrape_plugin_data(this_plugin_id)
						if not scraped_plugin_dict is None and len(scraped_plugin_dict) > 0:
							plugin_downloaded_content[this_plugin_id] = {}
							for scraped_key, scraped_val in scraped_plugin_dict.items():
								report_item_dict[scraped_key] = scraped_val
								plugin_downloaded_content[this_plugin_id][scraped_key] = scraped_val
	except Exception as e:
		print("==== Exception ====")
		print("parse_report_item()")
		print(e)
		traceback.print_exc()
		print("===================")
	return report_item_dict

'''

	write_worksheet_data
	
		write row data to a given worksheet
		input parameters:
			ws_type in ["issue", "error", "time"]
			row_item_list is a list of dictionaries with data for each row in the output

'''
def write_worksheet_data(worksheet, ws_type, row_item_list, out_col_dict, ws_row_count):
	try:
		if ws_type in out_col_dict.keys():
			for row_item_dict in row_item_list:
				for col_name, col_dict in out_col_dict[ws_type].items():
					#	col_name is just the output title, so we need the "map" value as a key in the row_item_dict
					value = row_item_dict[col_dict["map"]]
					worksheet.write(ws_row_count, col_dict["num"], value, col_dict["font"])
				ws_row_count += 1
	except Exception as e:
		print("==== Exception ====")
		print("write_worksheet_data()")
		print(e)
		traceback.print_exc()
		print("===================")
	return worksheet, ws_row_count

'''

	set_out_col_style
	
		sets the style values that will be applied to cells in the output workbook/spreadsheet
		returns two dictionaries:
			cell_fonts
			out_col_dict

		the following variables contain the style values:
			cell_fonts : style aspects applied to different cells
			out_col_dict : contains various data fields for the worksheets in the output workbook/spreadsheet,
							including fonts
		there are three (3) worksheet types, each of which has a different set of columns/fields:
			"target"
			"error"
			"issue"
		data fields for each worksheet include the following:
			column number ("num")
			column width ("width")
			data dictionary key to which the output field name is mapped ("map")
			style/font for the cells in that field ("font")
'''
def set_out_col_style(workbook, cell_fonts, out_col_dict):
	try:
		# setting cell formatting styles
		cell_fonts["left"] = workbook.add_format()
		cell_fonts["left"].set_align("top")
		cell_fonts["left"].set_text_wrap()
		cell_fonts["left"].set_border()
		cell_fonts["center"] = workbook.add_format()
		cell_fonts["center"].set_align("center")
		cell_fonts["center"].set_align("top")
		cell_fonts["center"].set_text_wrap()
		cell_fonts["center"].set_border()
		cell_fonts["header"] = workbook.add_format({"bold": True})
		cell_fonts["header"].set_bg_color("#336699")
		cell_fonts["header"].set_font_color("#FFFFFF")
		cell_fonts["header"].set_align("center")
		cell_fonts["header"].set_align("top")
		cell_fonts["header"].set_text_wrap()
		cell_fonts["header"].set_border()
		cell_fonts["date_format"] = workbook.add_format({"num_format": "yyyy-mm-dd"})
		cell_fonts["date_format"].set_align("center")
		cell_fonts["date_format"].set_align("top")
		cell_fonts["date_format"].set_text_wrap()
		cell_fonts["date_format"].set_border()
		cell_fonts["datetime_format"] = workbook.add_format({"num_format": "yyyy-mm-dd hh:mm:ss"})
		cell_fonts["datetime_format"].set_align("center")
		cell_fonts["datetime_format"].set_align("top")
		cell_fonts["datetime_format"].set_text_wrap()
		cell_fonts["datetime_format"].set_border()
		#	setting column order number, width, mapping, and font
		#	"time" type worksheet
		out_col_dict["time"] = {
			"File Name": {"num": 0, "width": 25, "map": "File Name", "font": cell_fonts["center"]},
			"Report Name": {"num": 1, "width": 25, "map": "Report Name", "font": cell_fonts["center"]},
			"Target Name": {"num": 2, "width": 42, "map": "Target Name", "font": cell_fonts["center"]},
			"FQDN": {"num": 3, "width": 25, "map": "host-fqdn", "font": cell_fonts["center"]},
			"IP Address": {"num": 4, "width": 15, "map": "host-ip", "font": cell_fonts["center"]},
			"System Type": {"num": 5, "width": 15, "map": "system-type", "font": cell_fonts["center"]},
			"Credentialed Scan": {"num": 6, "width": 16, "map": "Credentialed_Scan", "font": cell_fonts["center"]},
			"Start Time": {"num": 7, "width": 25, "map": "HOST_START", "font": cell_fonts["datetime_format"]},
			"End Time": {"num": 8, "width": 25, "map": "HOST_END", "font": cell_fonts["datetime_format"]}
		}
		#	"error" type worksheet
		out_col_dict["error"] = {
			"File Name": {"num": 0, "width": 40, "map": "File Name", "font": cell_fonts["center"]},
			"Report Name": {"num": 1, "width": 40, "map": "Report Name", "font": cell_fonts["center"]},
			"Plugin ID": {"num": 2, "width": 10, "map": "plugin_id", "font": cell_fonts["center"]},
			"Plugin Name": {"num": 3, "width": 30, "map": "plugin_name", "font": cell_fonts["center"]},
			"Plugin Output": {"num": 4, "width": 50, "map": "plugin_output", "font": cell_fonts["left"]},
			"Target Name": {"num": 5, "width": 42, "map": "Target Name", "font": cell_fonts["center"]},
			"FQDN": {"num": 6, "width": 30, "map": "host-fqdn", "font": cell_fonts["center"]},
			"IP Address": {"num": 7, "width": 22, "map": "host-ip", "font": cell_fonts["center"]}
		}
		#	"issue" type worksheet
		out_col_dict["issue"] = {
			"Plugin Name":{"num":0, "width":20, "map":"plugin_name", "font":cell_fonts["center"]},
			"Product Name":{"num":1, "width":30, "map":"Product Name", "font":cell_fonts["center"]},
			"Description":{"num":2, "width":50, "map":"description", "font":cell_fonts["left"]},
			"Synopsis":{"num":3, "width":25, "map":"synopsis", "font":cell_fonts["left"]},
			"Plugin Output":{"num":4, "width":40, "map":"plugin_output", "font":cell_fonts["left"]},
			"Solution":{"num":5, "width":30, "map":"solution", "font":cell_fonts["left"]},
			"Patch Publication Date":{"num":6, "width":25, "map":"patch_publication_date",
									   "font":cell_fonts["date_format"]},
			"Plugin Publication Date":{"num":7, "width":25, "map":"plugin_publication_date",
										"font":cell_fonts["date_format"]},
			"Plugin Modification Date":{"num":8, "width":25, "map":"plugin_modification_date",
										 "font":cell_fonts["date_format"]},
			"Target Name":{"num":9, "width":42, "map":"Target Name", "font":cell_fonts["center"]},
			"FQDN":{"num":10, "width":25, "map":"host-fqdn", "font":cell_fonts["center"]},
			"Hostname":{"num":11, "width":25, "map":"hostname", "font":cell_fonts["center"]},
			"IP":{"num":12, "width":15, "map":"host-ip", "font":cell_fonts["center"]},
			"Port":{"num":13, "width":6, "map":"port", "font":cell_fonts["center"]},
			"Protocol":{"num":14, "width":8, "map":"protocol", "font":cell_fonts["center"]},
			"Nessus Plugin ID":{"num":15, "width":13, "map":"plugin_id", "font":cell_fonts["center"]},
			"Associated CVEs":{"num":16, "width":15, "map":"cves", "font":cell_fonts["center"]},
			"Reference Links":{"num":17, "width":50, "map":"see_also", "font":cell_fonts["left"]},
			"Exploit Available":{"num":18, "width":13, "map":"exploit_available",
								  "font":cell_fonts["center"]},
			"Operating System":{"num":19, "width":30, "map":"operating-system",
								  "font":cell_fonts["center"]},
			"Nessus Severity":{"num":20, "width":13, "map":"severity", "font":cell_fonts["center"]},
			"Nessus Risk":{"num":21, "width":13, "map":"Nessus Risk", "font":cell_fonts["center"]},
			"CVSS Risk":{"num":22, "width":13, "map":"CVSS Risk", "font":cell_fonts["center"]},
			"CVSS 3-or-2 Base Score":{"num":23, "width":20, "map":"cvss3or2_base_score",
									   "font":cell_fonts["center"]},
			"CVSS 3.0 Base Score":{"num":24, "width":15, "map":"cvss3_base_score",
									"font":cell_fonts["center"]},
			"CVSS 3.0 Base Vector":{"num":25, "width":30, "map":"cvss3_vector", "font":cell_fonts["center"]},
			"CVSS 3 Temporal Score":{"num":26, "width":15, "map":"cvss3_temporal_score",
									  "font":cell_fonts["center"]},
			"CVSS 3 Temporal Vector":{"num":27, "width":30, "map":"cvss3_temporal_vector",
									  "font":cell_fonts["center"]},
			"CVSS 2 Base Score":{"num":28, "width":15, "map":"cvss_base_score", "font":cell_fonts["center"]},
			"CVSS 2 Base Vector":{"num":29, "width":25, "map":"cvss_vector", "font":cell_fonts["center"]},
			"CVSS 2 Temporal Score":{"num":30, "width":15, "map":"cvss_temporal_score",
									  "font":cell_fonts["center"]},
			"CVSS 2 Temporal Vector":{"num":31, "width":25, "map":"cvss_temporal_vector",
									   "font":cell_fonts["center"]}
		}
	except Exception as e:
		print("==== Exception ====")
		print("find_nessus_output()")
		print(e)
		traceback.print_exc()
		print("===================")
	return cell_fonts, out_col_dict

'''

	prep_worksheet
	
		prepare a results worksheet

'''
def prep_worksheet(worksheet, ws_type, cell_fonts, out_col_dict):
	try:
		if ws_type in out_col_dict.keys():
			# set column width and column titles (first row values)
			for col_name, col_dict in out_col_dict[ws_type].items():
				worksheet.set_column(col_dict["num"], col_dict["num"], col_dict["width"])
				worksheet.write(0, col_dict["num"], col_name, cell_fonts["header"])
		# freeze the first row and column in view
		worksheet.freeze_panes(1, 1)
	except Exception as e:
		print("==== Exception ====")
		print("prep_worksheet()")
		print(e)
		traceback.print_exc()
		print("===================")
	return worksheet

'''

	prep_workbook
	
		prepare the results workbook/spreadsheet
		this includes adding worksheets with names, fonts, and header rows
			fonts/styles set in set_out_col_style() function
			worksheets created/started in prep_worksheet() function

'''
def prep_workbook(wb_name, ws_dict, cell_fonts, out_col_dict):
	workbook = ""
	try:
		workbook = xlsxwriter.Workbook(wb_name, {"strings_to_urls": False})
		workbook.set_size(2400, 1350)
		cell_fonts, out_col_dict = set_out_col_style(workbook=workbook, cell_fonts=cell_fonts,
								  out_col_dict=out_col_dict)
		for ws_nickname, ws_struct_dict in ws_dict.items():
			temp = workbook.add_worksheet(ws_struct_dict["name"])
			temp = prep_worksheet(worksheet=temp, ws_type=ws_struct_dict["type"], cell_fonts=cell_fonts,
								  out_col_dict=out_col_dict)
	except Exception as e:
		print("==== Exception ====")
		print("prep_workbook()")
		print(e)
		traceback.print_exc()
		print("===================")
	return workbook, cell_fonts, out_col_dict

'''

	nepali_logo
	
		a silly little function to return the nepali logo as a string

'''
def nepali_logo():
	try:
		retval = ""
		retval = retval + "\n _______               /\ /\  __________              /\ /\   .____    .__ "
		retval = retval + "\n \      \   ____      / / \ \ \______   \_____       / / \ \  |    |   |__|"
		retval = retval + "\n /   |   \_/ __ \    / /   \ \ |     ___/\__  \     / /   \ \ |    |   |  |"
		retval = retval + "\n/    |    \  ___/   / /     \ \|    |     / __ \_  / /     \ \|    |___|  |"
		retval = retval + "\n\____|__  /\___  > / /       \ \____|    (____  / / /       \ \_______ \__|"
		retval = retval + "\n        \/     \/  \/         \/              \/  \/         \/       \/   "
		retval = retval + "\n\nby FYRM Associates\n"
		return retval
	except Exception as e:
		print("==== Exception ====")
		print("nepali_logo()")
		print(e)
		traceback.print_exc()
		print("===================")
		print("(this is really embarrassing)")
		return "NePaLi"

'''

-- End of non-main function declarations --

'''

'''

	main()

'''
def main():
	try:
		#
		# -- Parse execution arguments and find input files --
		#
		parser = argparse.ArgumentParser()
		parser.add_argument("-d", help="Location of the directory in which the Nessus output files are stored.")
		parser.add_argument("-f", help="Name of the nessus file you want to parse. Ignored if -d option is used.")
		parser.add_argument("-g", action='store_false', help="Do not get missing field data (default is to make attempt")
		parser.add_argument("-n", action='store_true', help="Include \"None\" severity items in output (default does not include them)")
		parser.add_argument("-o", help="Base name of spreadsheet file to which you want the parsed results to be written.")
		'''
			Removed these arguments because they're confusing. Default is now to exclude None severity (severity=0) plugins.
			Initially I added -e to be simpler, but I prefer the default option of not including them.
		parser.add_argument("-e", help="Exclude Informational (None severity) items in output; alternate for (-i F) option")
		parser.add_argument("-i", help="(-i F) Do not include Informational severity items in output (default/omitted == True).")
		'''
		args = parser.parse_args()
		print("\n\n" + nepali_logo() + "\n\nRunning nepali...\n")
		print("<< Finding Nessus output files >>")
		#
		# -- main variables used throughout the function --
		#
		file_list = []
		get_mfd = True
		include_info_items = False
		cell_fonts = {}
		out_col_dict = {}
		workbook = ""
		worksheets = {}
		worksheets["time"] = {"name":"Time", "type": "time", "row_count": 1}
		worksheets["error"] = {"name":"Error", "type": "error", "row_count": 1}
		worksheets["vuln"] = {"name":"Scan Data (vuln)", "type": "issue", "row_count": 1}
		worksheets["audit_fail"] = {"name":"Scan Data (audit fail)", "type": "issue", "row_count": 1}
		worksheets["audit_error"] = {"name":"Scan Data (audit errors)", "type": "issue", "row_count": 1}
		#	parse arguments
		print("args.g:", args.g)
		if args.g is False:
			get_mfd = False
			print("Disabled scraping missing data fields from Tenable web site")
		print("args.n:", args.n)
		if args.n is True:
			include_info_items = True
			print("Including informational items (severity==0) in output")
		try:
			if args.d:
				file_list = find_nessus_output(args.d)
			elif args.f:
				file_list.append(args.f)
			else:
				print("No directory or file argument provided. Trying current directory.")
				file_list = find_nessus_output(".")
		except:
			print(
				"\nERROR: Something went wrong when trying to get .nessus file(s). This is not my fault. You failed miserably and should feel bad.")
			sys.exit()
		print("<< Finished finding Nessus output files >>")
		if file_list == []:
			print("\nNote: input file list is empty; that\'s bad. But also we\'re done. That\'s good. Better luck next time. The sprinkles are also cursed.")
			sys.exit()
		#
		# -- Start of output file prep --
		#
		try:
			timestamp_filename = datetime.datetime.now().strftime("%Y%m%d_%H%M")
			out_filename_base = ""
			if args.o:
				out_filename_base = str(args.o)
				out_filename_base = out_filename_base.replace(".xlsx", "")
			elif len(file_list) == 1:
				out_filename_base = file_list[0].replace(".nessus", "")
			else:
				out_filename_base = "Unnamed_File_Group"
			out_filename_base = out_filename_base + "__parsed"
			out_filename_base = out_filename_base + "__(" + timestamp_filename + ")"
			out_filename = out_filename_base + ".xlsx"
			print("<< Generating Excel Workbook and Worksheets >>")
			workbook, cell_fonts, out_col_dict = prep_workbook(wb_name=out_filename, ws_dict=worksheets,
															   cell_fonts=cell_fonts, out_col_dict=out_col_dict)
			print("<< Finished generating Excel Workbook and Worksheets >>\n")
		#
		# -- End of output file prep
		#
		except Exception as e:
			print("==== Exception ====")
			print("main(): output file prep")
			print(e)
			traceback.print_exc()
			print("===================")
			print("Exiting.")
			sys.exit()

		try:
			#
			# Nessus XML Namespace
			#	This is required to parse the audit compliance results that use an XML namespace
			ns = {"cm": "http://www.nessus.org/cm"}
			#
			# -- Start of file parsing --
			#
			for file in file_list:
				print("<< Parsing files and writing main output >>")
				print("Parsing file: " + file + "\n...")
				filename_nopath = file
				if "/" in filename_nopath:
					filename_nopath = file.split("/")[-1]
				tree = ET.parse(file)
				root = tree.getroot()
				#	output will be written to file after each report to avoid storing too much in memory
				#	use worksheets[ws_key]["name"] to ensure we use the same worksheet names
				report_dict = {}
				report_dict[worksheets["time"]["name"]] = []
				report_dict[worksheets["error"]["name"]] = []
				report_dict[worksheets["vuln"]["name"]] = []
				report_dict[worksheets["audit_fail"]["name"]] = []
				report_dict[worksheets["audit_error"]["name"]] = []
				#	the "Report" sub-element contains results of scan
				for report in root.iter("Report"):
					report_name = report.get("name")
					#	Iterating through each host
					for host in report.iter("ReportHost"):
						target_dict = parse_host_properties(host=host)
						#	parse_host_properties() adds "Target Name" but not "File Name" or "Report Name"
						target_dict["File Name"] = filename_nopath
						target_dict["Report Name"] = report_name
						report_dict[worksheets["time"]["name"]].append(target_dict)
						'''print("\n" + "added to time - target_dict:", target_dict)
						print()'''
						#	Iterating through each report item for this host/target
						print_count = 0
						print_max = 2
						for item in host.iter("ReportItem"):
							report_item_dict = parse_report_item(item, target_dict, out_col_dict, ns, get_mfd)
							#	parse_report_item() does not add "File Name" or "Report Name"
							#		currently only needed with error plugins going into the error worksheet
							for key,val in target_dict.items():
								report_item_dict[key] = val
							#report_item_dict["File Name"] = filename_nopath
							#report_item_dict["Report Name"] = report_name
							'''if print_count < print_max:
								print("\n" + "adding to issue worksheet - report_item_dict:", report_item_dict)
								print()
								print_count += 1'''
							if not "Compliance" in report_item_dict["plugin_name"]:
								#	add to error worksheet if it's in the list (defined globally)
								if report_item_dict["plugin_id"] in error_plugin_id_list:
									report_dict[worksheets["error"]["name"]].append(report_item_dict)
								#	add to vuln worksheet depending on severity and arguments given to nepali
								if include_info_items is True:
									report_dict[worksheets["vuln"]["name"]].append(report_item_dict)
								elif include_info_items is False and report_item_dict["severity"] != "0":
									report_dict[worksheets["vuln"]["name"]].append(report_item_dict)
							elif "Compliance" in report_item_dict["plugin_name"]:
								if "[FAILED]" in report_item_dict["description"]:
									report_dict[worksheets["audit_fail"]["name"]].append(report_item_dict)
								elif "[ERROR]" in report_item_dict["description"]:
									report_dict[worksheets["audit_error"]["name"]].append(report_item_dict)
								else:
									print("Warning: not sure how to report item:", report_item_dict["plugin_name"])
							else:
								print("Warning: not sure how to report item:", report_item_dict["plugin_name"])
						# --End ReportItem iter --
						print("\t\tFinished parsing:", target_dict["Target Name"])
				#	add data to output
				#	worksheets format reminder:
				#		worksheets["time"] = {"name":"Time", "type": "time", "row_count": 1}
				for ws_key, ws_val in worksheets.items():
					ws = workbook.get_worksheet_by_name(worksheets[ws_key]["name"])
					ws_type = worksheets[ws_key]["type"]
					report_item_list = report_dict[worksheets[ws_key]["name"]]
					ws_count = worksheets[ws_key]["row_count"]
					ws, ws_cols = write_worksheet_data(worksheet=ws, ws_type=ws_type, row_item_list=report_item_list,
													   out_col_dict=out_col_dict, ws_row_count=ws_count)
				# --End ReportHost iter
				print("...\nFinished parsing file: " + file)
			# --End Report iter
			workbook.close()
			print("\n--------------------------------\n")
			print("Done. Output workbook saved:\n\n" + out_filename)
			print("\n--------------------------------\n")
			#
			# -- End of file parsing --
			#
		except Exception as e:
			print("==== Exception ====")
			print("main(): file parsing")
			print(e)
			traceback.print_exc()
			print("===================")
			print("Exiting.")
			sys.exit()
	except Exception as e:
		print("==== Exception ====")
		print("main()")
		print(e)
		traceback.print_exc()
		print("===================")
		print("Exiting.")
		sys.exit()

'''

	-- Main program --

'''
if __name__ == "__main__":
	main()

	'''
	I decided it was not worthwhile to put each CVSS vector value into their own column.
	However, I'm leaving these dictionaries in case someone wants to do something with them
	cvss3_keyvalue_dict = {"AV:N": "Attack Vector: Network", "AV:A": "Attack Vector: Adjacent",
						   "AV:L": "Attack Vector: Local", "AV:P": "Attack Vector: Physical",
						   "AC:L": "Attack Complexity: Low", "AC:H": "Attack Complexity: High",
						   "PR:N": "Privileges Required: None", "PR:L": "Privileges Required: Low",
						   "PR:H": "Privileges Required: High", "UI:N": "User Interaction: None",
						   "UI:R": "User Interaction: Required", "S:U": "Scope: Unchanged",
						   "S:C": "Scope: Changed", "C:N": "Confidentiality: None", "C:L": "Confidentiality: Low",
						   "C:H": "Confidentiality: High", "I:N": "Integrity: None", "I:L": "Integrity: Low",
						   "I:H": "Integrity: High",
						   "A:N": "Availability: None", "A:L": "Availability: Low", "A:H": "Availability: High",
						   "E:X": "Exploit Code Maturity: Not Defined", "E:U": "Exploit Code Maturity: Unproven",
						   "E:P": "Exploit Code Maturity: Proof-of-Concept", "E:F": "Exploit Code Maturity: Functional",
						   "E:H": "Exploit Code Maturity: High", "RL:X": "Remediation Level: Not Defined",
						   "RL:O": "Remediation Level: Official Fix",
						   "RL:T": "Remediation Level: Temporary Fix", "RL:W": "Remediation Level: Workaround",
						   "RL:U": "Remediation Level: Unavailable", "RC:X": "Report Confidence: Not Defined",
						   "RC:U": "Report Confidence: Unknown",
						   "RC:R": "Report Confidence: Reasonable", "RC:C": "Report Confidence: Confirmed"}
	cvss2_keyvalue_dict = {"AV:N": "Access Vector: Network", "AV:A": "Access Vector: Adjacent Network",
						   "AV:L": "Access Vector: Local", "AC:L": "Attack Complexity: Low",
						   "AC:M": "Attack Complexity: Medium", "AC:H": "Attack Complexity: High",
						   "Au:M": "Authentication: Multiple", "Au:S": "Authentication: Single",
						   "Au:N": "Authentication: None", "C:N": "Confidentiality Impact: None",
						   "C:P": "Confidentiality Impact: Partial",
						   "C:C": "Confidentiality Impact: Complete", "I:N": "Integrity Impact: None",
						   "I:P": "Integrity Impact: Partial", "I:C": "Integrity Impact: Complete",
						   "A:N": "Availability Impact: None",
						   "A:P": "Availability Impact: Partial", "A:C": "Availability Impact: Complete",
						   "E:U": "Exploitability: Unproven", "E:POC": "Exploitability: Proof-of-Concept",
						   "E:F": "Exploitability: Functional",
						   "E:H": "Exploitability: High", "E:ND": "Exploitability: Not Defined",
						   "RL:OF": "Remediation Level: Official Fix", "RL:TF": "Remediation Level: Temporary Fix",
						   "RL:W": "Remediation Level: Workaround",
						   "RL:U": "Remediation Level: Unavailable", "RL:ND": "Remediation Level: Not Defined",
						   "RC:UC": "Report Confidence: Unconfirmed", "RC:UR": "Report Confidence: Uncorroborated",
						   "RC:C": "Report Confidence: Confirmed",
						   "RC:ND": "Report Confidence: Not Defined"}
	'''
	
