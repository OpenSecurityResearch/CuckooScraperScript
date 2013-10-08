#CuckooScraperScript
#by Sk3tchymoos3

import os
import json
import jinja2
import argparse

parser = argparse.ArgumentParser(description='Reiterates through your Cuckoo Analyses and returns the Yara hits, VT hits, and links to the HTML report')
parser.add_argument('-p', '--path', help="Path you your cuckoo analyses folder", required=True)
parser.add_argument('-t', '--template', help="Path to your template", required=True)
parser.add_argument('-o', '--output', help="Path you want to save the output to", required=True)

args= vars(parser.parse_args())

pathToFolder=args['path']
template=args['template']
outputFile=args['output']


#jinja stuff
templateLoader= jinja2.FileSystemLoader( searchpath="/")
templateEnv = jinja2.Environment( loader=templateLoader)
TEMPLATE_FILE=template
template= templateEnv.get_template(TEMPLATE_FILE)

#get all the folder name in the directory
dirName= []
for stuff in os.listdir(pathToFolder):
	dirName.append(stuff)

htmlFile=open(outputFile, "w")
htmlFile.write("<HTML>")

for number in dirName:
	rootDir=pathToFolder
	path=os.path.join(rootDir,number,"reports/report.json")
	urlPath=os.path.join(rootDir,number,"reports/report.html")
	if os.path.isfile(path):
		with open(path) as data_file:
			data=json.load(data_file)
			filename=data["target"]["file"]["name"]
			yaraHits=data["target"]["file"]["yara"]
			virusTotalResponseCode=data["virustotal"]["response_code"]
			#if we have any VirusTotal hits...			
			if virusTotalResponseCode != 0:
				numPositive=data["virustotal"]["positives"]
				VTurl=data["virustotal"]["permalink"]
			#else keep the fields blank!			
			else:
				numPositive=" "
				VTurl=" "
			virusTotalVerbose=data["virustotal"]["verbose_msg"]
			url=urlPath
			templateVars = {"name":filename,"yara":yaraHits, "VTResponse":virusTotalResponseCode, "VTVerbose":virusTotalVerbose,"urlAddress":url,"VTHits":numPositive, "VTUrl": VTurl}
			outputText = template.render(templateVars)
			htmlFile.write(outputText) 
	else:
		print "File ", path, " does not exist!"
		pass

htmlFile.write("</HTML>")
htmlFile.close()

