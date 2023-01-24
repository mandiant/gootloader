#!/usr/bin/env python
# filename          : GootLoaderManualJsDecode-Dynamic.py
# description       : GootLoader JS decoder
# author            : @g0vandS - Govand Sinjari
# author            : @andy2002a - Andy Morales
# date              : 2021-12-01
# updated           : 2023-01-19
# version           : 2.0
# usage             : python GootLoaderManualJsDecode-Dynamic.py malicious.js
# output            : DecodedJsPayload.js_
# py version        : 3
#
# WARNING: This script executes part of the GOOTLOADER code, as a result it should only be run in an isolated environment. This script should only be used if the static version (GootLoaderAutoJsDecode.py) fails.
#
# This script will not work against V2.1 nor V3 samples.
#
# Note: To make JS files readable, you can use CyberChef JavaScript or Generic Code Beautify
#
############################
#
# Legal Notice
#
# Copyright 2023 Mandiant.  All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
#
############################

import argparse
import re

# Argument parsing
parser = argparse.ArgumentParser()
parser.add_argument('-y', '-Y', help='Ignores the warning message.', action='store_true')
args = parser.parse_args()

# Warning message
print('\nThis script executes part of the GOOTLOADER code, as a result it should only be run in an isolated environment.')

if not args.y:
    confirmationInput = input('\nContinue (Y/N)?')
    if confirmationInput.lower().strip()[0] != 'y':
        print('Exiting script')
        exit()

# PASTE ENCODED DATA BELOW



# PASTE ENCODED DATA ABOVE


# Variable name
ObfuscatedVariableMatch = '''PASTE THE VARIABLE NAME HERE'''

exec("stringToDecode = %s" % ObfuscatedVariableMatch)

def decodeString(scripttext):
    ans = ""
    for i in range(0, len(scripttext)):
        if i % 2 == 1:
            ans += scripttext[i]
        else:
            ans = scripttext[i] + ans
    return ans

# run the decoder
round1Result = decodeString(stringToDecode)

# find code text in the result of the first decode round
findCodeinQuotePattern = re.compile(r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'")

CodeMatch = findCodeinQuotePattern.search(round1Result)[0]

exec("newCodeMatchVar = %s" % CodeMatch)

# run the decode function on the previous result 
round2Result = decodeString(newCodeMatchVar)

OutputCode = round2Result
v2DomainRegex = re.compile(r'(.*)(\[\".*?\"\])(.*)')
domainsMatch = v2DomainRegex.search(round2Result)[2]
maliciousDomains = domainsMatch.replace("[","").replace("]","").replace("\"","").replace("+(","").replace(")+","").split(',')

# Write output file 
OutputFileName = 'DecodedJsPayload.js_'
outFile = open(OutputFileName, "w")
outFile.write(OutputCode)
outFile.close()

# Print to screen
print('\nOutput Saved to: %s\n' % OutputFileName)

def defang(input):
    if not input.strip():
        return input
    
    # most domains/ip/url have a dot, match anything not already in brackets ([^\[])\.([^\]])
    start = input
    end = ""
    ignoreNext = False
    for i,_ in enumerate(input):
        if ignoreNext:
            ignoreNext = False
            continue
        
        # if input has a single slash, not a double slash, split it at the first one and just escape the first half.
        # this avoids escaping the domains' URI dots, which are always after the first single slash
        if input[i] == '/':
            if (i + 1) < len(input) and input[i + 1] == '/':
                ignoreNext = True
                continue
            
            start = input[:i]
            end = input[i:]
            break
    
    result = re.compile("([^\\[])\\.([^\\]])").sub(r"\1[.]\2", start) + end
    
    # but not all! http://0x7f000001 ([^\[]):([^\]])
    #result = result.replaceAll(new RegExp("([^\\[]):([^\\]])", 'g'), "$1[:]$2");
    result = re.compile("([^\\[]):([^\\]])").sub(r"\1[:]\2", result)
    if result.lower().startswith("http"):
        result = result.replace("https", "hxxps")
        result = result.replace("http", "hxxp")
    return result

outputDomains = ''
for dom in maliciousDomains:
    outputDomains += defang(dom) + '\n'
print('\nMalicious Domains: \n\n%s' % outputDomains)
