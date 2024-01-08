#!/usr/bin/env python
# filename          : GootLoaderAutoJsDecode-Dynamic.py
# description       : Dynamic version of the GootLoader automatic JS decoder
# author            : @g0vandS - Govand Sinjari
# author            : @andy2002a - Andy Morales
# date              : 2021-12-01
# updated           : 2024-01-08
# version           : 3.7
# usage             : python GootLoaderAutoJsDecode-Dynamic malicious.js
# usage             : python GootLoaderAutoJsDecode-Dynamic malicious.js -y
# output            : DecodedJsPayload.js_ and GootLoader3Stage2.js_
# py version        : 3
#
# WARNING: This script executes part of the GOOTLOADER code, as a result it should only be run in an isolated environment. This script should only be used if the static version (GootLoaderAutoJsDecode.py) fails.
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
parser.add_argument('jsFilePath', help='Path to the GOOTLOADER JS file.')
parser.add_argument('-y', '-Y', help='Ignores the warning message.', action='store_true')
args = parser.parse_args()

# Warning message
print('\nThis script executes part of the GOOTLOADER code, as a result it should only be run in an isolated environment. This script should only be used if the static version (GootLoaderAutoJsDecode.py) fails.')

if not args.y:
    confirmationInput = input('\nContinue (Y/N)?')
    if confirmationInput.lower().strip()[0] != 'y':
        print('Exiting script')
        exit()

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

def fixInvalidVar(inputStr):
    fixVariablesPattern = re.compile('''((?:;|\+|^)\s?)(False|break|for|not|None|class|from|or|True|continue|global|pass|def|if|raise|and|del|import|return|as|elif|in|try|assert|else|is|while|async|except|lambda|with|await|finally|nonlocal|yield)(\s?(?:=|\+|;))''')
    fixedVar = re.sub(fixVariablesPattern, r'\1\2_\3', inputStr)
    return fixedVar

def decodeString(scripttext):
    ans = ""
    for i in range(0, len(scripttext)):
        if i % 2 == 1:
            ans += scripttext[i]
        else:
            ans = scripttext[i] + ans
    return ans

# Decoding scripts converted from their JS versions
def remainder(v1, v2, v3):
    # The 3 and the 1 could possibly change in the future
    if(v3 % (3-1)):
        rtn = v1+v2
    else:
        rtn = v2+v1
    return rtn

def rtrSub(inputStr, idx1): 
    # use this odd format of substring so that it matches the way JS works
    return inputStr[idx1:(idx1+1)]

def workFunc(inputStr):
    outputStr =''
    for i in range(len(inputStr)):
        var1 = rtrSub(inputStr,i)
        outputStr = remainder(outputStr,var1,i)
    return outputStr

def gootDecode(path):
    # Open File
    file = open(path, mode="r", encoding="utf-8")
    
    # Check for the GootLoader obfuscation variant
    fileTopLines = ''.join(file.readlines(5))
    
    goot3linesRegex = """GOOT3"""
    goot3linesPattern = re.compile(goot3linesRegex, re.MULTILINE)
    
    gootloader3sample = False
    
    if re.search(r'jQuery JavaScript Library v\d{1,}\.\d{1,}\.\d{1,}$',fileTopLines):
        print('\nGootLoader Obfuscation Variant 2.0 detected')
        gootloader21sample = False
    elif goot3linesPattern.match(fileTopLines):
        print('\nGootLoader Obfuscation Variant 3.0 detected\n\nIf this fails try using CyberChef "JavaScript Beautify" against the sample first.')
        gootloader3sample = True
        # 3 and 2 have some overlap so enabling both flags for simplicity
        gootloader21sample = True
    else:
        print('\nGootLoader Obfuscation Variant 2.1 or higher detected')
        gootloader21sample = True
    
    # reset cursor to read again
    file.seek(0)
    
    fileData = file.read()
    
    if gootloader21sample:
        # Sample is GootLoader Obfuscation Variant 2.1
        goot21regex = (
            """(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}'.*'\s{0,};)|(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}".*"\s{0,};)|"""  # Find: var = 'str'; and var = "str";
            """(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:\(?[a-zA-Z0-9_]{2,}\)?\s{0,}(?:\+|\-)\s{0,}){1,}\(?[a-zA-Z0-9_]{2,}\)?\s{0,};)|"""  # Find: var1 = var2+var3+(var4);
            """(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z0-9_]{2,}\s{0,};)|"""  # Find: var1 = var2;
            """(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}\d{1,};)"""  # Find: var = 1234;
        ) 
        
        # initialize regex pattern
        goot21Pattern = re.compile(goot21regex, re.MULTILINE)
        
        goot21allMatches = goot21Pattern.findall(fileData)
        
        # Some variants have the final variable in the middle of the code. Search for it separately so that it shows up last.
        goot21regexLastVar = (
            """(?:^\t[a-zA-Z0-9_]{2,}\s{0,}=(?:\s{0,}[a-zA-Z0-9_]{2,}\s{0,}\+?\s{0,}){5,}\s{0,};)"""  # Find: [tab]var1 = var2+var3+var4+var5+var6+var7;
        )
        
        goot21regexLastVarPattern = re.compile(goot21regexLastVar, re.MULTILINE) 
        
        goot21allMatches += list(sorted(goot21regexLastVarPattern.findall(fileData), key = len))
        
        # go through each line and execute the code(set variables). use try/catch to ignore errors from junk matches
        for line in goot21allMatches:
            try:
                exec(line.replace("\t", ""))
            except:
                try:
                    # If the previous command fails it might be because it's using a variable name that is invalid. Try substituting it. 
                    fixedLine = fixInvalidVar(line)
                    exec(fixedLine.replace("\t", ""))
                except:
                    # If the previous failed, then probably a junk regex match
                    pass
        
        # technically GootLoader Obfuscation Variant 2.1 doesn't need everything in one line, but it reduces code later on
        Obfuscated1Match = ''.join(goot21allMatches).replace("\n", " ").replace("\r", " ").replace("\t", "")
    else:
        # pre-2.1 sample
        # Find the obfuscated code line
        findObfuscatedPattern = re.compile('''((?<=\t)|(?<=\;))(.{800,})(\n.*\=.*\+.*)*(?=\;)''')
        
        # Make sure that the text is in a single line
        Obfuscated1Match = findObfuscatedPattern.search(fileData)[0].replace("\n", " ").replace("\r", " ")
    
    file.close()
    
    # Remove extra cmd at the end if it exists: xxxx(0000)
    findExtraCmdPattern = re.compile('''[a-zA-Z]{2,}\(\d{4}\)''')
    
    Obfuscated1Match = re.sub(findExtraCmdPattern, '', Obfuscated1Match)
    
    # find just the variable name. Remove white space.
    findVariableNamePattern = re.compile('''(?<=\;)([a-zA-Z0-9_\s-]{1,}\=[a-zA-Z0-9_\s-]{1,}\+)''')
    
    ObfuscatedVariableMatch = findVariableNamePattern.findall(Obfuscated1Match)[-1].split('=')[0].strip()
    
    if not gootloader21sample:
        # execute the string (will set variables)
        # GootLoader Obfuscation Variant 2.1 variables have already been set earlier, so they are not executed here
        try:
            exec(Obfuscated1Match)
        except:
            # If the previous command fails it might be because it's using a variable name that is invalid. Try substituting it. 
            exec(fixInvalidVar(Obfuscated1Match))
    
    exec("global stringToDecode; stringToDecode = %s" % ObfuscatedVariableMatch, globals(), locals())
    
    # run the decoder
    round1Result = decodeString(stringToDecode)
    
    # find code text in the result of the first decode round
    findCodeinQuotePattern = re.compile(r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'")
    
    CodeMatch = findCodeinQuotePattern.search(round1Result)[0]
    
    exec("global newCodeMatchVar; newCodeMatchVar = %s" % CodeMatch, globals(), locals())
    
    # run the decode function on the previous result 
    round2Result = decodeString(newCodeMatchVar)
    
    if round2Result.startswith('function'):
        print('GootLoader Obfuscation Variant 3.0 sample detected.')
        
        global goot3detected
        goot3detected = True

        # Get all the relevant variables from the sample
        v3workFuncVarsPattern = re.compile('''(?:\((?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,}\))''') # Find: (var1+var2+var3)
        v3WorkFuncVars = v3workFuncVarsPattern.search(round2Result)[0]
        
        exec("global stage2JavaScript; stage2JavaScript = workFunc(%s)" % v3WorkFuncVars, globals(), locals())
        
        #Get all the string variables on their own line
        strVarPattern = re.compile(r'''([a-zA-Z0-9_]{2,}\s{0,}=(["'])((?:\\\2|(?:(?!\2)).)*)(\2);)(?=([a-zA-Z0-9_]{2,}\s{0,}=)|function)''') # Find: var='xxxxx';[var2=|function]
        strVarsNewLine = re.sub(strVarPattern, r'\n\1\n', stage2JavaScript)
        
        # Get all the var concat on their own line
        strConcPattern = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}(?:\+|-)\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,};)''') # Find: var1 = var2+var3
        strConcatNewLine = re.sub(strConcPattern, r'\n\1\n', strVarsNewLine)
        
        # Attempt to find the last variable and add a tab in front of it. This search is imperfect since the line could be shorter than what this regex picks up.
        finalStrConcPattern = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){5,}[a-zA-Z0-9_]{2,}\s{0,};)''')
        finalStrConcNewLine = re.sub(finalStrConcPattern, r'\n\t\1\n', strConcatNewLine)
        
        # put 1:1 variables on their own lines
        strVarPattern2 = re.compile('''((?:\n|^)[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z0-9_]{2,};)''')#Find: var =var2;
        finalRegexStr = re.sub(strVarPattern2, r'\n\1\n', finalStrConcNewLine)
        
        OutputCode = 'GOOT3\n'
        
        for line in finalRegexStr.splitlines():
            # clean up the empty lines
            if line.strip():
                OutputCode += (line+'\n')
        
        OutputFileName = 'GootLoader3Stage2.js_'
        
        print('\nScript output Saved to: %s\n' % OutputFileName)
        print('\nThe script will new attempt to deobfuscate the %s file.' % OutputFileName)
    else:
        if gootloader3sample:
            OutputCode = round2Result.replace("'+'",'').replace("')+('",'').replace("+()+",'').replace("?+?",'')
            
            v3DomainRegex = re.compile('''(?:(?:https?):\/\/)[^\[|^\]|^\/|^\\|\s]*\.[^'"]+''')
            
            maliciousDomains = re.findall(v3DomainRegex, OutputCode)
        else:
            OutputCode = round2Result
            v2DomainRegex = re.compile(r'(.*)(\[\".*?\"\])(.*)')
            domainsMatch = v2DomainRegex.search(round2Result)[2]
            maliciousDomains = domainsMatch.replace("[","").replace("]","").replace("\"","").replace("+(","").replace(")+","").split(',')
        
        OutputFileName = 'DecodedJsPayload.js_'
        
        # Print to screen
        print('\nScript output Saved to: %s\n' % OutputFileName)
        
        outputDomains = ''
        
        for dom in maliciousDomains:
            outputDomains += defang(dom) + '\n'
        
        print('\nMalicious Domains: \n\n%s' % outputDomains)
    
    # Write output file 
    outFile = open(OutputFileName, "w")
    outFile.write(OutputCode)
    outFile.close()
        
goot3detected = False

gootDecode(args.jsFilePath)

# Run the decode function against the 3.0 sample if detected
if goot3detected:
    gootDecode('GootLoader3Stage2.js_')
