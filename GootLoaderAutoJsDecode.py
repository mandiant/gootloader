#!/usr/bin/env python
# filename          : GootLoaderAutoJsDecode.py
# description       : GootLoader automatic static JS decoder
# author            : @andy2002a - Andy Morales
# author            : @g0vandS - Govand Sinjari
# date              : 2023-01-13
# updated           : 2023-09-11
# version           : 3.5
# usage             : python GootLoaderAutoJsDecode.py malicious.js
# output            : DecodedJsPayload.js_ and GootLoader3Stage2.js_
# py version        : 3
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
args = parser.parse_args()

goot3detected = False


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

def ConvertVarsToDict(inArray):
    # Converts variables to a dict
    # Adds the first 2 items only since the rest is not part of the match
    varDict = {}
    
    def removeEmptyTuples(tuples):
        tuples = [t for t in tuples if t]
        if len(tuples) == 1:
            # the var was probably an empty string and the function wiped it out. Add an empty string back.
            tuples += ['']
        return tuples
    
    for arItem in inArray:
        varDict.update({arItem[0]:arItem[1]})
    return varDict

def convertConcatToString(inputConcatMatches,inputVarsDict,noEquals=False):
    # Joins multiple concat operations into a string
    
    # V3 matches do not have an equal sign so add some dummy text 
    if noEquals:
        dummyEquals = 'dummy='+inputConcatMatches.replace('(','').replace(')','')
        inputConcatMatches = [dummyEquals]
    
    for index, concatItem in enumerate(inputConcatMatches):
        # Remove any unwanted characters and split on '=' 
        splitItem = concatItem.replace(';','').replace(' ','').replace('\t','').split('=')
        
        currentLineString = ''
        
        for additionItem in splitItem[1].split('+'):
            try:
                # look up the items in the dict and join them together
                currentLineString += inputVarsDict[additionItem]
            except:
                # probably a junk match
                continue
            
        if index != len(inputConcatMatches) - 1:
            # add the items back into the dict so that they can be referenced later in the loop
            inputVarsDict.update({splitItem[0]:currentLineString})
        else:
            # This is the last item in the list
            # return the full encoded line fixing escaped chars
            return currentLineString.encode('raw_unicode_escape').decode('unicode_escape')

def decodeString(scripttext):
    # Gootloader decode function
    ans = ""
    for i in range(0, len(scripttext)):
        if i % 2 == 1:
            ans += scripttext[i]
        else:
            ans = scripttext[i] + ans
    return ans

def rotateSplitText (string,count):
    for i in range(count+1):
        string = string[1:]+string[0]
    return str(string)

# V3 Decoding scripts converted from their JS versions
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
    outputStr = ''
    for i in range(len(inputStr)):
        var1 = rtrSub(inputStr,i)
        outputStr = remainder(outputStr,var1,i)
    return outputStr

def findFileInStr(fileExtension, stringToSearch):
    fileExtensionPattern = re.compile('''["']([a-zA-Z0-9_\-\s]+\.''' + fileExtension + ''')["']''') ## Find: "Example Engineering.log"
    regexMatch = fileExtensionPattern.search(stringToSearch)
    if (regexMatch):
        dataFound = regexMatch.group(1)
    else:
        dataFound = 'NOT FOUND'
    return dataFound

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
        print('\nGootLoader Obfuscation Variant 3.0 detected\n\nIf this fails try using CyberChef "JavaScript Beautify" against the %s file first.' % path)
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
        # 2.1 sample
        dataToDecode = fileData
        
        # Regex Group 1 = variable name
        # Regex Group 2 = string
        variables21Regex = ("""(?:^([a-zA-Z0-9_]{2,})\s{0,}=\s{0,}'(.*)'\s{0,};)|""" # Find: var='str';
        """(?:^([a-zA-Z0-9_]{2,})\s{0,}=\s{0,}"(.*)"\s{0,};)|""" # Find: var = "str";
        """(?:^([a-zA-Z0-9_]{2,})\s{0,}=\s{0,}(\d{1,});)""") # Find: var = 1234;
        variablesPattern = re.compile(variables21Regex, re.MULTILINE)
        
        concat21Regex = ("""(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,};)|""" # Find: var1 = var2+var3+var4;
        """(?:^[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z0-9_]{2,}\s{0,};)""") # Find: var1 = var2;
        concatPattern = re.compile(concat21Regex, re.MULTILINE)
    else:
        # pre-2.1 sample
        
        # Find the obfuscated code line
        findObfuscatedPattern = re.compile('''((?<=\t)|(?<=\;))(.{800,})(\n.*\=.*\+.*)*''')
        dataToDecode = findObfuscatedPattern.search(fileData)[0].replace("\n", " ").replace("\r", " ")
        
        variables2Regex = ("""(?:([a-zA-Z0-9_]{2,})\s{0,}=\s{0,}'(.+?)'\s{0,};)|""" # Find: var = 'str';
        """(?:([a-zA-Z0-9_]{2,})\s{0,}=\s{0,}"(.+?)"\s{0,};)""") # Find: var = "str";
        variablesPattern = re.compile(variables2Regex, re.MULTILINE)
        
        concat2Regex = ("""(?:[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,};)|""" # Find: var1 = var2+var3+var4;
        """(?:[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z0-9_]{2,}\s{0,};)""") # Find: var1 = var2;
        concatPattern = re.compile(concat2Regex, re.MULTILINE)
    
    # Find all the variables
    variablesAllmatches = variablesPattern.findall(dataToDecode)
    
    VarsDict = ConvertVarsToDict(variablesAllmatches)
    
    # Find all the concat functions
    concatAllmatches = concatPattern.findall(dataToDecode)
    
    if gootloader21sample:
        # Some variants have the final variable in the middle of the code. Search for it separately so that it shows up last.
        lastConcat21Regex = ("""(?:^\t[a-zA-Z0-9_]{2,}\s{0,}=(?:\s{0,}[a-zA-Z0-9_]{2,}\s{0,}\+?\s{0,}){5,}\s{0,};)""") # Find: [tab]var1 = var2+var3+var4+var5+var6+var7;
        lastConcatPattern = re.compile(lastConcat21Regex, re.MULTILINE)
        
        concatAllmatches += list(sorted(lastConcatPattern.findall(fileData), key = len))
    
    Obfuscated1Text = convertConcatToString(concatAllmatches,VarsDict)
    
    file.close()
    
    # run the decoder
    round1Result = decodeString(Obfuscated1Text)
    
    # Find code text in the result of the first decode round
    findCodeinQuotePattern = re.compile(r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'")
    
    CodeMatch = findCodeinQuotePattern.findall(round1Result)[0]
    
    # run the decode function against the previous result 
    round2Result = decodeString(CodeMatch.encode('raw_unicode_escape').decode('unicode_escape'))
    
    if round2Result.startswith('function'):
        
        print('GootLoader Obfuscation Variant 3.0 sample detected.')
        
        ####################################################################################
        
        # File Names and scheduled task
        fullCode = decodeString(round1Result.encode('raw_unicode_escape').decode('unicode_escape'))
        
        # Check to see if the code has been reversed, and reverse it back to normal if so
        if 'noitcnuf' in fullCode:
            fullCode = fullCode[::-1]
        
        # Find the '|' separated string 
        splitTextPattern= re.compile('''"((?:.{3,30}?\|.{3,30}){5,})";''') # Find: "text|text2|text3";
        splitTextArray = splitTextPattern.search(fullCode).group(1).split('|')
        
        # un-rotate the strings
        fixedStrings = []
        for i in range(len(splitTextArray)):
            fixedStrings.append(rotateSplitText(splitTextArray[i], i))
        
        # Find the file names in the array
        for str in fixedStrings:
            if str.endswith('.log'):
                s2LogFileName = str
            elif str.endswith('.js'):
                s2JsFileName = str
        
        #In some instances the .log/.js file was outside of the "|" separated string. Try to find it outside
        if 's2LogFileName' not in locals():
            s2LogFileName = findFileInStr('log', fullCode)
        if 's2JsFileName' not in locals():
            s2JsFileName = findFileInStr('js', fullCode)
        
        # Find the offset of the scheduled task name
        taskCreationRegexPattern = re.compile('''\((\w+),\s?(\w+),\s?6,\s['"]{2}\s?,\s?['"]{2}\s?,\s?3\s?\)''') # Find: (str1, str2, 6, "" , "" , 3)
        taskCreationVarname = taskCreationRegexPattern.search(fullCode).group(1)
        taskNameOffsetPattern = re.compile('''\}''' + taskCreationVarname + '''\s?=\s\w{1,2}\((\d{1,3})\);''') # Find: }str1 = Z(41);
        
        taskNameOffsetMatch = taskNameOffsetPattern.search(fullCode)
        
        if taskNameOffsetMatch:
            taskNameOffset = int(taskNameOffsetMatch.group(1))
            scheduledTaskName = fixedStrings[taskNameOffset]
        else:
            # MD5 9565187442f857bd47c8ab0859009752 had the task name in plain text
            taskNameStrPattern = re.compile('''\}''' + taskCreationVarname + '''\s?=\s"(.{10,232})";''') # Find: }str1 = "Task Name";
            taskNameStrMatch = taskNameStrPattern.search(fullCode)
            if taskNameStrMatch:
                scheduledTaskName = taskNameStrMatch.group(1)
            else:
                scheduledTaskName = 'NOT FOUND'
        
        Stage2Data = '\nFile and Scheduled task data:\n'
        
        FileTaskFileName = 'FileAndTaskData.txt'
        
        Stage2Data += '\nLog File Name:       ' + s2LogFileName
        Stage2Data += '\nJS File Name:        ' + s2JsFileName
        Stage2Data += '\nScheduled Task Name: ' + scheduledTaskName
        Stage2Data += '\n\nData Saved to: ' + FileTaskFileName + '\n'
        
        outFile = open(FileTaskFileName, "w")
        outFile.write(Stage2Data)
        outFile.close()
        
        print(Stage2Data)
        ####################################################################################
        
        global goot3detected
        goot3detected = True
        
        # Get all the relevant variables from the sample
        v3workFuncVarsPattern = re.compile('''(?:\((?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,}\))''') # Find: (var1+var2+var3)
        v3WorkFuncVars = v3workFuncVarsPattern.search(round2Result)[0]
        
        stage2JavaScript=workFunc(convertConcatToString(v3WorkFuncVars,VarsDict,True))
        
        #Get all the string variables on their own line
        strVarPattern = re.compile(r'''([a-zA-Z0-9_]{2,}\s{0,}=(["'])((?:\\\2|(?:(?!\2)).)*)(\2);)(?=([a-zA-Z0-9_]{2,}\s{0,}=)|function)''') # Find: var='xxxxx';[var2=|function]
        strVarsNewLine = re.sub(strVarPattern, r'\n\1\n', stage2JavaScript)
        
        # Get all the var concat on their own line
        strConcPattern = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,};)''') # Find: var1 = var2+var3
        strConcatNewLine = re.sub(strConcPattern, r'\n\1\n', strVarsNewLine)
        
        # Attempt to find the last variable and add a tab in front of it. This search is imperfect since the line could be shorter than what this regex picks up.
        finalStrConcPattern = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){5,}[a-zA-Z0-9_]{2,}\s{0,};)''') # Find: var0 = var1+var2+var3+var4+var5+var6
        finalStrConcNewLine = re.sub(finalStrConcPattern, r'\n\t\1\n', strConcatNewLine)
        
        # put 1:1 variables on their own lines
        strVar1to1Pattern = re.compile('''((?:\n|^)[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z0-9_]{2,};)''')# Find: var = var2;
        str1to1NewLine = re.sub(strVar1to1Pattern, r'\n\1\n', finalStrConcNewLine)
        
        # put long digits on their own lines 
        strLongDigitPattern = re.compile(''';(\d{15,};)''') # Find: ;216541846845465456465121312313221456456465;
        finalRegexStr = re.sub(strLongDigitPattern, r';\n\1\n', str1to1NewLine)
        
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
            OutputCode = round2Result.replace("'+'",'').replace("')+('",'').replace("+()+",'')
            
            # Check to see if the code has been reversed, and reverse it back to normal if so
            # Sample MD5: 2e6e43e846c5de3ecafdc5f416b72897
            if 'sptth' in OutputCode:
                OutputCode = OutputCode[::-1]
            
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

gootDecode(args.jsFilePath)

if goot3detected:
    gootDecode('GootLoader3Stage2.js_')
