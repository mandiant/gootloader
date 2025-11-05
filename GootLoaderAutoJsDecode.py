#!/usr/bin/env python
# filename          : GootLoaderAutoJsDecode.py
# description       : GootLoader automatic static JS decoder
# author            : @andy2002a - Andy Morales
# author            : @g0vandS - Govand Sinjari
# date              : 2023-01-13
# updated           : 2025-11-05
# version           : 3.8.1
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
        
        splitItem = re.sub(r'[;\s\(\)]', '',concatItem).split('=')

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
    fileExtensionPattern = re.compile('''["']([a-zA-Z0-9_\-\s]+\.''' + fileExtension + ''')["']''')  ## Find: "Example Engineering.log"
    regexMatch = fileExtensionPattern.search(stringToSearch)
    if (regexMatch):
        dataFound = regexMatch.group(1)
    else:
        dataFound = 'NOT FOUND'
    return dataFound


def getGootVersion(topFileData):
    goot3linesRegex = """GOOT3"""
    goot3linesPattern = re.compile(goot3linesRegex, re.MULTILINE)
    
    gloader3sample = False
    gloader21sample = False
    
    if re.search(r'jQuery JavaScript Library v\d{1,}\.\d{1,}\.\d{1,}$',topFileData):
        print('\nGootLoader Obfuscation Variant 2.0 detected')
        gloader21sample = False
    elif goot3linesPattern.match(topFileData):
        print('\nGootLoader Obfuscation Variant 3.0 detected\n\nIf this fails try using CyberChef "JavaScript Beautify" against the file first.')
        gloader3sample = True
        # 3 and 2 have some overlap so enabling both flags for simplicity
        gloader21sample = True
    else:
        print('\nGootLoader Obfuscation Variant 2.1 or higher detected')
        gloader21sample = True
    
    return gloader21sample, gloader3sample


def separateFileAndTaskString(regexPattern, delimiter, inputString):
    # searches and returns text that has been joined together with a delimiter
    splitTextPattern= re.compile(regexPattern)

    splitTextResult = splitTextPattern.search(inputString)

    if splitTextResult:
        splitTextArray = splitTextResult.group(1).split(delimiter)
        return splitTextArray
    else:
        return None


def getFileandTaskData(inputString):
    # Check to see if the code has been reversed, and reverse it back to normal if so
    if 'noitcnuf' in inputString:
        inputString = inputString[::-1]
    
    # New samples like b20162ee69b06184d87dc2f5665f5c80 have added another character replacement 
    charReplacementRegex = re.compile(r'''\.replace\(\/(.)\/g,\s?['"](.)['"]\)''') # Find: .replace(/!/g, 'e')

    charReplacementResult = charReplacementRegex.search(inputString)

    # Replace the chars in the input strings with those from the regex result
    if charReplacementResult:
        inputString = inputString.replace(charReplacementResult.group(1), charReplacementResult.group(2))

    # Find the string that has been joined together with a delimiter (usually by |)
    # some new samples are using @ as a separator rather than | : MD5: d5e60e0941ebcef5436406a7ecf1d0f1
    regexPatternAndDelimiter = [
        [r'''(?<=\=)\s?"((?:.{3,30}?\|.{3,30}){5,})";''',"|"], # Find: "text|text2|text3";
        [r'''(?<=\=)\s?"((?:.{3,30}?\@.{3,30}){5,})";''',"@"]  # Find: "text@text2@text3";
        ]

    for patternDelim in regexPatternAndDelimiter:
        separationResult = separateFileAndTaskString(patternDelim[0], patternDelim[1], inputString)

        if separationResult:
            splitTextArray = separationResult
            #exit the loop if we get a hit
            break

        if patternDelim == regexPatternAndDelimiter[-1]:
            # hit the last delimiter without getting a hit.
            logger.debug("Reached the last FileAndTaskData delimiter without getting a hit.")
            return None

    # un-rotate the strings
    fixedStrings = []
    for i in range(len(splitTextArray)):
        fixedStrings.append(rotateSplitText(splitTextArray[i], i))
    
    # Find the file names in the array
    for fixedString in fixedStrings:
        if fixedString.endswith(('.log', '.dat', '.txt', '.xml')):
            s2FirstFileName = fixedString
        elif fixedString.endswith('.js'):
            s2JsFileName = fixedString
    
    #In some instances the .log/.js file was outside of the "|" separated string. Try to find it outside
    if 's2FirstFileName' not in locals():
        s2FirstFileName = findFileInStr('(?:log|dat)', inputString)
    if 's2JsFileName' not in locals():
        s2JsFileName = findFileInStr('js', inputString)
    
    # Find the offset of the scheduled task name
    taskCreationRegexPattern = re.compile(
        '''\((\w+),\s?(\w+),\s?6,\s['"]{2}\s?,\s?['"]{2}\s?,\s?3\s?\)'''  # Find: (str1, str2, 6, "" , "" , 3)
    )

    taskCreationResult = taskCreationRegexPattern.search(inputString)

    # Newer variants use an LNK file
    lnkPersistancePattern = re.compile(
      r'''\(\w+,\s?\w+\s?\+\s?['"]\\\\['"]\s?\+\s?(\w+)\s?\+\s?\w\(\d{1,3}\)\)''' # Find (BBBB, CCCC + '\\' + AAAAAA + f(40))  ## Where AAAAAAA is the variable we want
    )

    lnkPersistanceResult = lnkPersistancePattern.search(inputString)

    persistenceVariableName = ''
    persistenceType = 'N/A'

    if taskCreationResult:
      persistenceVariableName = taskCreationResult.group(1)
      persistenceType = 'Scheduled Task'
    elif lnkPersistanceResult:
      persistenceVariableName = lnkPersistanceResult.group(1)
      persistenceType = 'LNK File'

    if persistenceVariableName:
      persistenceOffsetPattern = re.compile(
          '''\}''' + persistenceVariableName + '''\s?=\s\w{1,2}\((\d{1,3})\);'''  # Find: }str1 = Z(41);
      )

      persistenceOffsetMatch = persistenceOffsetPattern.search(inputString)

      if persistenceOffsetMatch:
        persistenceOffset = int(persistenceOffsetMatch.group(1))
        persistenceItemName = fixedStrings[persistenceOffset]
        if lnkPersistanceResult:
          persistenceItemName += '.lnk'
      else:
        # MD5 9565187442f857bd47c8ab0859009752 had the task name in plain text
        persistenceStrPattern = re.compile(
            '''\}''' + persistenceVariableName + '''\s?=\s"(.{10,232})";'''  # Find: }str1 = "Task Name";
        )
        persistenceStrMatch = persistenceStrPattern.search(inputString)
        if persistenceStrMatch:
          persistenceItemName = persistenceStrMatch.group(1)
        else:
          persistenceItemName = 'NOT FOUND'
          persistenceType = 'N/A'
    else:
      persistenceItemName = 'NOT FOUND'
      persistenceType = 'N/A'

    Stage2Data = 'File and Persistence data:\n'
    
    FilePersistenceFileName = 'FileAndPersistenceData.txt'
    
    Stage2Data += '\nFirst File Name:         ' + s2FirstFileName
    Stage2Data += '\nJS File Name:            ' + s2JsFileName
    Stage2Data += '\nPersistance Item Name:   ' + persistenceItemName
    Stage2Data += '\nPersistance Type:        ' + persistenceType
    
    with open(FilePersistenceFileName, mode="w") as file:
        file.write(Stage2Data)
    
    Stage2Data += '\n\nData Saved to: ' + FilePersistenceFileName
    
    print('\n'+Stage2Data+'\n')


def invokeStage2Decode(inputString, inputVarsDict):
    # Get all the relevant variables from the sample
    v3workFuncVarsPattern = re.compile(
        '''(?:\((?:[a-zA-Z0-9_]{1,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{1,}\s{0,}\))'''  # Find: (var1+var2+var3)
    )
    v3WorkFuncVars = v3workFuncVarsPattern.search(inputString)[0]

    stage2JavaScript=workFunc(convertConcatToString(v3WorkFuncVars,inputVarsDict,True))

    #Get all the string variables on their own line
    strVarPattern = re.compile(
        r'''([a-zA-Z0-9_]{1,}\s{0,}=(["'])((?:\\\2|(?:(?!\2)).)*)(\2);)(?=([a-zA-Z0-9_]{1,}\s{0,}=)|function)'''  # Find: var='xxxxx';[var2=|function]
    )
    strVarsNewLine = re.sub(strVarPattern, r'\n\1\n', stage2JavaScript)

    # Get all the var concat on their own line
    strConcPattern = re.compile(
        '''([a-zA-Z0-9_]{1,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{1,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{1,}\s{0,};)'''  # Find: var1 = var2+var3
    )
    strConcatNewLine = re.sub(strConcPattern, r'\n\1\n', strVarsNewLine)

    # Attempt to find the last variable and add a tab in front of it. This search is imperfect since the line could be shorter than what this regex picks up.
    finalStrConcPattern = re.compile(
        '''([a-zA-Z0-9_]{1,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{1,}\s{0,}\+\s{0,}){5,}[a-zA-Z0-9_]{1,}\s{0,};)'''  # Find: var0 = var1+var2+var3+var4+var5+var6
    )
    finalStrConcNewLine = re.sub(finalStrConcPattern, r'\n\t\1\n', strConcatNewLine)

    # put 1:1 variables on their own lines
    strVar1to1Pattern = re.compile(
        '''((?:\n|^)[a-zA-Z0-9_]{1,}\s{0,}=\s{0,}[a-zA-Z0-9_]{1,};)'''  # Find: var = var2;
    )
    str1to1NewLine = re.sub(strVar1to1Pattern, r'\n\1\n', finalStrConcNewLine)

    # put long digits on their own lines 
    strLongDigitPattern = re.compile(
        ''';(\d{15,};)'''  # Find: ;216541846845465456465121312313221456456465;
    )

    finalRegexStr = re.sub(strLongDigitPattern, r';\n\1\n', str1to1NewLine)
    
    outputString = []

    for line in finalRegexStr.splitlines():
        # clean up the empty lines
        if line.strip():
            outputString.append(line)
    
    outputString = '\n'.join(outputString)
    
    return outputString


def findCodeMatchInRound1Result(inputStr):
    # Find code text in the result of the first decode round
    findCodeinQuotePattern = re.compile(
        r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'"
    )
    outputStr = max(findCodeinQuotePattern.findall(inputStr), key=len) #Return the longest string since that is the one that will contain the data
    return outputStr
        

def getVariableAndConcatPatterns(isGloader21Sample):
    if isGloader21Sample:
        # 2.1 sample
        # Regex Group 1 = variable name
        # Regex Group 2 = string
        varPattern = re.compile(
            """(?:^([a-zA-Z0-9_]{1,})\s{0,}=\s{0,}'(.*)'\s{0,};)|"""  # Find: var='str';
            """(?:^([a-zA-Z0-9_]{1,})\s{0,}=\s{0,}"(.*)"\s{0,};)|"""  # Find: var = "str";
            """(?:^([a-zA-Z0-9_]{1,})\s{0,}=\s{0,}(\d{1,});)"""  # Find: var = 1234;
            , re.MULTILINE
        )
        
        concPattern = re.compile(
            """(?:^[a-zA-Z0-9_]{1,}\s{0,}=\s{0,}(?:\(?[a-zA-Z0-9_]{1,}\)?\s{0,}(?:\+|\-)\s{0,}){1,}\(?[a-zA-Z0-9_]{1,}\)?\s{0,};)|"""  # Find: var1 = var2+var3+(var4);
            """(?:^[a-zA-Z0-9_]{1,}\s{0,}=\s{0,}[a-zA-Z0-9_]{1,}\s{0,};)"""  # Find: var1 = var2;
            , re.MULTILINE
        )
    else:
        # pre-2.1 sample
        # Find the obfuscated code line
        varPattern = re.compile(
            """(?:([a-zA-Z0-9_]{1,})\s{0,}=\s{0,}'(.+?)'\s{0,};)|"""  # Find: var = 'str';
            """(?:([a-zA-Z0-9_]{1,})\s{0,}=\s{0,}"(.+?)"\s{0,};)"""  # Find: var = "str";
            , re.MULTILINE
        )
        
        concPattern = re.compile(
            """(?:[a-zA-Z0-9_]{1,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{1,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{1,}\s{0,};)|"""  # Find: var1 = var2+var3+var4;
            """(?:[a-zA-Z0-9_]{1,}\s{0,}=\s{0,}[a-zA-Z0-9_]{1,}\s{0,};)"""  # Find: var1 = var2;
            , re.MULTILINE
        )
    
    return varPattern, concPattern


def getDataToDecode(isGloader21Sample, inputData):
    if isGloader21Sample:
        outputData = inputData
    else:
        findObfuscatedPattern = re.compile(
            '''((?<=\t)|(?<=\;))(.{800,})(\n.*\=.*\+.*)*'''
        )
        outputData = findObfuscatedPattern.search(inputData)[0].replace("\n", " ").replace("\r", " ")
    return outputData


def parseRound2Data(round2InputStr, round1InputStr, variablesDict, isGootloader3sample):
    if round2InputStr.startswith('function'):
        print('GootLoader Obfuscation Variant 3.0 sample detected.')
        
        # File Names and scheduled task
        try:
            getFileandTaskData(decodeString(round1InputStr.encode('raw_unicode_escape').decode('unicode_escape')))
        except:
            print('Unable to parse Scheduled Task and Second Stage File Names')

        global goot3detected
        goot3detected = True

        outputCode = 'GOOT3\n' + invokeStage2Decode(round2InputStr, variablesDict)
        
        outputFileName = 'GootLoader3Stage2.js_'
        
        print('\nScript output Saved to: %s\n' % outputFileName)
        print('\nThe script will new attempt to deobfuscate the %s file.' % outputFileName)
    else:
        if isGootloader3sample:
            outputCode = round2InputStr.replace("'+'",'').replace("')+('",'').replace("+()+",'').replace("?+?",'')

            # new samples have added this character replacement, might be worth doing this programmatically in the future
            outputCode = outputCode.replace('~+~','') 
            
            # Check to see if the code has been reversed, and reverse it back to normal if so
            # Sample MD5: 2e6e43e846c5de3ecafdc5f416b72897
            if 'sptth' in outputCode:
                outputCode = outputCode[::-1]
            
            v3DomainRegex = re.compile(
                '''(?:(?:https?):\/\/)[^\[|^\]|^\/|^\\|\s]*\.[^'"]+'''
            )
            
            maliciousDomains = re.findall(v3DomainRegex, outputCode)
        else:
            outputCode = round2InputStr
            
            v2DomainRegex = re.compile(
                r'(.*)(\[\".*?\"\])(.*)'
            )
            domainsMatch = v2DomainRegex.search(round2InputStr)[2]
            maliciousDomains = domainsMatch.replace("[","").replace("]","").replace("\"","").replace("+(","").replace(")+","").split(',')
        
        outputFileName = 'DecodedJsPayload.js_'
        
        # Print to screen
        print('\nScript output Saved to: %s\n' % outputFileName)
        
        outputDomains = ''
        
        for dom in maliciousDomains:
            outputDomains += defang(dom) + '\n'
        
        print('\nMalicious Domains: \n\n%s' % outputDomains)
    return outputCode, outputFileName

def gootDecode(path):
    # Open File
    with open(path, mode="r", encoding="utf-8") as file:
        # Check for the GootLoader obfuscation variant
        fileTopLines = ''.join(file.readlines(5))
        
        gootloader21sample, gootloader3sample = getGootVersion(fileTopLines)
        
        # reset cursor to read again
        file.seek(0)
        fileData = file.read()
    
    # Extract the relevant data that will be decoded
    dataToDecode = getDataToDecode(gootloader21sample, fileData)
    
    # Get the regex patterns that will be used to find variables and concat lines
    variablesPattern, concatPattern = getVariableAndConcatPatterns(gootloader21sample)
    
    # Find all the variables
    variablesAllmatches = variablesPattern.findall(dataToDecode)
    
    VarsDict = ConvertVarsToDict(variablesAllmatches)
    
    # Find all the concat functions
    concatAllmatches = concatPattern.findall(dataToDecode)
    
    if gootloader21sample:
        # Some variants have the final variable in the middle of the code. Search for it separately so that it shows up last.
        lastConcatPattern = re.compile(
            # This is split into 2 regex because the lookbehind must be a fixed length
            """(?:(?<=\t)\s*\w+\s*=\s*\(?\w+(?:\s?\+\s?\w+)+\)?;)|"""       # Find: [tab]var1 = var2+var3+var4+var5+var6+var7;
            """(?:(?<=\)\{)\s*\w+\s*=\s*\(?\w+(?:\s?\+\s?\w+)+\)?;)"""      # Find: ){var1 = var2+var3+var4+var5+var6+var7;
                                                                            # Find: ){var1 = (var2+var3+var4+var5+var6+var7);
            , re.MULTILINE
        )
        
        concatAllmatches += list(sorted(lastConcatPattern.findall(fileData), key = len))
    
    Obfuscated1Text = convertConcatToString(concatAllmatches,VarsDict)
    
    # run the decoder
    round1Result = decodeString(Obfuscated1Text)
    
    # Find code text in the result of the first decode round
    CodeMatch = findCodeMatchInRound1Result(round1Result)
    
    # run the decode function against the previous result 
    round2Result = decodeString(CodeMatch.encode('raw_unicode_escape').decode('unicode_escape'))

    round2Code, round2FileName = parseRound2Data(round2Result, round1Result, VarsDict, gootloader3sample)
    
    # Write output file 
    with open(round2FileName, mode="w") as file:
        file.write(round2Code)

gootDecode(args.jsFilePath)

if goot3detected:
    gootDecode('GootLoader3Stage2.js_')
