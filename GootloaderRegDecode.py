#!/usr/bin/env python
# filename          : GootloaderRegDecode.py
# description       : GootLoader regsitry payload decoder from a CSV file
# author            : @g0vandS , Govand Sinjari
# author            : @andy2002a, Andy Morales
# date              : 2021-10-09
# updated           : 2022-05-12
# version           : 1.1
# usage             : python GootloaderRegDecode.py stage1stage2reg.csv 
# output            : payload1.dll_ and payload2.exe
# Export the payload from registry path HKCU:Software\Microsoft\Phone\username\ and HKCU:Software\Microsoft\Phone\username0\.

#
# Below is a sample of what the CSV headers should look like along with some sample data.
#
# Reg Key Event Path: HKEY_USERS\S-1-5-21-1212115-212121848\SOFTWARE\Microsoft\Phone\JSMITH0\0
# Reg Key Event Value Name: 0
# Reg Key Event Text: 300515140003004afb0154548000086899877afd009a011a0
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

import sys
import csv
import hashlib

CsvFile = sys.argv[1]

f1 = open(CsvFile)
csvData = csv.reader(f1)
header = next(csvData)

# Find the "Value Name" or "Reg Key Event Value Name" column in the CSV
try:
    # ESPIR Export
    CsvValueNameIndex = header.index('Reg Key Event Value Name')
except:
    #Redline Export
    CsvValueNameIndex = header.index('Value Name')
    
# Find the "Reg Key Event Text" or "Text Data" column in the CSV
try:
    # ESPIR Export
    CsvTextDataIndex = header.index('Reg Key Event Text')
except:
    #Redline Export
    CsvTextDataIndex = header.index('Text Data')
    
# Find the "Reg Key Event Path" or "Path" column in the CSV
try:
    # ESPIR Export
    CsvRegPathIndex = header.index('Reg Key Event Path')
except:
    #Redline Export
    CsvRegPathIndex = header.index('Path')

# Sorting CSV rows by the value of the CsvValueNameIndex column
csvSorted = sorted(csvData, key=lambda row: int(row[CsvValueNameIndex]), reverse=False)

payload1Data = ""
payload2Data = ""

#Split the reg path and check the penultimate item for the number '0' at the end of the path.
for row in csvSorted:

    if row[CsvRegPathIndex].split('\\')[-2].endswith('0'):
        #payload 1 has a 0 at the end of the username
        payload1Data = payload1Data + row[CsvTextDataIndex]
    else:
        #payload 2 doesn't have a 0 at the end of the username
        payload2Data = payload2Data + row[CsvTextDataIndex]

f1.close()

OutputString = ''

if payload1Data:
    # replace '#' in the input data with 1000, this based on the analysis of the Powershell code that decodes the registry entries
    
    p1ReplacedText=payload1Data.replace("#","1000")

    payload1ByteArray = bytearray.fromhex(p1ReplacedText)

    OutputName = "payload1.dll_"

    f = open(OutputName, "wb")
    f.write(payload1ByteArray)
    f.close()
    
    result = hashlib.md5(payload1ByteArray)
    
    OutputString += '\nFile: ' + OutputName + '\nMD5: ' + result.hexdigest() + '\n'

if payload2Data:
    # Substitution table retreived from stage 1 payload (MD5: 35238D2A4626E7A1B89B13042F9390E9) using dnSpy.
    
    OutputName = "payload2.exe_"

    p2replacedText = payload2Data.replace("q","000").replace("v","0").replace("w","1").replace("r","2").replace("t","3").replace("y","4").replace("u","5").replace("i","6").replace("o","7").replace("p","8").replace("s","9").replace("q","A").replace("h","B").replace("j","C").replace("k","D").replace("l","E").replace("z","F")

    payload2ByteArray = bytearray.fromhex(p2replacedText)

    f = open(OutputName, "wb")
    f.write(payload2ByteArray)
    f.close()
    
    result = hashlib.md5(payload2ByteArray)
    
    OutputString += '\nFile: ' + OutputName + '\nMD5: ' + result.hexdigest() + '\n'
    
if OutputString:
    print(OutputString)

else:
    print('\nNo Payloads were decoded')
