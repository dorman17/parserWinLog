import mmap
import argparse
from xml.dom import minidom
from datetime import datetime
from Evtx.Evtx import FileHeader
import Evtx.Views
# import xml.dom.minidom as xml
import os
import sys
import xml.etree.ElementTree as xee
import csv
import hashlib


def parser_to_csv(path, nfile):
    # mapping EventID con relativo nome
    # per aggiungere ulteriori eventi modificare questo map e il relativo if
    global file_comp
    event_log_dict = {
        "4624": "Logon",
        "4634": "Logoff",
        "4625": "Wrong Credential",
        "4672": "Special Logon",
        "5379": "Credential Manager",
        "1101": "Audit events have been dropped by the transport",
        "1102": "The audit log was cleared",
        "4616": "The system time was changed",
        "4670": "Permissions on an object were changed",
        "4726": "A user account was deleted",
        "4950": "A Windows Firewall setting has changed",
        "5025": "The Windows Firewall has been shut down",
        "6006": "Correct Shutdown",
        "6008": "Unexpected Shutdown",
        "6005": "Power On"
    }

    tree = xee.parse(path)
    root = tree.getroot()

    # apertura file
    pathname = os.path.dirname(sys.argv[0])
    pt = os.path.abspath(pathname)
    new_pt = pt + "/" + "Log_" + nfile + ".csv"
    csv_file = open(new_pt, 'w')

    # create the csv writer object
    csv_writer = csv.writer(csv_file, lineterminator="\n")
    csv_head = []
    count_System = 0
    count = False
    for member in root.findall('Event'):
        for member1 in member.findall('System'):
            # gestisco formato riga
            row = []
            if not count:
                event_id = member1.find('EventID').tag
                csv_head.append(event_id)
                chn = member1.find('Channel').tag
                csv_head.append(chn)
                time = member1.find('TimeCreated').tag
                csv_head.append(time)
                if nfile == "Security":
                    csv_head.append('Username')
                    csv_head.append('Target Username')
                csv_writer.writerow(csv_head)
                count = True
            if member1.find('EventID').text in event_log_dict.keys():
                count_System = count_System + 1
                try:
                    event_id_text = event_log_dict.get(member1.find('EventID').text)
                    row.append(event_id_text)
                    chn_text = member1.find('Channel').text
                    row.append(chn_text)
                    time_text = member1.find('TimeCreated').attrib["SystemTime"]
                    row.append(time_text)
                    for member_data in member.findall('UserData'):
                        for member_log in member_data.findall('LogFileCleared'):
                            user_text = member_log.find('SubjectUserName').text
                            row.append(user_text)
                    if nfile == "Security":
                        for member2 in member.findall('EventData'):
                            for member3 in member2.findall('Data'):
                                if member3.attrib['Name'] == "SubjectUserName":
                                    user_text = member3.text
                                    row.append(user_text)
                                if member3.attrib['Name'] == "TargetUserName":
                                    user_target_text = member3.text
                                    row.append(user_target_text)

                    csv_writer.writerow(row)
                except AttributeError:
                    if row[0] is None:
                    file_comp = open("xml_corrupt.log", "w")
                    file_comp.write("EvtxCorupt")
                    file_comp.close()
                    print("Evtx compromesso mancato tag")
    csv_file.close()


def main():
    parser = argparse.ArgumentParser(prog="evtIdDumper", description="Specify eventID to dump")
    parser.add_argument("-f", "--iFile", dest="ifile", type=str, required=True, help="path to the input file")
    parser.add_argument("-o", "--oFile", dest="ofile", type=str, required=True, help="path to the output file")
    parser.add_argument("-n", "--nFile", dest="nfile", type=str, required=True, help="path to the output file")

    args = parser.parse_args()
    dateTimeObj = datetime.now()
    timestampStr = dateTimeObj.strftime("%Y%m%d_%H%M%S")
    outputFilename = args.nfile + "_" + timestampStr + ".xml"
    #pathFileOut = args.ofile + "/" + outputFilename
    outFile = open(args.ofile + "/" + outputFilename, 'a+')

    # doc = xml.Document()
    # declaration = doc.toxml()

    with open(args.ifile, 'r') as f:
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        fh = FileHeader(buf, 0x00)
        hOut = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?><Events>"
        if outFile:
            print(hOut)
            outFile.write(hOut)
        else:
            print hOut

        for strxml, record in Evtx.Views.evtx_file_xml_view(fh):
            xmlDoc = minidom.parseString(strxml.replace("\n", ""))

            for node in xmlDoc.childNodes:
                if node.attributes:
                    for key in node.attributes.keys():
                        node.removeAttribute(key)

            for p in xmlDoc.getElementsByTagName("LogFileCleared"):
                if p.attributes:
                    for key in p.attributes.keys():
                        p.removeAttribute(key)

            for p in xmlDoc.getElementsByTagName("UMDFDeviceInstallEnd"):
                if p.attributes:
                    for key in p.attributes.keys():
                        p.removeAttribute(key)

            for p in xmlDoc.getElementsByTagName("InstallDeviceID"):
                if p.attributes:
                    for key in p.attributes.keys():
                        p.removeAttribute(key)

            for p in xmlDoc.getElementsByTagName("AddServiceID"):
                if p.attributes:
                    for key in p.attributes.keys():
                        p.removeAttribute(key)

            for p in xmlDoc.getElementsByTagName("UMDFServiceInstall"):
                if p.attributes:
                    for key in p.attributes.keys():
                        p.removeAttribute(key)

            for p in xmlDoc.getElementsByTagName("UMDFDeviceInstallBegin"):
                if p.attributes:
                    for key in p.attributes.keys():
                        p.removeAttribute(key)

            evtId = xmlDoc.getElementsByTagName("EventID")[0].childNodes[0].nodeValue
            # outFile.write(xmlDoc.toprettyxml()[len(declaration):])
            outFile.write(xmlDoc.toprettyxml()[23:].encode("utf-8"))
            print(xmlDoc.toprettyxml())
            '''
            if args.id == 'all':
                if outFile:
                    outFile.write(xmlDoc.toprettyxml())
                else:
                    print xmlDoc.toprettyxml()
            else:
                if evtId == args.evtId:
                    if outFile:
                        outFile.write(xmlDoc.toprettyxml)
                    else:
                        print xmlDoc.toprettyxml()
            '''
        buf.close()
        endTag = "</Events>"
        if outFile:
            outFile.write(endTag)
            print(endTag)
        else:
            print endTag
        outFile.close()
    print("-----------------------------------------------------")
    print("CONVERSIONE IN FORMATO XML COMPLETATO CORRETTAMENTE!")
    print("-----------------------------------------------------")

    # print(pathFileOut)
    # prendo il nome del percorso
    pathname = os.path.dirname(sys.argv[0])
    # prendo il
    pt = os.path.abspath(pathname)
    full_pt = pt + "/" + outputFilename
    print("Generazione file csv in corso...")
    parser_to_csv(full_pt, args.nfile)
    hasher = hashlib.sha1()
    hasher256 = hashlib.sha256()
    with open(pt + "//" + args.nfile + ".evtx", 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
        hasher256.update(buf)
        sha1 = hasher.hexdigest()
        sha256 = hasher256.hexdigest()
    hash_file = open(pt + "//" + args.nfile + "_hash.txt", 'w+')
    hash_file.write("HASH SHA1: " + sha1 + "\nHASH SHA256: " + sha256)
    hash_file.close()

    hasher_file = hashlib.sha1()
    hasher256_file = hashlib.sha256()
    new_pt = pt + "/" + "Log_" + args.nfile + ".csv"
    with open(new_pt, 'rb') as afile:
        buf_file = afile.read()
        hasher_file.update(buf_file)
        hasher256_file.update(buf_file)
        sha1_file = hasher_file.hexdigest()
        sha256_file = hasher256_file.hexdigest()
    hash_file_csv = open(new_pt + "_hash.txt", 'w+')
    hash_file_csv.write("HASH SHA1: " + sha1_file + "\nHASH SHA256: " + sha256_file)
    hash_file_csv.close()

    print("-----------------------------------------------------")
    print("PROCESSO COMPLETATO CON SUCCESSO!")
    print("-----------------------------------------------------")


if __name__ == '__main__':
    main()
