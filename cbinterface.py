#!/data/home/carbonblack/env3/bin/python3
#/data/home/smcfeely/dev/env3/bin/python3

import os
import re
import sys
import signal
import time
import argparse
#import datetime
import shlex
import subprocess
import json
import glob
import logging
import pymysql

#from dateutil import tz
from queue import Queue
from threading import Thread
from configparser import ConfigParser

from cbapi import auth
from cbapi.response import *
from cbapi import live_response_api
from cbapi.errors import ApiError, ObjectNotFoundError, TimeoutError, MoreThanOneResultError

from classes.CBProcess import ProcessList, ProcessWrapper
from classes.CBquery import CBquery
from classes.CBglobal import eastern_time

# Not using logging.BasicConfig because it turns on the cbapi logger
LOGGER = logging.getLogger('cbinterface')
LOGGER.setLevel(logging.DEBUG)
LOGGER.propagate = False
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
handler.setLevel(logging.DEBUG)
LOGGER.addHandler(handler)

# MAX number of threads performing splunk searches
MAX_SEARCHES = 4


def clean_exit(signal, frame):
    print("\nExiting ..")
    sys.exit(0)
signal.signal(signal.SIGINT, clean_exit)


## -- TBD/WIP -- ##
def enumerate_usb(cb, host, start_time=None):
    query_string = r'regmod:registry\machine\system\currentcontrolset\control\deviceclasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\*'
    query_string += ' hostname:{0:s}'.format(host)
    if start_time:
        query_string += ' start:{0:s}'.format(start_time)

    for proc in cb.select(Process).where(query_string):
        print("\n[+] Found {} - {}:".format(proc.process_name, proc.id))
        print("%s=== USB REGMODS ====" % ('  '))
        for rm in proc.regmods:
            if "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" in rm.path:
                pieces = rm.path.split("usbstor#disk&")
                if len(pieces) < 2:
                    print("WARN:::: {0}".format(str(pieces)))
                else:
                    device_info = pieces[1] #.split('{53f56307-b6bf-11d0-94f2-00a0c91efb8b}')[0]
                    print("  {}: {} {}".format(eastern_time(rm.timestamp), rm.type, device_info))
                    #print(device_info)
                    

## -- Intel/detection helpers -- ##
def perform_splunk_search(splunk_command, debug=None):

    splunkargs = shlex.split(splunk_command)
    splunk_output = None
    if debug:
        LOGGER.debug("Searching splunk with: {}".format(splunk_command))
    try:
        splunk_output = subprocess.check_output(splunkargs)
        return splunk_output

    except subprocess.CalledProcessError as e:
        # error but continue 
        LOGGER.error("returncode: " + str(e.returncode) + "; with output: "
              + str(e.output) + "; for cmd: " + str(e.cmd) )
        return None


def parse_splunk_results(results, debug=None):
    result_dict = json.loads(results.decode("utf-8"))
    result_list = result_dict['result']
    hits = {'feed_hits': [], 'watchlist_hits': []}
    for result in result_list:
        full_result = json.loads(result['_raw'])
        # CB redundant logging causes duplicates on feed hits sometimes
        if 'feed' in result['notification_type']:
            query_string = None
            feed_name = None
            feed_link = None
            try:
                query_string = full_result['ioc_query_string']
            except KeyError as err:
                if debug:
                    LOGGER.debug("KeyError: " + str(err))
            try:
                feed_name = full_result['feed_name']
            except KeyError as err:
                if debug:
                    LOGGER.debug("KeyError: " + str(err))
            try:
                feed_link = full_result['docs'][0]['alliance_link_'+feed_name]
            except KeyError as err:
                if debug:
                    LOGGER.debug("KeyError: " + str(err))
            if len(full_result['docs']) > 1:
                LOGGER.warn("result document list greater than one")
            if feed_name is not None and feed_link is not None:
                hits['feed_hits'].append((feed_name, feed_link, query_string))
        elif 'watchlist' in result['notification_type']:
            # for some reasone, some watchlists log both watchlist.hit.process
            # and watchlist.storage.hit.process
            if full_result['watchlist_name'] not in hits['watchlist_hits']:
                hits['watchlist_hits'].append(full_result['watchlist_name'])
        else:
            LOGGER.error("Problem parsing splunk results.")
    return hits


def splunk_search_worker(search_queue, result, debug=None):
    while not search_queue.empty():
        search_data = search_queue.get()
        proc_guid = search_data[0]
        search_text = search_data[1]
        if debug:
            LOGGER.debug("Kicking intel search for {} ...".format(proc_guid))
        result[proc_guid] = perform_splunk_search(search_text, debug)
        search_queue.task_done()
    return True


def build_vx_queries(query_info):
    # create the list of queries that we will make with the CB api
    if not isinstance(query_info, ProcessList):
        print("[ERROR] build_queries: input type not supported")
        sys.exit(1)

    queries = []
    parent_name = None # keep track
    for process in query_info:
        pid_has_query = False
        for child_proc in process.children:
            queries.append("process_name:{} process_pid:{} childproc_name:{}".format(process.proc_name,
                process.pid, child_proc.proc_name))
            pid_has_query = True
            break

        if pid_has_query is False:
            if parent_name: # not None
                queries.append("process_name:{} process_pid:{} parent_name:{}".format(process.proc_name,
                    process.pid, parent_name))
            else: # this query is not specific enough
                queries.append("process_name:{} process_pid:{}".format(process.proc_name,
                    process.pid))
        parent_name = process.proc_name
    return queries


def get_vxstream_cb_guids(cb, vx_process_list):
    ProcessQueryResults = []
    for query in build_vx_queries(vx_process_list):
        ProcessQueryResults = cb.select(Process).where(query).group_by('id')
        for proc in ProcessQueryResults:
            for vxp in vx_process_list:
                if int(proc.process_pid) == int(vxp.pid):
                    vxp.id = proc.id
                    break
    return 


def parse_vxstream_report(cb, report_path):
    json_report = None
    try:
        with open(report_path, 'r') as fp:
            json_report = json.load(fp)
    except Exception as e:
        print("unable to load json from {}: {}".format(args.report_path, str(e)))
        sys.exit(1)


    process_list = ProcessList()
    process_list_json = json_report["analysis"]["runtime"]["targets"]["target"]

    if process_list_json:
        if isinstance(process_list_json, dict):
            process_list_json = [process_list_json]

        for process in process_list_json:
            command = process["name"] + " " + process["commandline"]
            process_name = process["name"]
            pid = process["pid"]
            parent_pid = process["parentpid"]
            #print("{} @ {}".format(pid, process["date"]))
            new_process = ProcessWrapper(command, pid, parent_pid, process_name, None)
            process_list.add_process(new_process)

    # call structure() to build process relationship tree
    process_list.structure() # come back to investigate why returning this output breaks script
    get_vxstream_cb_guids(cb, process_list)
    return process_list


def get_vxtream_cb_guids(report):
    try:
        cb = CbResponseAPI(profile='vxstream')
    except:
        LOGGER.error("Failure to get CbResponseAPI with 'vxstream' profile")
        return 1

    process_list = parse_vxstream_report(cb, report)
    return [ p.id for p in process_list ]


def query_vx_detection_db(process_list):
    ''' TODO: delete all this functionaliy or move db items to a config file '''
    db = pymysql.connect("removed","removed","removed","removed")
    cursor = db.cursor(pymysql.cursors.DictCursor)
    results_dict = {}
    for process in process_list:
        query = "SELECT * FROM splunk_detections WHERE proc_guid='{}'".format(process.id)
        cursor.execute(query)
        results_dict[process.id] = []
        for row in cursor:
            results_dict[process.id].append(row['hunt_name'])
    db.close()
    return results_dict


## -- Process analysis functions -- ##
def events_to_json(proc):

    process_raw_sum_data = proc._cb.get_object("/api/v1/process/{0}".format(proc.id))
    process_summary = process_raw_sum_data['process']
    process_summary['parent'] = process_raw_sum_data['parent']
    start_time = process_summary['start'].replace('T', ' ')
    start_time = start_time.replace('Z','')
    start_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
    process_summary['start'] = eastern_time(start_time)

    process_summary['filemods'] = []
    process_summary['regmods'] = []
    process_summary['unsigned_modloads'] = []
    process_summary['netconns'] = []
    process_summary['crossprocs'] = []
    process_summary['children'] = []
    #process_summary['segments'] = []

    for segment in proc.get_segments():
        proc.current_segment = segment
        #process_summary['segments'].append(segment)

        for nc in proc.netconns:
            nc_dict = { 'timestamp': str(eastern_time(nc.timestamp)), 'domain': nc.domain,
                        'remote_ip': nc.remote_ip, 'remote_port': nc.remote_port,
                        'proto': nc.proto, 'direction': nc.direction, 'local_ip': nc.local_ip,
                        'local_port': nc.local_port, 'proxy_ip': nc.proxy_ip,
                        'proxy_port': nc.proxy_port, 'segment': segment }
            process_summary['netconns'].append(nc_dict)

        for child in proc.children:
            child = { 'timestamp': str(eastern_time(child.timestamp)), 'procguid': child.procguid,
                      'pid': child.pid, 'path': child.path, 'md5': child.md5, 'segment': segment }
            process_summary['children'].append(child)

        for fm in proc.filemods:
            fm_dict = { 'timestamp': str(eastern_time(fm.timestamp)), 'type': fm.type, 'path': fm.path,
                        'filetype': fm.filetype, 'md5': fm.md5, 'segment': segment }
            # note we can also cb.select the md5 and see if it's signed, etc.
            process_summary['filemods'].append(fm_dict)

        for rm in proc.regmods:
            rm_dict = { 'timestamp': str(eastern_time(rm.timestamp)), 'type': rm.type,
                        'path': rm.path, 'segment': segment }
            process_summary['regmods'].append(rm_dict)

        for ml in proc.unsigned_modloads:
            unsml_dict = { 'timestamp': str(eastern_time(ml.timestamp)), 'md5': ml.md5,
                           'path': ml.path, 'segment': segment }
            process_summary['unsigned_modloads'].append(unsml_dict)

        for crossp in proc.crossprocs:
            cp_dict = { 'timestamp': str(eastern_time(crossp.timestamp)), 'type': crossp.type,
                        'privileges': crossp.privileges, 'target_md5': crossp.target_md5,
                        'target_path': crossp.target_path, 'segment': segment }
            process_summary['crossprocs'].append(cp_dict)

    return process_summary


def print_filemods(proc):

    print("%s=== FILEMODS ====" % ('  '))

    for segment in proc.get_segments():
        proc.current_segment = segment
        for fm in proc.filemods:

            signed = ""
            product_name = ""
            if fm.type != "CreatedFile" and fm.md5:
                try:
                    b = proc._cb.select(Binary, fm.md5)
                    signed = b.signed
                    product_name = b.product_name
                    print("%s%s: %s: %s , md5:%s, signed:%s, product_name:%s" % ('  ',
                          eastern_time(fm.timestamp), fm.type, fm.path,
                          fm.md5, signed, product_name))
                except ObjectNotFoundError:
                    print("%s%s: %s: %s , md5:%s" % ('  ', eastern_time(fm.timestamp),
                          fm.type, fm.path, fm.md5))
            elif fm.type != "CreatedFile":
                print("%s%s: %s: %s" % ('  ', eastern_time(fm.timestamp), fm.type, fm.path))
    print()


def print_netconns(proc):
    print("%s=== NETCONNS ====" % ('  '))

    for segment in proc.get_segments():
        proc.current_segment = segment
        for nc in proc.netconns:
            print("  {}: ({}) remote IP:{} remote port:{} domain:{}".format(eastern_time(nc.timestamp),
                                                                            nc.direction, nc.remote_ip,
                                                                            nc.remote_port, nc.domain))
    print()


def print_regmods(proc):
    print("  === REGMODS ====")

    for segment in proc.get_segments():
        proc.current_segment = segment
        for rm in proc.regmods:
            print("  {}: {} {}".format(eastern_time(rm.timestamp), rm.type, rm.path))
    print()


def unsigned_modloads(proc):
    print("%s=== UNSIGNED MODLOADS ====" % ('  '))

    for segment in proc.get_segments():
        proc.current_segment = segment
        for unmodload in proc.unsigned_modloads:
            print("  {}: {} , md5:{}".format(eastern_time(unmodload.timestamp),
                                             unmodload.path, unmodload.md5))
    print()


def print_crossprocs(proc):
    print("%s=== CROSSPROCS ====" % ('  '))

    for segment in proc.get_segments():
        proc.current_segment = segment
        for cross in proc.crossprocs:
            print("  {} | {} | {} -> {} | {} -> {}".format(eastern_time(cross.timestamp),
                                                           cross.type,
                                                           cross.source_path,
                                                           cross.target_path,
                                                           cross.source_proc.webui_link,
                                                           cross.target_proc.webui_link))
            print()
    print()


def print_child_events(proc):
    print("  == CHILDPROC Start/End Events ==")
    children = {}
    # group childproc events together for printing
    for childproc in proc.children:
        guid = childproc.procguid[:childproc.procguid.rfind('-')]
        if guid in children:
            children[guid].append(childproc)
        else:
            children[guid] = [childproc]
    # print
    for guid in children:
        child_events = children[guid]
        # reverse so they're printed in start/end sequence
        for c in reversed(child_events):
            print("  {}: {} (PID={}) - {}".format(eastern_time(c.timestamp),
                                                  c.path,
                                                  c.pid,
                                                  c.procguid))
        print()


def analyze_proc(proc):
    print_filemods(proc)
    print_netconns(proc)
    print_regmods(proc)
    unsigned_modloads(proc)
    print_crossprocs(proc)


def walk_process_tree(proc):
    process_list = ProcessList()
    # add root proc
    process_list.add_process(ProcessWrapper(proc.cmdline, proc.process_pid,
                                            proc.parent_pid, proc.process_name, proc.id))
    def crawler(process_list, proc):
        childguids = []
        for childproc in proc.children:
            if childproc.procguid not in childguids:
                childguids.append(childproc.procguid)

                # Get all events by selecting the process (CbChildProcEvent != Process)
                cProc = proc._cb.select(Process, proc._cb.select(Process, childproc.procguid).id)

                if childproc.is_suppressed:
                    process_list.add_process(ProcessWrapper(
                                             "[DATA SUPPRESSED] "+childproc.proc_data['cmdline'],
                                             childproc.pid, proc.process_pid, childproc.path,
                                             childproc.procguid, childproc.is_suppressed))
                else:
                    process_list.add_process(ProcessWrapper(
                                             cProc.cmdline, cProc.process_pid,
                                             cProc.parent_pid, cProc.process_name,
                                             cProc.id))
                    crawler(process_list, cProc)
        return process_list

    process_list = crawler(process_list, proc)

    return process_list


def process_event_analysis(proc, args):

    process_tree = None
    if args.proc_info:
        binary_vinfo = proc.binary.version_info
        binary_sdata = proc.binary.signing_data
        binary_vt = proc.binary.virustotal
        print("\n\t-------------------------")
        print("\tProcess Name: {}".format(proc.process_name))
        print("\tProcess PID: {}".format(proc.process_pid))
        print("\tProcess Start: {}".format(eastern_time(proc.start)))
        print("\tProcess MD5: {}".format(proc.process_md5))
        print("\tCommand Line: {}".format(proc.cmdline))
        print("\tParent Name: {}".format(proc.parent_name))
        print("\tParent GUID: {}".format(proc.parent_id))
        print("\tHostname: {}".format(proc.hostname))
        print("\tUsername: {}".format(proc.username))
        print("\tBinary Description: {}".format(binary_vinfo.file_desc))
        print("\tProduct Name: {}".format(binary_vinfo.product_name))
        print("\tDigital Copyright: {}".format(binary_vinfo.legal_copyright))
        print("\tOriginal filename: {}".format(binary_vinfo.original_filename))
        print("\tSigned Status: {}".format(binary_sdata.result))
        print("\tSignature Publisher: {}".format(binary_sdata.publisher))
        print("\tSignature Issuer: {}".format(binary_sdata.issuer))
        print("\tSignature Subject: {}".format(binary_sdata.subject))
        print("\tVirusTotal Score: {}".format(binary_vt.score))
        print("\tVirusTotal Link: {}".format(binary_vt.link))
        print("\tGUI Link: {}".format(proc.webui_link))
        print()
        return None

    cb = proc._cb
    if args.walk_tree:
        print("\nProcess tree for {0:s} executed on {1:s} by {2:s}:\n".format(proc.path,
                                                                              proc.hostname,
                                                                              proc.username))
        process_tree = walk_process_tree(proc)
        print(process_tree) 
        print("")

        if process_tree.size > 10 and args.no_analysis != True and args.warnings == True:
            print("Warning: Process Tree contains {} processes.".format(process_tree.size))
            print_results = input("Print all process tree events? (y/n) [n] ") or 'n'
            arg.no_analysis = True if print_results == 'n' else False

        for process in process_tree:
            if process.is_suppressed:
                print("+  [DATA SUPPRESSED] {} (PID:{}) - {}".format(process.proc_name, process.pid,
                                                                   process.id))
                continue

            proc = cb.select(Process, process.id)
            print("+  {} (PID:{}) - {}".format(proc.process_name, proc.process_pid,
                                               process.id))
            if args.filemods:
                print_filemods(proc)
                args.no_analysis = True
            if args.netconns:
                print_netconns(proc)
                args.no_analysis = True
            if args.regmods:
                print_regmods(proc)
                args.no_analysis = True
            if args.unsigned_modloads:
                unsigned_modloads(proc)
                args.no_analysis = True
            if args.crossprocs:
                print_crossprocs(proc)
                args.no_analysis = True

            if args.no_analysis != True:
                if args.json:
                    print(events_to_json(proc))
                else:
                    analyze_proc(proc)

    else:
        process_tree = ProcessList()
        process_tree.add_process(ProcessWrapper(proc.cmdline, proc.process_pid,
                                                proc.parent_pid, proc.process_name, proc.id))
        
        print("\n{0:s} executed on {1:s} by {2:s}:\n".format(proc.path,
                                                             proc.hostname, proc.username))
        print(process_tree)
        print()
        if args.filemods:
            print_filemods(proc)
            args.no_analysis = True
        if args.netconns:
            print_netconns(proc)
            args.no_analysis = True
        if args.regmods:
            print_regmods(proc)
            args.no_analysis = True
        if args.unsigned_modloads:
            unsigned_modloads(proc)
            args.no_analysis = True
        if args.crossprocs:
            print_crossprocs(proc)
            args.no_analysis = True
        if args.show_children:
            print_child_events(proc)
            args.no_analysis = True

        if args.no_analysis != True:
            if args.json:
                print(events_to_json(proc))
            else:
                analyze_proc(proc)
                print_child_events(proc)

    return process_tree


## -- Live Response (collect/remediate) -- ##
def go_live(sensor):
    start_time = time.time()
    timeout = 604800 # seven days
    current_day = 0
    lr_session = None
    if sensor.status == 'Offline':
        LOGGER.info("Waiting for sensor to come online..")
    while time.time() - start_time < timeout:
        try:
            lr_session = sensor.lr_session()
            print("[+] LR session started at {}".format(time.ctime()))
            break
        except TimeoutError:
            elapsed_time = time.time() - start_time
            if current_day != elapsed_time // 86400:
                current_day+=1
                LOGGER.info("24 hours of timeout when polling for LR session")
                print("\tAttempting LR session again on {} @ {}".format(sensor.hostname,
                                                                        time.ctime()))
    return lr_session


def getFile_with_timeout(lr_session, sensor, filepath, localfname=None):
    print("~ downloading {}".format(filepath))
    raw = lr_session.get_raw_file(filepath, timeout=3600)
    content = raw.read()
    raw.close()
    if localfname is None:
        localfname = sensor + '_' + filepath.rsplit("\\",1)[1]
    with open(localfname,'wb') as f:
        f.write(content)
    print("+ wrote {}".format(localfname))
    return localfname


def wait_for_process_to_finish(lr_session, process_name):
    # THIS SHOULDN'T BE NECCESSARY GRR - https://github.com/carbonblack/cbapi-python/issues/97
    print(" - checking if "+process_name+" is running")
    running = None

    for process in lr_session.list_processes():
        if process_name in process['command_line']:
            running = True
            print(" - {} still running..".format(process_name))

    if running:
        print(" - waiting for {} to finish...".format(process_name))
        while(running):
            time.sleep(30)
            running = False
            for process in lr_session.list_processes():
                if process_name in process['command_line']:
                    running = True
                    print(" - {} still running..".format(process_name))

    return


def streamline(command):
    args = shlex.split(command)
    return subprocess.call(args, stdout=subprocess.PIPE)


def LR_collection(lr_session, args):
    # perform a full Live Response collection

    def lr_cleanup(lr_session):
        try:
            dir_output = lr_session.list_directory("C:\\")
            for dir_item in dir_output:
                if 'DIRECTORY' in dir_item['attributes'] and dir_item['filename'] == 'lr':
                    print("[+] Found existing lr directory.. deleting")
                    command_str = "powershell.exe Remove-Item {} -Force -Recurse".format("C:\\lr")
                    result = lr_session.create_process(command_str)
                    if result != b'':
                        LOGGER.warn(" ! Problem  deleting {}".format("C:\\lr"))
                if 'ARCHIVE' in dir_item['attributes'] and dir_item['filename'] == 'lr.exe' \
                    or dir_item['filename'] == 'cbilr.exe':
                    print("[+] Existing LR package found.. deleting..")
                    try:
                        lr_session.delete_file("C:\\" + dir_item['filename'])
                    except TypeError as e:
                        if 'startswith first arg must be bytes' in e:
                            LOGGER.warn("Error deleting lr.exe.. trying to move on")
        except live_response_api.LiveResponseError as e:
            if 'ERROR_PATH_NOT_FOUND' not in str(e):
                print("[ERROR] LiveResponseError: {}".format(e))
                return 1

    #Check if LR.exe and/or lr dir already on host. Delete everything if so
    lr_cleanup(lr_session)

    # Put latest LR.exe on host
    lr_analysis_path = "/opt/host_analysis/cblr/lr.exe"
    # https://community.carbonblack.com/thread/7740
    #lr_analysis_path = "/opt/host_analysis/cblr/lrcbi.exe"
    print("[+] Dropping latest LR on host..")
    filedata = None
    with open(lr_analysis_path, 'rb') as f: 
        filedata = f.read()
    try:
        lr_session.put_file(filedata, "C:\\lr.exe")
    except Exception as e:
        # If we make it here and there is still and lr.exe on the host then something went wrong
        # and we will work with the existing lr.exe
        if 'ERROR_FILE_EXISTS' not in str(e):
            LOGGER.error("Unknown Error: {}".format(str(e)))
            return 1
    
    # execute lr.exe to extract files
    unzip = "C:\\lr.exe -o \'C:\\' -y"
    print("[+] Extracting LR.exe..")
    lr_session.create_process(unzip)
    
    # execute collect.bat
    collect = "C:\\lr\\win32\\tools\\collect.bat"
    time.sleep(1)
    print("[+] Executing collect.bat..")
    start_time = time.time()
    lr_session.create_process(collect, wait_for_output=False, wait_for_completion=False) #, wait_timeout=900)
    wait_for_process_to_finish(lr_session, "collect.bat")
    collect_duration = datetime.timedelta(minutes=(time.time() - start_time))
    print("[+] Collect completed in {}".format(collect_duration))

    # Collect output 7z file
    outputdir = "C:\\lr\\win32\\output\\"
    localfile = None
    for dir_item in lr_session.list_directory(outputdir):
        if 'ARCHIVE' in dir_item['attributes'] and  dir_item['filename'].endswith('7z'):
            localfile = getFile_with_timeout(lr_session, args.sensor, outputdir+dir_item['filename'], dir_item['filename'])

    # HERE need to delete our LR files from sensor
    lr_cleanup(lr_session)
 
    # Call steamline on the 7z lr package
    streamline_path = "/opt/host_analysis/streamline/streamline.py"
    print("[+] Starting streamline on {}".format(localfile))
    streamline(streamline_path + " " + localfile)
    print("[+] Streamline complete")
    return


def Collection(cb, args):
    if args.info:
        print()
        sensor = cb.select(Sensor).where("hostname:{}".format(args.sensor)).one()
        print("Sensor object - {}".format(sensor.webui_link))
        print("-------------------------------------------------------------------------------\n")
        print("\tcb_build_version_string: {}".format(sensor.build_version_string))
        print("\tcomputer_sid: {}".format(sensor.computer_sid))
        print("\tcomputer_dns_name: {}".format(sensor.computer_dns_name))
        print("\tcomputer_name: {}".format(sensor.computer_name))
        print("\tos_environment_display_string: {}".format(sensor.os_environment_display_string))
        print("\tphysical_memory_size: {}".format(sensor.physical_memory_size))
        print("\tsystemvolume_free_size: {}".format(sensor.systemvolume_free_size))
        print("\tsystemvolume_total_size: {}".format(sensor.systemvolume_total_size))
        print()
        print("\tstatus: {}".format(sensor.status))
        print("\tis_isolating: {}".format(sensor.is_isolating))
        print("\tsensor_id: {}".format(sensor.id))
        print("\tlast_checkin_time: {}".format(sensor.last_checkin_time))
        print("\tnext_checkin_time: {}".format(sensor.next_checkin_time))
        print("\tsensor_health_message: {}".format(sensor.sensor_health_message))
        print("\tsensor_health_status: {}".format(sensor.sensor_health_status))
        print("\tnetwork_interfaces:")
        for ni in sensor.network_interfaces:
            print("\t\t{}".format(ni))
        if sensor.status == "Online":
            print("\n\t+ Tring to get logical drives..")
            lr_session = sensor.lr_session()
            print("\t\tAvailable Drives: %s" % ' '.join(lr_session.session_data.get('drives', [])))
            lr_session.close()
            lr_session = None
        print()
        return 0

    lr_session = go_live(cb.select(Sensor).where("hostname:{}".format(args.sensor)).one())

    if lr_session:
        if args.multi_collect:
            filepaths = regpaths = full_collect = None
            config = ConfigParser()
            config.read(args.multi_collect)
            try:
                filepaths = config.items("files")
            except:
                filepaths = []
            try:
                regpaths = config.items("registry_paths")
            except:
                regpaths = []
            try:
                full_collect = config.get('full_collect', 'action')
            except:
                pass
            
            if regpaths is not None:
                for regpath in regpaths:
                    if isinstance(regpath, tuple):
                        regpath = regpath[1]
                    print("~ Trying to get {}".format(regpath))
                    try:
                        result = lr_session.get_registry_value(regpath)
                        if result:
                            localfname = args.sensor + '_regkey_' + result['value_name'] + ".txt"
                            with open(localfname,'wb') as f:
                                f.write(bytes(result['value_data'], 'UTF-8'))
                            print("\t+ Data written to: {}".format(localfname))
                    except Exception as e:
                        print("[!] Error: {}".format(str(e)))
            if filepaths is not None:
                for filepath in filepaths:
                    try:
                        getFile_with_timeout(lr_session, args.sensor, filepath[1])
                    except Exception as e:
                        print("[!] Error: {}".format(str(e)))
            if full_collect == 'True':
               return LR_collection(lr_session, args) 

        elif args.filepath:
            getFile_with_timeout(lr_session, args.sensor, args.filepath)
        elif args.process_list:
            print("~ obtaining running process data..")
            for process in lr_session.list_processes():
                pname = process['path'][process['path'].rfind('\\')+1:]
                print("\n\t-------------------------")
                print("\tProcess: {} (PID: {})".format(pname, process['pid']))
                #print("\tProcID: {}".format(process['pid']))
                print("\tGUID: {}".format(process['proc_guid']))
                print("\tUser: {}".format(process['username']))
                print("\tCommand: {}".format(process['command_line']))
            print()
        elif args.memdump:
            if args.memdump == 'ALLMEM':
                print("~ dumping contents of memory on {}".format(args.sensor))
                local_file = remote_file = "{}.memdmp".format(args.sensor)
                try:
                    dump_object = lr_session.start_memdump(remote_filename=remote_file, compress=False)
                    dump_object.wait()
                    print("+ Memory dump complete on host -> C:\windows\carbonblack\{}".format(remote_file))
                except live_response_api.LiveResponseError as e:
                    print("[ERROR] LiveResponseError: {}".format(e))
                    return 1
                filedata = None
                with open('/opt/carbonblack/cbinterface/lr_tools/compress_file.bat', 'rb') as f:
                    filedata = f.read()
                try:
                    lr_session.put_file(filedata, "C:\\Windows\\CarbonBlack\\compress_file.bat")
                except live_response_api.LiveResponseError as e:
                    if 'ERROR_FILE_EXISTS' not in str(e):
                        LOGGER.error("Error puting compress_file.bat")
                        return 1
                    else:
                        lr_session.delete_file("C:\\Windows\\CarbonBlack\\compress_file.bat")
                        lr_session.put_file(filedata, "C:\\Windows\\CarbonBlack\\compress_file.bat")
                print("~ Launching compress_file.bat to create C:\windows\carbonblack\_memdump.zip")
                compress_cmd = "C:\\Windows\\CarbonBlack\\compress_file.bat "+remote_file
                lr_session.create_process(compress_cmd, wait_for_output=False, wait_for_completion=False)
                print("  [!] If compression successful, _memdump.zip will exist, otherwise {} will exist".format(remote_file))
            else:
                print("~ dumping memory where pid={} for {}".format(args.memdump, args.sensor))
                # need to make sure procdump.exe is on the sensor
                lr_tool_path = "C:\\lr\\win32\\tools\\"
                procdump_host_path = None
                try:
                    dir_output = lr_session.list_directory(lr_tool_path)
                    for dir_item in dir_output:
                        if dir_item['filename'] == 'procdump.exe':
                            print("[INFO] procdump.exe already on host. Sweet")
                            procdump_host_path = lr_tool_path + "procdump.exe"
                            break
                    else:
                        print("[INFO] procdump.exe not already on host.")
                except live_response_api.LiveResponseError as e:
                    if 'ERROR_PATH_NOT_FOUND' not in str(e):
                        print("[ERROR] LiveResponseError: {}".format(e))
                        return 1
                    else:
                        try: # has cbinterface already dropped it?
                            dir_output = lr_session.list_directory("C:\\lr\\")
                            for dir_item in dir_output:
                                if dir_item['filename'] == 'procdump.exe':
                                    print("[INFO] procdump.exe already on host.")
                                    procdump_host_path = "C:\\lr\\procdump.exe"
                                    break
                        except live_response_api.LiveResponseError as e:
                            if 'ERROR_PATH_NOT_FOUND' not in str(e) and 'ERROR_FILE_NOT_FOUND' not in str(e):
                                print("here")
                                print("[ERROR] LiveResponseError: {}".format(e))
                                return 1
                            else:
                                print("[INFO] Procdump not already on host, dropping procdump..")

                if not procdump_host_path:
                    print("~ dropping procdump.exe on host.")
                    procdump_analysis_path = "/opt/host_analysis/cblr/lr_tools/procdump.exe"
                    filedata = None
                    with open(procdump_analysis_path, 'rb') as f: 
                        filedata = f.read()
                    try:
                        lr_session.create_directory("C:\\lr")
                    except live_response_api.LiveResponseError:
                        print("[INFO] LR directory already exists")
                    lr_session.put_file(filedata, "C:\\lr\\procdump.exe")
                    procdump_host_path = "C:\\lr\\procdump.exe"

                print("~ Executing procdump..")
                command_str = procdump_host_path + " -accepteula -ma " + str(args.memdump) 
                result = lr_session.create_process(command_str)
                time.sleep(1)
                print("+ procdump output:\n-------------------------")
                result = result.decode('utf-8')
                print(result + "\n-------------------------")

                # cut off the carriage return and line feed from filename 
                dumpfile_name = result[result.rfind('\\')+1:result.rfind('.dmp')+4]
                dumpfilepath = "C:\\WINDOWS\\CarbonBlack\\"
                while True:
                    if 'procdump.exe' not in str(lr_session.list_processes()):
                        break
                    else:
                        time.sleep(1)
                # download dumpfile to localdir
                getFile_with_timeout(lr_session, args.sensor, dumpfilepath+dumpfile_name)
        elif args.command_exec:
            print("executing '{}' on {}".format(args.command_exec, args.sensor))
            result = lr_session.create_process(args.command_exec, wait_timeout=60, wait_for_output=True)
            print("\n-------------------------")
            result = result.decode('utf-8')
            print(result + "\n-------------------------")
            print()
        elif args.regkeypath:
            print("\n\t{}".format(args.regkeypath))
            result = lr_session.get_registry_value(args.regkeypath)
            print("\t-------------------------")
            print("\tName: {}".format(result['value_name']))
            print("\tType: {}".format(result['value_type']))
            print("\tData: {}".format(result['value_data']))
            print()
        elif args.get_task:
            print("[+] Making scheduledTaskOps.ps1 available on host.")
            schtask_ps_path = '/opt/carbonblack/cbinterface/lr_tools/scheduledTaskOps.ps1'
            filedata = None
            with open(schtask_ps_path, 'rb') as f:
                filedata = f.read()
            try:
                lr_session.put_file(filedata, "C:\\windows\\carbonblack\\scheduledTaskOps.ps1")
                print("[+] Dropped scheduledTaskOps.ps1.")
            except live_response_api.LiveResponseError as e:
                if "ERROR_FILE_EXISTS" in str(e):
                    print("[+] scheduledTaskOps.ps1 already on host.")
                else:
                    LOGGER.error(str(e))
                    return 1
            # execute
            cmd = "powershell.exe C:\\windows\\carbonblack\\scheduledTaskOps.ps1 -Get"
            print("[+] Executing: {}".format(cmd))
            result = lr_session.create_process(cmd)
            result = result.decode('utf-8')
            print("[+] Execution Results:\n-------------------------")
            print(result + "\n-------------------------")
            print()
 
        else:
            return LR_collection(lr_session, args)
    return 0


def Remediation(cb, args):
    sensor = cb.select(Sensor).where("hostname:{}".format(args.sensor)).one()

    lr_session = go_live(sensor)
    print("[+] Starting Remediation on {}..".format(args.sensor))

    process_names = pids = regpaths = filepaths = dirpaths = schtasks = None
    if args.remediation_filepath:
        config = ConfigParser()
        config.read(args.remediation_filepath)
        try:
            filepaths = config.items("files")
        except:
            filepaths = [] 
        try:
            process_names = config.items("process_names")
        except:
            process_names = []
        try:
            pids = config.items("pids")
        except:
            pids = []
        try:
            regpaths = config.items("registry_paths")
        except:
            regpaths = []
        try:
            dirpaths = config.items("directories")
        except:
            dirpaths = []
        try:
            schtasks = config.items("scheduled_tasks")
        except:
            schtasks = []
    elif args.kill_process_name:
        pids = []
        process_names = []
        process_names.append(args.kill_process_name)
    elif args.kill_pid:
        pids = []
        pids.append(args.kill_pid)
    elif args.delete_file:
        filepaths = []
        filepaths.append(args.delete_file)
    elif args.delete_regkey:
        regpaths = []
        regpaths.append(args.delete_regkey)
    elif args.delete_directory:
        dirpaths = []
        dirpaths.append(args.delete_directory)
    elif args.delete_scheduled_task:
        print("[+] Making scheduledTaskOps.ps1 available on host.")
        schtask_ps_path = '/opt/carbonblack/cbinterface/lr_tools/scheduledTaskOps.ps1'
        filedata = None
        with open(schtask_ps_path, 'rb') as f:
            filedata = f.read()
        try:
            lr_session.put_file(filedata, "C:\\windows\\carbonblack\\scheduledTaskOps.ps1")
            print("[+] Dropped scheduledTaskOps.ps1.")
        except live_response_api.LiveResponseError as e:
            if "ERROR_FILE_EXISTS" in str(e):
                print("[+] scheduledTaskOps.ps1 already on host.")
            else:
                LOGGER.error(str(e))
                return 1
        schtasks = []
        schtasks.append(args.delete_scheduled_task)


    if lr_session is not None:
        # first, kill running processes
        if process_names is not None:
            for process in lr_session.list_processes():
                for evil_proc in process_names:
                    if isinstance(evil_proc, tuple):
                        evil_proc = evil_proc[1]
                    pname = process['path'][process['path'].rfind('\\')+1:]
                    if evil_proc.lower() == pname:
                        print(" ~ found: {} with pid:{}".format(process['path'], process['pid']))
                        pids.append(process['pid'])
        if pids is not None:
            for pid in pids:
                if isinstance(pid, tuple):
                    pid = pid[1]
                try:
                    if lr_session.kill_process(pid):
                        print(" + successfully killed pid:{}".format(pid))
                    else:
                        print(" - unable to kill pid:{}".format(pid))
                except live_response_api.LiveResponseError:
                    LOGGER.warn("LiveResponseError: unable to find pid={}".format(pid))
        # second, delete registry locations
        if regpaths is not None:
            for regpath in regpaths:
                if isinstance(regpath, tuple):
                    regpath = regpath[1]
                try:
                    lr_session.delete_registry_value(regpath)
                    print(" + Deleted {}".format(regpath))
                except live_response_api.LiveResponseError as e:
                    LOGGER.warn("LiveResponseError for {}: {}".format(regpath, e))
        # third, delete files
        if filepaths is not None:
            for path in filepaths:
                if isinstance(path, tuple):
                    path = path[1]
                try:
                    lr_session.delete_file(path)
                    print(" + Deleted {}".format(path))
                except live_response_api.LiveResponseError as e:
                    LOGGER.warn("LiveResponseError for {}: {}".format(path, e))
        # forth, delete entire directories (or force delete files)
        # instead of walking the directory and iterating over all of the files
        # we will powershell ~ assuption made: windows os
        if dirpaths is not None:
            #print("[INFO] Directory deletion currently disabled")
            for dirpath in dirpaths:
                if insinstance(dirpath, tuple):
                    dirpath = dirpath[1] 
                command_str = "powershell.exe Remove-Item {} -Force -Recurse".format(dirpath)
                result = lr_session.create_process(command_str)
                if result == b'':
                    print(" + Deleted {}".format(dirpath))
                else:
                    print(" - Problem  deleting {}".format(dirpath))
        
        # fifth, delete any scheduled tasks
        if schtasks is not None:
            for task in schtasks:
                if isinstance(task, tuple):
                    task = task[1]
                # execute
                cmd = "powershell.exe C:\\windows\\carbonblack\\scheduledTaskOps.ps1 -Remove -ComputerName {} -Path {}"
                cmd = cmd.format(args.sensor, task)
                print("[+] Executing: {}".format(cmd))
                result = lr_session.create_process(cmd)
                result = result.decode('utf-8')
                if result == '':
                    print(" + successfully deleted scheduled task: {}".format(task))
                else:
                    LOGGER.warn("problem deleting scheduled task: {}".format(task))
                    print("[!] Execution results:")
                    print(" | -------------------------")
                    print(" | " + result + " | -------------------------")
                    print()
 
    return 0


def sensor_search(profiles, sensor_name):
    if not isinstance(profiles, list):
        LOGGER.error("profiles argument is not a list")
        return 1
    cb_finds = []
    for profile in profiles:
        cb = CbResponseAPI(profile=profile)
        try:
            cb.select(Sensor).where("hostname:{}".format(sensor_name)).one()
            cb_finds.append(cb)
            LOGGER.info("Found a sensor by this name in {} environment".format(profile))
        except TypeError as e:
            # Appears to be bug in cbapi library here -> site-packages/cbapi/query.py", line 34, in one
            # Raise MoreThanOneResultError(message="0 results for query {0:s}".format(self._query))
            # That raises a TypeError ¯\_(ツ)_/¯
            if 'non-empty format string passed to object' in str(e):
                try: # accounting for what appears to be an error in cbapi error handling
                    result = cb.select(Sensor).where("hostname:{}".format(sensor_name))
                    if isinstance(result[0], models.Sensor):
                        print()
                        LOGGER.warn("MoreThanOneResultError searching for {0:s}".format(sensor_name))
                        print("\nResult breakdown:")
                        for sensor in result:
                            print()
                            print("Sensor object - {}".format(sensor.webui_link))
                            print("-------------------------------------------------------------------------------\n")
                            print("\tos_environment_display_string: {}".format(sensor.os_environment_display_string))
                            print()
                            print("\tstatus: {}".format(sensor.status))
                            print("\tsensor_id: {}".format(sensor.id))
                            print("\tlast_checkin_time: {}".format(sensor.last_checkin_time))
                            print("\tnext_checkin_time: {}".format(sensor.next_checkin_time))
                            print("\tsensor_health_message: {}".format(sensor.sensor_health_message))
                            print("\tsensor_health_status: {}".format(sensor.sensor_health_status))
                            print("\tnetwork_interfaces:")
                        print()
                        return 1
                except:
                    pass
        except Exception as e:
            LOGGER.debug("Exception searching for sensor in {}".format(str(e)))
            pass
    return cb_finds


def proc_search_environments(profiles, proc_guid):

    #cbapi does not check for guids and doesn't error correctly
    regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    if regex.match(proc_guid) == None:
        LOGGER.error("{} is not in the format of a process guid".format(proc_guid))
        return False

    stored_exceptions = []
    for profile in profiles:
        cb = CbResponseAPI(profile=profile)
        try:
            proc = cb.select(Process, proc_guid, force_init=True)
            LOGGER.info("process found in {} environment".format(profile))
            return proc
        except Exception as e:
            stored_exceptions.append((profile, str(e)))
            pass

    LOGGER.error("Didn't find this process guid in any environments. Exceptions: {}".format(stored_exceptions))
    return False


def main():

    parser = argparse.ArgumentParser(description="An interface to our CarbonBlack environments")
    profiles = auth.CredentialStore("response").get_profiles()
    parser.add_argument('-e', '--environment', choices=profiles,
                        help='specify an environment you want to work with. Default=All defined environment profiles')
    parser.add_argument('--debug', action='store_true', help='print debugging info')
    #parser.add_argument('--warnings', action='store_true',
    #                         help="Warn before printing large executions")

    subparsers = parser.add_subparsers(dest='command') #title='subcommands', help='additional help')
    cbinterface_commands = [ 'query', 'proc', 'collect', 'remediate', 'enumerate_usb', 'vxdetect']

    parser_vx = subparsers.add_parser('vxdetect', help="search cbsandbox for processes in vxstream report, show detections")
    parser_vx.add_argument('vxstream_report', help='path to vxstream report')
    parser_vx.add_argument('-p', '--print-process-tree', action='store_true', help='print the process tree')

    parser_usb = subparsers.add_parser('enumerate_usb')
    parser_usb.add_argument('sensor', help='hostname of the sensor')
    parser_usb.add_argument('-s', '--start-time', action='store',
                            help='how far back to query (default:ALL time)')

    parser_proc = subparsers.add_parser('proc', help="analyze a process GUID. 'proc -h' for more")
    parser_proc.add_argument('process', help="the process GUID to analyze")
    parser_proc.add_argument('--warnings', action='store_true',
                             help="Warn before printing large executions")
    parser_proc.add_argument('-w', '--walk-tree', action='store_true',
                             help="walk and analyze the process tree")
    parser_proc.add_argument('-d', '--detection', action='store_true',
                             help="show detections that would result in ACE alerts")
    parser_proc.add_argument('-i', '--proc-info', action='store_true',
                             help="show binary and process information")
    parser_proc.add_argument('-c','--show-children', action='store_true',
                             help="only print process children event details")
    parser_proc.add_argument('-nc', '--netconns', action='store_true',
                             help="print network connections")
    parser_proc.add_argument('-fm', '--filemods', action='store_true',
                             help="print file modifications")
    parser_proc.add_argument('-rm', '--regmods', action='store_true',
                             help="print registry modifications")
    parser_proc.add_argument('-um', '--unsigned-modloads', action='store_true',
                             help="print unsigned modloads")
    parser_proc.add_argument('-cp', '--crossprocs', action='store_true',
                             help="print crossprocs")
    parser_proc.add_argument('-intel', '--intel-hits', action='store_true',
                             help="show intel (feed/WL) hits that do not result in ACE alerts")
    parser_proc.add_argument('--no-analysis', action='store_true',
                             help="Don't fetch and print process activity")
    parser_proc.add_argument('--json', action='store_true', help='output process summary in json')

    facet_args = [
        'process_name', 'childproc_name', 'username', 'parent_name', 'path', 'hostname',
        'parent_pid', 'comms_ip', 'process_md5', 'start', 'group', 'interface_ip',
        'modload_count', 'childproc_count', 'cmdline', 'regmod_count', 'process_pid',
        'parent_id', 'os_type', 'rocessblock_count', 'crossproc_count', 'netconn_count',
        'parent_md5', 'host_type', 'last_update', 'filemod_count'
        ]
 
    parser_query = subparsers.add_parser('query',
                                         help="execute a process search query. 'query -h' for more")
    parser_query.add_argument('query', help="the process search query you'd like to execute")
    parser_query.add_argument('-s', '--start-time', action='store',
                              help="Only return processes with events after given date/time stamp\
 (server’s clock). Format:'Y-m-d H:M:S' eastern time")
    parser_query.add_argument('-e', '--end-time', action='store',
                              help="Set the maximum last update time. Format:'Y-m-d H:M:S' eastern time")
    parser_query.add_argument('--facet', action='store', choices=facet_args,
                              help='stats info on single field accross query results (ex. process_name)')
    parser_query.add_argument('--no-warnings', action='store_true',
                             help="Don't warn before printing large query results")
    parser_query.add_argument('-lh', '--logon-history', action='store_true', help="Display available logon history for given username or hostname")

    parser_collect = subparsers.add_parser('collect', help='perform LR collection tasks on a host')
    #parser_collect.add_argument('environment', choices=environments,
    #                             help="The carbonblack environment where the sensor resides.")
    parser_collect.add_argument('sensor', help="the hostname/sensor to collect from")
    parser_collect.add_argument('-f', '--filepath', action='store', help='collect file')
    parser_collect.add_argument('-c', '--command-exec', action='store', help='command to execute')
    parser_collect.add_argument('-p', '--process-list', action='store_true', 
                                help='show processes running on sensor')
    parser_collect.add_argument('-m', '--memdump', action='store', const='ALLMEM', nargs='?',
                                help='dump memory on a specific process-id')
    parser_collect.add_argument('-r', '--regkeypath', action='store',
                                help='return the value of the regkey')
    parser_collect.add_argument('-i', '--info', action='store_true', help='print sensor information')
    parser_collect.add_argument('-gst', '--get-task', action='store_true', help='get scheduled tasks or specifc task')
    parser_collect.add_argument('-mc', '--multi-collect', action='store', help='path to ini file listing files and regs to collect')

    remediate_file_example = """Example remediate ini file:
    [files]
    file1=C:\\Users\\user\\Desktop\\testfile.txt 

    [process_names]
    proc1=cmd.exe
    proc2=notepad++.exe
     
    [directories]
    directory1=C:\\Users\\user\\Desktop\\nanocore
     
    [scheduled_tasks]
    task1=\\monkey_task
    task1=\\Microsoft\\windows\\some\\flake\\task

    [pids]
    pid1=10856
     
    [registry_paths]
    reg1=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\calc
    reg2=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\hippo"""

    parser_remediate = subparsers.add_parser('remediate', help='remediate a host')
    #parser_remediate.add_argument('environment', choices=environments,
    #                              help="The carbonblack environment where the sensor resides.")
    parser_remediate.add_argument('sensor', help="the hostname/sensor needing remediation")
    parser_remediate.add_argument('-f', '--remediation-filepath',
                                  help="path to the remediation ini file; 'help' as the filepath for example")
    parser_remediate.add_argument('-dst', '--delete-scheduled-task',
                                  help="path of scheduled task to delete")
    parser_remediate.add_argument('-kpname', '--kill-process-name', help="kill all processes with this name")
    parser_remediate.add_argument('-kpid', '--kill-pid', help="a process id to kill")
    parser_remediate.add_argument('-df', '--delete-file', help="path to file needing deletion")
    parser_remediate.add_argument('-dr', '--delete-regkey', help="path to regkey value needing deletion")
    parser_remediate.add_argument('-dd', '--delete-directory', help="path to directory needing deletion")
    args = parser.parse_args()

    if args.command == 'remediate' and args.remediation_filepath == 'help':
        print(remediate_file_example)
        parser.parse_args(['remediate', '-h'])

    if args.command is None:
        print("\n\n*****")
        print("You must specify one of the following commands:\n")
        print(cbinterface_commands)
        print("\n*****\n\n")
        parser.parse_args(['-h'])

    args.debug = True
    if args.debug:
        root = logging.getLogger()
        root.addHandler(logging.StreamHandler())
        logging.getLogger("cbapi").setLevel(logging.ERROR)

    print(time.ctime() + "... starting")

    # ignore the proxy
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']

    if args.command == 'vxdetect':
        cb = CbResponseAPI(profile='vxstream')
        process_list = parse_vxstream_report(cb, args.vxstream_report)
        if args.print_process_tree:
            print()
            print(process_list)
        print()
        detections = query_vx_detection_db(process_list)
        print(" === ACE Detections ===")
        for process in process_list:
            for detection in detections[process.id]:
                print("\n\t-------------------------")
                print("  (ACE) {} on {} (PID:{}) ~ {}".format(detection, process.proc_name,
                                                      process.pid, process.id))
        print()
        return 0

    # Try and select the correct environment and perform some checks
    cb = cbash = cbvalv = None
    if args.environment:
        print("Using {} environment ..".format(args.environment))
        #credentials = auth.CredentialStore("response").get_credentials(profile=args.environment)
        cb = CbResponseAPI(profile=args.environment) 
        if args.command == 'proc':
            #cbapi does not check for guids and doesn't error correctly
            regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
            if regex.match(args.process) == None:
                LOGGER.error("{} is not in the format of a process guid".format(args.process))
                return 1
            proc = cb.select(Process, args.process, force_init=True)
    else:
        if args.command == 'proc':
            proc = proc_search_environments(profiles, args.process)
            if not proc:
                return 1
        elif args.command == 'collect' or args.command == 'remediate' or args.command == 'enumerate_usb':
            cb_results = sensor_search(profiles, args.sensor)
            if not isinstance(cb_results, list):
                # an error occured
                return cb_results
            else:
                if not cb_results:
                    LOGGER.info("A sensor with hostname {} wasn't found in any environments".format(args.sensor))
                    return 0
                elif len(cb_results) > 1:
                    LOGGER.error("A sensor by hostname {} was found in multiple environments".format(args.sensor))
                    return 1
                cb = cb_results[0]

    # Show USB Regmod activity
    if args.command == 'enumerate_usb':
        enumerate_usb(cb, args.sensor, args.start_time)

    # Process Quering #
    if args.command == 'query':
        if args.environment:
            q = CBquery(args.environment)
            q.process_query(args)
        else: # query all environments
            for profile in auth.CredentialStore("response").get_profiles():
                print("\nSearching {} environment..".format(profile))
                q = CBquery(profile=profile)
                q.process_query(args)
        return 0

    # Collection #
    if args.command == 'collect':
        return Collection(cb, args)

    # Remediation #
    if args.command == 'remediate':
        return Remediation(cb, args)

    # Process Investigation #
    process_tree = None
    if args.command == 'proc':
        process_tree = process_event_analysis(proc, args)
        
    print()
    return 0

if __name__ == "__main__":
    result = main()
    if result != 1:
        print(time.ctime() + "...Done.")
    sys.exit(result)
