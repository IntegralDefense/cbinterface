#!/usr/bin/env python3

import argparse
import datetime
import glob
import json
import logging
import os
import pprint
import re
import shlex
import signal
import subprocess
import sys
import time

from configparser import ConfigParser
from dateutil import tz
from queue import Queue
from threading import Thread

from cbapi import auth
from cbapi import live_response_api
from cbapi.errors import ApiError, ObjectNotFoundError, TimeoutError, MoreThanOneResultError
from cbapi.response import *

from cbinterface.modules.helpers import as_configured_timezone, CONFIG
from cbinterface.modules.process import SuperProcess
from cbinterface.modules.query import CBquery
from cbinterface.modules.response import hyperLiveResponse

# logging 
LOGGER = logging.getLogger('cbinterface')
LOGGER.setLevel(logging.DEBUG)
LOGGER.propagate = False
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
LOGGER.addHandler(handler)


# MAX number of threads performing splunk searches
MAX_SEARCHES = 4


def clean_exit(signal, frame):
    print("\nExiting ..")
    sys.exit(0)
signal.signal(signal.SIGINT, clean_exit)


## -- TBD/WIP -- ##
def enumerate_usb(sensor, start_time=None):
    cb = sensor._cb
    host = sensor.hostname
    query_string = r'regmod:registry\machine\system\currentcontrolset\control\deviceclasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\*'
    query_string += ' hostname:{0:s}'.format(host)
    if start_time:
        query_string += ' start:{0:s}'.format(start_time)

    for proc in cb.select(Process).where(query_string):
        if proc.sensor.id != sensor.id:
            print()
            print("!WARNING! - The following process result is for a different sensor, with the same hostname: {}".format(proc.sensor.id))
        print("\n[+] Found {} - {}:".format(proc.process_name, proc.id))
        print("%s=== USB REGMODS ====" % ('  '))
        for rm in proc.regmods:
            if "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" in rm.path:
                pieces = rm.path.split("usbstor#disk&")
                if len(pieces) < 2:
                    print("WARN:::: {0}".format(str(pieces)))
                else:
                    device_info = pieces[1] #.split('{53f56307-b6bf-11d0-94f2-00a0c91efb8b}')[0]
                    print("  {}: {} {}".format(as_configured_timezone(rm.timestamp), rm.type, device_info))
                    #print(device_info)
                    

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


def LR_collection(hyper_lr, args):
    """This custom function implements a proprietary IntegralDefense Live Response collection package.
    'None' will be immediately returned if you do no have this package. The location of the package is
    assumed to be defined by a 'lr_path' variable in the configuration file.

    :dependencies lr_package_path: Path to the ID LR package on system cbinterface is running
    :dependencies streamline_path: Path to proprietary post-collection LR streamline package

    :returns: True on success, False on Failure, None if a requirement is missing
    """

    # Get configuration items
    config = CONFIG
    lr_analysis_path = config['ID-LR']['lr_package_path']
    if not os.path.exists(lr_analysis_path):
        LOGGER.info("LR package not defined")
        return None
    lr_filename = lr_analysis_path[lr_analysis_path.rfind('/')+1:]
    lr_dirname = lr_filename[:lr_filename.rfind('.')]
    sensor_dir = config['ID-LR']['sensor_path']
    if not sensor_dir:
        LOGGER.info("sensor_dir not defined in configuration. Using C:\\")
        sensor_dir = "C:\\" # Default
    streamline_path = config['ID-LR']['streamline_path']
    if not os.path.exists(streamline_path):
        LOGGER.info("Path to streamline.py doesn't exist.")
        return None    
    collect_cmd = config['ID-LR']['collect_cmd']
    if not collect_cmd:
        LOGGER.info("Collection command missing")
        return None

    lr_session = hyper_lr.go_live()

    def lr_cleanup(lr_session):
        # delete our LR tools
        try:
            dir_output = lr_session.list_directory(sensor_dir)
            for dir_item in dir_output:
                if 'DIRECTORY' in dir_item['attributes'] and dir_item['filename'] == lr_dirname:
                    print("[+] Found existing LR directory.. deleting")
                    command_str = "powershell.exe Remove-Item {} -Force -Recurse".format(sensor_dir + lr_dirname)
                    result = lr_session.create_process(command_str)
                    if result != b'':
                        LOGGER.warn(" ! Problem  deleting {}".format(sensor_dir + lr_dirname))
                if 'ARCHIVE' in dir_item['attributes'] and dir_item['filename'] == lr_filename:
                    print("[+] Existing LR package found.. deleting..")
                    try:
                        lr_session.delete_file(sensor_dir + dir_item['filename'])
                    except TypeError as e:
                        if 'startswith first arg must be bytes' in e: # might be fixed in newer cbapi versions
                            LOGGER.warn("Error deleting {}.. trying to move on".format(lr_filename))
        except live_response_api.LiveResponseError as e:
            if 'ERROR_PATH_NOT_FOUND' not in str(e):
                print("[ERROR] LiveResponseError: {}".format(e))
                return False

    # LR remnants already on host?
    lr_cleanup(lr_session)

    print("[+] Dropping latest LR on host..")
    filedata = None
    with open(lr_analysis_path, 'rb') as f: 
        filedata = f.read()
    try:
        lr_session.put_file(filedata, sensor_dir + lr_filename)
    except Exception as e:
        if 'ERROR_FILE_EXISTS' not in str(e):
            LOGGER.error("Unknown Error: {}".format(str(e)))
            return False
    
    # execute lr.exe to extract files
    # unzip = "C:\\lr.exe -o \'C:\\' -y"
    extract_cmd = " -o \'" + sensor_dir + "' -y"
    unzip = sensor_dir + lr_filename + extract_cmd
    print("[+] Extracting LR ..")
    lr_session.create_process(unzip)
    
    # execute collection
    #collect = "C:\\lr\\win32\\tools\\collect.bat"
    collect = sensor_dir + lr_dirname + collect_cmd
    collect_filename = collect_cmd[collect_cmd.rfind('\\')+1:]
    time.sleep(1)
    print("[+] Executing collect.bat..")
    start_time = time.time()
    lr_session.create_process(collect, wait_for_output=False, wait_for_completion=False) #, wait_timeout=900)
    hyper_lr.wait_for_process_to_finish(collect_filename)
    collect_duration = datetime.timedelta(minutes=(time.time() - start_time))
    print("[+] Collect completed in {}".format(collect_duration))

    # Collect resulting output file
    outputdir = sensor_dir + lr_dirname + "\\win32\\output\\"
    localfile = None
    for dir_item in lr_session.list_directory(outputdir):
        if 'ARCHIVE' in dir_item['attributes'] and  dir_item['filename'].endswith('7z'):
            # use lerc, if available
            if hyper_lr.lerc_session:
                lerc = hyper_lr.lerc_session.get_host(hyper_lr.hostname)
                command = lerc.Upload(outputdir+dir_item['filename'])
                #command = hyper_lr.lerc_session.check_command()
                # wait for client to complete the command
                print(" ~ Issued upload command to lerc. Waiting for command to finish..")
                if command.wait_for_completion():
                    print(" ~ lerc command complete. Streaming LR from lerc server..")
                    command.get_results(file_path=dir_item['filename'])
                    if command:
                        print("[+] lerc command results: ")
                        print(command)
                        file_path = command.server_file_path
                        filename = file_path[file_path.rfind('/')+1:]
                        print()
                        print("[+] Wrote {}".format(dir_item['filename']))
                        localfile = dir_item['filename']
                else:
                    LOGGER.error("problem waiting for lerc client to complete command")
            else:
                localfile = hyper_lr.getFile_with_timeout(outputdir+dir_item['filename'], localfname=dir_item['filename'])

    # Delete leftovers from sensor
    lr_cleanup(lr_session)
 
    # Call steamline on the 7z lr package
    print("[+] Starting streamline on {}".format(localfile))
    args = shlex.split(streamline_path + " " + localfile)
    subprocess.call(args, stdout=subprocess.PIPE)
    print("[+] Streamline complete")
    return True


def Remediation(sensor, args):
    #sensor = cb.select(Sensor).where("hostname:{}".format(args.sensor)).one()

    lr_session = go_live(sensor)
    if args.isolate:
        if sensor.is_isolating:
            print("[+] Removing isolation ..")
            sensor.unisolate()
        else:
            print("[+] Isolating Sensor ..")
            sensor.isolate()
        print("[+] Sensor is isolating: {}".format(sensor.is_isolating))
        return 0

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
                if isinstance(dirpath, tuple):
                    dirpath = dirpath[1] 
                command_str = "powershell.exe Remove-Item {} -Force -Recurse".format(dirpath)
                result = lr_session.create_process(command_str)
                if result == b'':
                    print(" + Deleted Directory {}".format(dirpath))
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

# handle proxy configurations as specified
# for each profile in credentials.response
HTTPS_PROXY = None
if 'https_proxy' in os.environ:
    HTTPS_PROXY = os.environ['https_proxy']

def handle_proxy(profile):
    creds = auth.FileCredentialStore("response").get_credentials(profile=profile)

    if 'ignore_system_proxy' in creds and 'https_proxy' in os.environ:
        if creds['ignore_system_proxy']:
            del os.environ['https_proxy']
        else:
            os.environ['https_proxy'] = HTTPS_PROXY
    return


## locate environment by sensor name ## 
def sensor_search(profiles, sensor_name):
    if not isinstance(profiles, list):
        LOGGER.error("profiles argument is not a list")
        return 1
    cb_finds = []
    for profile in profiles:
        LOGGER.debug("Searching {} environment".format(profile))
        handle_proxy(profile)
        cb = CbResponseAPI(profile=profile)
        try:
            sensor = cb.select(Sensor).where("hostname:{}".format(sensor_name)).one()
            cb_finds.append((sensor, profile))
            LOGGER.info("Found a sensor by this name in {} environment".format(profile))
        except TypeError as e:
            # bug in cbapi library here -> site-packages/cbapi/query.py", line 34, in one
            # Raise MoreThanOneResultError(message="0 results for query {0:s}".format(self._query))
            # That raises a TypeError 
            # https://github.com/carbonblack/cbapi-python/issues/161
            if 'non-empty format string passed to object' in str(e) or 'unsupported format string passed to dict' in str(e):
                try: # accounting for what appears to be an error in cbapi error handling
                    result = cb.select(Sensor).where("hostname:{}".format(sensor_name))
                    if isinstance(result[0], models.Sensor):
                        print()
                        LOGGER.warn("MoreThanOneResultError searching for {0:s}".format(sensor_name))
                        print("\nResult breakdown:")
                        sensor_ids = []
                        choice_string = "Which sensor do you want to use?\n"
                        for sensor in result:
                            sensor_ids.append(int(sensor.id))
                            choice_string += "\t- {}\n".format(sensor.id)
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
                        default_sid = max(sensor_ids)
                        choice_string += "\nEnter one of the sensor ids above. Default: [{}]".format(default_sid)
                        user_choice = int(input(choice_string) or default_sid)
                        for sensor in result:
                            if user_choice == int(sensor.id):
                                cb_finds.append((sensor, profile))
                    elif isinstance(result[0], None):
                        LOGGER.debug("No results for sensor query.")
                        print("here")
                    else:
                        LOGGER.error("-Unseen error condition: {}".format(e))
                except Exception as e:
                    LOGGER.debug("--Unseen error condition: {}".format(e))
            else:
                LOGGER.error("---Unseen error condition: {}".format(e), exc_info=True)
        except Exception as e:
            LOGGER.debug("Exception searching for sensor in {}".format(str(e)))
            pass
    return cb_finds


## locate environment by process guid ##
def proc_search_environments(profiles, proc_guid):

    #cbapi does not check for guids and doesn't error correctly
    regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    if regex.match(proc_guid) == None:
        LOGGER.error("{} is not in the format of a process guid".format(proc_guid))
        return False

    #stored_exceptions = []
    for profile in profiles:
        handle_proxy(profile)
        cb = CbResponseAPI(profile=profile)
        try:
            proc = cb.select(Process, proc_guid, force_init=True)
            LOGGER.info("process found in {} environment".format(profile))
            return proc
        except Exception as e:
            #stored_exceptions.append((profile, str(e)))
            pass

    LOGGER.error("Didn't find this process guid in any environments.")
    return False


def main():

    parser = argparse.ArgumentParser(description="An interface to CarbonBlack environments")

    parser.add_argument('-e', '--environment', choices=auth.FileCredentialStore("response").get_profiles(),
                        help='specify a specific instance you want to work with. If not defined \'-t production\' will be used implicitly.')
    parser.add_argument('-t', '--envtypes', type=str, 
                        help='specify any combination of envtypes. Default=All \'production\' envtypes. Ignored if -e is set.',
                        default='production')
    parser.add_argument('-tz', '--time-zone', action='store', help='specify the timezone to override defaults. ex. "US/Eastern" or "Europe/Rome"')
    #parser.add_argument('--debug', action='store_true', help='print debugging info')
    #parser.add_argument('--warnings', action='store_true',
    #                         help="Warn before printing large executions")

    subparsers = parser.add_subparsers(dest='command') #title='subcommands', help='additional help')
    cbinterface_commands = [ 'query', 'proc', 'collect', 'remediate', 'enumerate_usb', 'vxdetect']

    parser_vx = subparsers.add_parser('vxdetect', help="search cbsandbox for processes in vxstream report, show detections")
    parser_vx.add_argument('vxstream_report', help='path to vxstream report')
    parser_vx.add_argument('-p', '--print-process-tree', action='store_true', help='print the process tree')

    parser_usb = subparsers.add_parser('enumerate_usb', help="Show recent removable drive activity on the sensor")
    parser_usb.add_argument('sensor', help='hostname of the sensor')
    parser_usb.add_argument('-s', '--start-time', action='store',
                            help='how far back to query (default:ALL time)')

    parser_proc = subparsers.add_parser('proc', help="analyze a process GUID. 'proc -h' for more")
    parser_proc.add_argument('process', help="the process GUID to analyze")
    parser_proc.add_argument('--warnings', action='store_true',
                             help="Warn before printing large executions")
    parser_proc.add_argument('-w', '--walk-tree', action='store_true',
                             help="walk and analyze the process tree")
    parser_proc.add_argument('-wp', '--walk-parents', action='store_true',
                             help="print details on the process ancestry")
    #parser_proc.add_argument('-d', '--detection', action='store_true',
    #                         help="show detections that would result in ACE alerts")
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
    parser_proc.add_argument('-ml', '--modloads', action='store_true',
                             help="print modloads")
    parser_proc.add_argument('-cp', '--crossprocs', action='store_true',
                             help="print crossprocs")
    #parser_proc.add_argument('-intel', '--intel-hits', action='store_true',
    #                         help="show intel (feed/WL) hits that do not result in ACE alerts")
    parser_proc.add_argument('--no-analysis', action='store_true',
                             help="Don't fetch and print process activity")
    parser_proc.add_argument('--json', action='store_true', help='output process summary in json')
    parser_proc.add_argument('--segment-limit', action='store', type=int, default=None,
                             help='stop processing events into json after this many process segments')

    facet_args = [
        'process_name', 'childproc_name', 'username', 'parent_name', 'path', 'hostname',
        'parent_pid', 'comms_ip', 'process_md5', 'start', 'group', 'interface_ip',
        'modload_count', 'childproc_count', 'cmdline', 'regmod_count', 'process_pid',
        'parent_id', 'os_type', 'rocessblock_count', 'crossproc_count', 'netconn_count',
        'parent_md5', 'host_type', 'last_update', 'filemod_count', 'digsig_result'
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
    parser_collect.add_argument('sensor', help="the hostname/sensor to collect from")
    parser_collect.add_argument('-f', '--filepath', action='store', help='collect file')
    parser_collect.add_argument('-c', '--command-exec', action='store', help='command to execute')
    parser_collect.add_argument('-p', '--process-list', action='store_true', 
                                help='show processes running on sensor')
    parser_collect.add_argument('-m', '--memdump', action='store', const='ALLMEM', nargs='?',
                                help='dump memory on a specific process-id')
    parser_collect.add_argument('-lr', '--regkeypath', action='store',
                                help='List all registry values from the specified registry key.')
    parser_collect.add_argument('-r', '--regkeyvalue', action='store',
                                help='Returns the associated value of the specified registry key.')
    parser_collect.add_argument('-i', '--info', action='store_true', help='print sensor information')
    parser_collect.add_argument('-gst', '--get-task', action='store_true', help='get scheduled tasks or specifc task')
    parser_collect.add_argument('-mc', '--multi-collect', action='store', help='path to ini file listing files and regs to collect')
    parser_collect.add_argument('--no-lerc', default=False, action='store_true', help='Do not attempt to use a LERC for anything.')

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
    parser_remediate.add_argument('sensor', help="the hostname/sensor needing remediation")
    parser_remediate.add_argument('-i', '--isolate', help='toggle host isolation', default=False, action='store_true')
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

    #args.debug = True
    #if args.debug:
    # configure some more logging
    root = logging.getLogger()
    root.addHandler(logging.StreamHandler())
    logging.getLogger("cbapi").setLevel(logging.ERROR)
    logging.getLogger("lerc_api").setLevel(logging.WARNING)

    ''' All VxStream related stuff may be removed in a future version '''
    if args.command == 'vxdetect':
        cb = CbResponseAPI(profile='vxstream')
        process_list = parse_vxstream_report(cb, args.vxstream_report)
        if args.print_process_tree:
            print()
            print(process_list)
        print()
        return 0

    # If user set timezone
    if args.time_zone:
        # as_configured_timezone does checking
        os.environ['CBINTERFACE_TIMEZONE'] = args.time_zone

    # Set up environment profiles
    profile = None
    profiles = []
    if args.environment: 
        print("Using {} environment ..".format(args.environment))
        profiles.append(args.environment)
    else:
        # a little hack for getting our environment type variable defined
        default_profile = auth.default_profile
        default_profile['envtype'] = 'production'
        query_envtype = set(args.envtypes.lower().split(','))
        for profile in auth.FileCredentialStore("response").get_profiles():
            credentials = auth.FileCredentialStore("response").get_credentials(profile=profile)
            profile_envtype = set(credentials['envtype'].lower().split(','))
            if(query_envtype.issubset(profile_envtype)):
                profiles.append(profile)
        
        


    # Process Quering #
    if args.command == 'query':
        for profile in profiles:
            handle_proxy(profile)
            print("\nSearching {} environment..".format(profile))
            q = CBquery(profile=profile)
            q.process_query(args)
        return 0


    # Select correct environment by sensor hostname and get the sensor object
    sensor = None
    if args.command == 'collect' or args.command == 'remediate' or args.command == 'enumerate_usb':
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
                for r in cb_results:
                    print("Results:")
                    print("Profile {}: {} (SID:{})".format(r[1],r[0].hostname,r[0].id))
                return 1
            results = cb_results[0]
            profile = results[1]
            sensor = results[0]


    # Show USB Regmod activity
    if args.command == 'enumerate_usb':
        enumerate_usb(sensor, args.start_time)


    # lerc install arguments can differ by company/environment
    # same lazy hack to define in cb config
    config = {}
    try:
        default_profile = auth.default_profile
        default_profile['lerc_install_cmd'] = None
        config = auth.FileCredentialStore("response").get_credentials(profile=profile)
    except:
        pass


    # Collection #
    if args.command == 'collect':
        hyper_lr = hyperLiveResponse(sensor)

        if args.info:
            print(hyper_lr)
            return True

        # start a cb lr session
        lr_session = hyper_lr.go_live()

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
                        hyper_lr.getFile_with_timeout(filepath[1])
                    except Exception as e:
                        print("[!] Error: {}".format(str(e)))
            if full_collect == 'True':
               return False #LR_collection(hyper_lr, args)
            return True

        elif args.filepath:
            hyper_lr.getFile_with_timeout(args.filepath)

        elif args.process_list:
            hyper_lr.print_processes()

        elif args.memdump:
            # get config items
            config = CONFIG
            cb_compress = config['memory'].getboolean('cb_default_compress')
            custom_compress = config['memory'].getboolean('custom_compress')
            custom_compress_file = config['memory']['custom_compress_file']
            auto_collect_mem = config['memory'].getboolean('auto_collect_mem_file')
            lerc_collect_mem = config['memory'].getboolean('lerc_collect_mem')
            path_to_procdump = config['memory']['path_to_procdump']
            
            if args.memdump == "ALLMEM":
                return hyper_lr.dump_sensor_memory(cb_compress=cb_compress, custom_compress=custom_compress,
                                                   custom_compress_file=custom_compress_file,
                                                   auto_collect_result=auto_collect_mem)
            else:
                return hyper_lr.dump_process_memory(args.memdump, path_to_procdump=path_to_procdump)

        elif args.command_exec:
            print("executing '{}' on {}".format(args.command_exec, args.sensor))
            result = lr_session.create_process(args.command_exec, wait_timeout=60, wait_for_output=True)
            print("\n-------------------------")
            result = result.decode('utf-8')
            print(result + "\n-------------------------")
            print()

        elif args.regkeypath:
            print("\n\t{}".format(args.regkeypath))
            results = lr_session.list_registry_keys(args.regkeypath)
            for result in results:
                print("\t-------------------------")
                print("\tName: {}".format(result['value_name']))
                print("\tType: {}".format(result['value_type']))
                print("\tData: {}".format(result['value_data']))
                print()

        elif args.regkeyvalue:
            print("\n\t{}".format(args.regkeyvalue))
            result = lr_session.get_registry_value(args.regkeyvalue)
            print("\t-------------------------")
            print("\tName: {}".format(result['value_name']))
            print("\tType: {}".format(result['value_type']))
            print("\tData: {}".format(result['value_data']))
            print()

        elif args.get_task:
            return hyper_lr.get_scheduled_tasks()

        else:
            # perform full live response collection
            if not args.no_lerc:
                if config['lerc_install_cmd']:
                    result = hyper_lr.get_lerc_status()
                    if not result or result == 'UNINSTALLED' or result == 'UNKNOWN':
                       if not hyper_lr.deploy_lerc(config['lerc_install_cmd']):
                           LOGGER.warn("LERC deployment failed")
                else:
                    LOGGER.info("{} environment is not configrued for LERC deployment".format(profile))
            return LR_collection(hyper_lr, args)

    # Remediation #
    if args.command == 'remediate':
        return Remediation(sensor, args)


    # Process Investigation #
    process_tree = None
    if args.command == 'proc':
        proc = proc_search_environments(profiles, args.process)
        if not proc:
            return 1
        sp = SuperProcess(proc)
        if args.proc_info:
            print(sp)
        elif args.walk_tree:
            sp.walk_process_tree()
            print()
            print(sp.process_tree)

            for process in sp.process_tree:
                if process.is_suppressed:
                    print("+  [DATA SUPPRESSED] {} (PID:{}) - {}".format(process.name, process.pid,
                                                                         process.id))
                    continue

                print("+  {} (PID:{}) - {}".format(process.name, process.pid, process.id))
                if args.filemods:
                    process.print_filemods()
                    args.no_analysis = True
                if args.netconns:
                    process.print_netconns()
                    args.no_analysis = True
                if args.regmods:
                    process.print_regmods()
                    args.no_analysis = True
                if args.unsigned_modloads:
                    process.print_unsigned_modloads()
                    args.no_analysis = True
                if args.modloads:
                    process.print_modloads()
                    args.no_analysis = True
                if args.crossprocs:
                    process.print_crossprocs()
                    args.no_analysis = True
                if args.walk_parents:
                    sp.show_ancestry()
                    args.no_analysis = True
                if args.no_analysis != True:
                    if args.json:
                        if args.segment_limit:
                            print(process.events_to_json(segment_limit=args.segment_limit))
                        else:
                            print(process.events_to_json())
                    else:
                        process.default_print()
        else:
            print()
            print(sp.process_tree)
            if args.walk_parents:
                sp.show_ancestry()
                args.no_analysis = True
            if args.filemods:
                sp.print_filemods()
                args.no_analysis = True
            if args.netconns:
                sp.print_netconns()
                args.no_analysis = True
            if args.regmods:
                sp.print_regmods()
                args.no_analysis = True
            if args.unsigned_modloads:
                sp.print_unsigned_modloads()
                args.no_analysis = True
            if args.modloads:
                sp.print_modloads()
                args.no_analysis = True
            if args.crossprocs:
                sp.print_crossprocs()
                args.no_analysis = True
            if args.show_children:
                sp.print_child_events()
                args.no_analysis = True

            if args.no_analysis != True:
                if args.json:
                    if args.segment_limit:
                        print(sp.events_to_json(segment_limit=args.segment_limit))
                    else:
                        print(sp.events_to_json())
                else:
                    sp.default_print()

        
    print()
    return True

if __name__ == "__main__":
    print(time.ctime() + "... starting")
    result = main()
    if result:
        print(time.ctime() + "... Done.")
    sys.exit(result)
