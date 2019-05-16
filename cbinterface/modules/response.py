
import os
import sys
import time
import atexit
import pprint
import logging
import datetime
from cbapi.response import models
from cbapi.live_response_api  import LiveResponseError
from cbapi.errors import TimeoutError

logging.getLogger(__name__)

try:
    from lerc_control import lerc_api
    from lerc_control.deploy_lerc import deploy_lerc as lerc_deployment
except:
    logging.debug("failed to import lerc_control. Will fallback to pure cb live response")


## -- Live Response (collect/remediate) -- ##
class hyperLiveResponse():

    lr_session = None
    lerc_session = None
    lerc_status = None

    def _close_lr_session(self):
        if self.lr_session:
            self.lr_session.close()

    def __init__(self, sensor):
        if not isinstance(sensor, models.Sensor):
            raise Exception("sensor is no cbapi.response.models.Sensor")
        self.sensor = sensor
        self.hostname = self.sensor.hostname
        atexit.register(self._close_lr_session)

    def go_live(self):
        if self.lr_session:
            return self.lr_session
        start_time = time.time()
        timeout = 604800 # seven days
        current_day = 0
        if self.sensor.status == 'Offline':
            print("Waiting for sensor to come online..")
        while time.time() - start_time < timeout:
            try:
                self.lr_session = self.sensor.lr_session()
                print("[+] LR session started at {}".format(time.ctime()))
                break
            except TimeoutError:
                elapsed_time = time.time() - start_time
                if current_day != elapsed_time // 86400:
                    current_day+=1
                    print("24 hours of timeout when polling for LR session")
                    print("Attempting LR session again on {} @ {}".format(self.hostname,
                                                                          time.ctime()))
        return self.lr_session


    def getFile_with_timeout(self, filepath, localfname=None):
        # THIS FUNCTION is no longer neccessary as a timeout argument was introduced
        # to the CbLRSessionBase.get_file(self, file_name, timeout=None, delay=None)

        # Make sure we're live
        self.go_live()

        print("~ downloading {}".format(filepath))
        raw = self.lr_session.get_raw_file(filepath, timeout=3600)
        content = raw.read()
        raw.close()
        if localfname is None:
            localfname = self.sensor.computer_name + '_' + filepath.rsplit("\\",1)[1]
        with open(localfname,'wb') as f:
            f.write(content)
        print("+ wrote {}".format(localfname))
        return localfname


    def wait_for_process_to_finish(self, process_name):
        # THIS FUNCTION is no longer neccessary as of cbapi==1.3.3
        # https://github.com/carbonblack/cbapi-python/issues/97

        self.go_live()

        print(" - checking if "+process_name+" is running")
        running = None

        for process in self.lr_session.list_processes():
            if process_name in process['command_line']:
                running = True
                print(" - {} still running..".format(process_name))

        if running:
            print(" - waiting for {} to finish...".format(process_name))
            while(running):
                time.sleep(30)
                running = False
                for process in self.lr_session.list_processes():
                    if process_name in process['command_line']:
                        running = True
                        print(" - {} still running..".format(process_name))

        return


    def get_lerc_status(self):

        if 'lerc_control.lerc_api' not in sys.modules.keys():
            return False

        if self.lerc_session is None:
            self.lerc_session = lerc_api.lerc_session()
        ls = self.lerc_session

        try:
            client = ls.get_host(self.hostname)
            if client:
                self.lerc_status = client.status
                return self.lerc_status
            else:
                logging.debug("No lerc by hostname '{}'".format(self.hostname))
                return False
        except:
            logging.debug("Can't reach the lerc control server")
        return None


    def deploy_lerc(self, install_cmd, lerc_installer_path=None):
        return lerc_deployment(self.sensor, install_cmd, lerc_installer_path)


    def __str__(self):
        text = "\n"
        text += "Sensor object - {}\n".format(self.sensor.webui_link)
        text += "-------------------------------------------------------------------------------\n"
        text += "\tcb_build_version_string: {}\n".format(self.sensor.build_version_string)
        text += "\tcomputer_sid: {}\n".format(self.sensor.computer_sid)
        text += "\tcomputer_dns_name: {}\n".format(self.sensor.computer_dns_name)
        text += "\tcomputer_name: {}\n".format(self.sensor.computer_name)
        text += "\tos_environment_display_string: {}\n".format(self.sensor.os_environment_display_string)
        text += "\tphysical_memory_size: {}\n".format(self.sensor.physical_memory_size)
        text += "\tsystemvolume_free_size: {}\n".format(self.sensor.systemvolume_free_size)
        text += "\tsystemvolume_total_size: {}\n".format(self.sensor.systemvolume_total_size)
        text += "\n"
        text += "\tstatus: {}\n".format(self.sensor.status)
        text += "\tis_isolating: {}\n".format(self.sensor.is_isolating)
        text += "\tsensor_id: {}\n".format(self.sensor.id)
        text += "\tlast_checkin_time: {}\n".format(self.sensor.last_checkin_time)
        text += "\tnext_checkin_time: {}\n".format(self.sensor.next_checkin_time)
        text += "\tsensor_health_message: {}\n".format(self.sensor.sensor_health_message)
        text += "\tsensor_health_status: {}\n".format(self.sensor.sensor_health_status)
        text += "\tnetwork_interfaces:\n"
        for ni in self.sensor.network_interfaces:
            text += "\t\t{}\n".format(ni)
        #if self.get_lerc_status():
        #    text += "\n\tLERC Status:\n"
        #    text += "\t\tClient installed at '{}' - status={} - last check-in='{}'\n".format(self.hostname,
        #            self.lerc_status['install_date'], self.lerc_status['status'], self.lerc_status['last_activity'])
        #if self.sensor.status == "Online":
        #    text += "\n\t+ Tring to get logical drives..\n"
        #    if not self.lr_session:
        #        try:
        #            self.go_live()
        #        except Exception as e:
        #            raise Exception("Failed to Go Live on sensor: '{}'".format(str(e)))
        #    text += "\t\tAvailable Drives: %s" % ' '.join(self.lr_session.session_data.get('drives', []))
        #    text += "\n"
        return text


    def print_processes(self):
        print("~ obtaining running process data..")
        for process in self.lr_session.list_processes():
            pname = process['path'][process['path'].rfind('\\')+1:]
            print("\n\t-------------------------")
            print("\tProcess: {} (PID: {})".format(pname, process['pid']))
            #print("\tProcID: {}".format(process['pid']))
            print("\tGUID: {}".format(process['proc_guid']))
            print("\tUser: {}".format(process['username']))
            print("\tCommand: {}".format(process['command_line']))
        print()


    def dump_sensor_memory(self, cb_compress=False, custom_compress=False, custom_compress_file=None, auto_collect_result=False):
        """Customized function for dumping sensor memory.

        :arguments cb_compress: If True, use CarbonBlack's built-in compression.
        :arguments custom_compress_file: Supply path to lr_tools/compress_file.bat to fork powershell compression
        :collect_mem_file: If True, wait for memdump + and compression to complete, then use cbapi to collect
        """

        print("~ dumping contents of memory on {}".format(self.sensor.computer_name))
        local_file = remote_file = "{}.memdmp".format(self.sensor.computer_name)
        if not self.lr_session:
            self.go_live()
        try:
            if cb_compress and auto_collect_result:
                logging.info("CB compression and auto-collection set")
                self.lr_session.memdump(remote_filename=remote_file, compress=cb_compress)
                return True
            dump_object = self.lr_session.start_memdump(remote_filename=remote_file, compress=cb_compress)
            dump_object.wait()
            if cb_compress:
               print("+ Memory dump compressed at -> C:\windows\carbonblack\{}.zip".format(remote_file))
               if auto_collect_result:
                   self.getFile_with_timeout("C:\\Windows\\CarbonBlack\\{}.zip".format(remote_file))
               return True
            print("+ Memory dump complete on host -> C:\windows\carbonblack\{}".format(remote_file))
        except LiveResponseError as e:
            raise Exception("LiveResponseError: {}".format(e))

        if custom_compress: # compress with powershell?
            if not os.path.exists(custom_compress_file):
                logging.debug("{} not found.".format(custom_compress_file))
                HOME_DIR = os.path.abspath(os.path.join(os.path.realpath(__file__),'..','..'))
                custom_compress_file = os.path.join(HOME_DIR, 'lr_tools', 'compress_file.bat')
                if not os.path.exists(custom_compress_file):
                    logging.error("{} not found.".format(custom_compress_file))
                    return False
            logging.info("Using {}".format(custom_compress_file))

            bat_filename = custom_compress_file[custom_compress_file.rfind('/')+1:]
            filedata = None
            with open(custom_compress_file, 'rb') as f:
                filedata = f.read()
            try:
                self.lr_session.put_file(filedata, "C:\\Windows\\CarbonBlack\\" + bat_filename)
            except LiveResponseError as e:
                if 'ERROR_FILE_EXISTS' not in str(e):
                    logging.error("Error puting compress_file.bat")
                    return False
                else:
                    self.lr_session.delete_file("C:\\Windows\\CarbonBlack\\" + bat_filename)
                    self.lr_session.put_file(filedata, "C:\\Windows\\CarbonBlack\\" + bat_filename)
            print("~ Launching "+ bat_filename +" to create C:\\windows\\carbonblack\\_memdump.zip")
            compress_cmd = "C:\\Windows\\CarbonBlack\\" + bat_filename  + " " + remote_file
            self.lr_session.create_process(compress_cmd, wait_for_output=False, wait_for_completion=False)
            if auto_collect_result:
                print("~ waiting for {} to complete.".format(bat_filename))
                self.wait_for_process_to_finish(bat_filename)
                self.getFile_with_timeout("C:\\windows\\carbonblack\\_memdump.zip")
            print("[!] If compression successful, _memdump.zip will exist, and {} should be deleted.".format(remote_file))
        # here, they didn't want to use cb or custom compression, but they did want to auto collect results
        if auto_collect_result:
            self.getFile_with_timeout("C:\\Windows\\CarbonBlack\\{}".format(remote_file))
        return True


    def dump_process_memory(self, pid, working_dir="c:\\windows\\carbonblack\\", path_to_procdump=None):
        """Use sysinternals procdump to dump process memory on a specific process. If only the pid is specified, the default
        behavior is to use the version of ProcDump supplied with cbinterface's pip3 installer.

        :requires: SysInternals ProcDump v9.0 included with cbinterface==1.1.0
        :arguments pid: Process id to dump memory for
        :arguments working_dir: Specify a directoy on the windows sensor to work out of. Default: C:\\Windows\\CarbonBlack\\
        :arguments path_to_procdump: Specify the path to a version of procdump you want to use. Default is included copy
        """

        self.go_live()

        print("~ dumping memory where pid={} for {}".format(pid, self.sensor.computer_name))
        # need to make sure procdump.exe is on the sensor
        procdump_host_path = None
        dir_output = self.lr_session.list_directory(working_dir)
        for dir_item in dir_output:
            if dir_item['filename'] == 'procdump.exe':
                logging.info("procdump.exe already on host.")
                procdump_host_path = working_dir + "procdump.exe"
                break
        else:
            logging.info("Dropping procdump.exe on host.")

        if not procdump_host_path:
            if not os.path.exists(path_to_procdump):
                HOME_DIR = os.path.abspath(os.path.join(os.path.realpath(__file__),'..','..'))
                path_to_procdump = os.path.join(HOME_DIR, 'lr_tools', 'procdump.exe')
                if not os.path.exists(path_to_procdump):
                    logging.warn("{} not found".format(path_to_procdump))
                    return False

            print("~ dropping procdump.exe on host.")
            filedata = None
            with open(path_to_procdump, 'rb') as f:
                filedata = f.read()
            try:
                self.lr_session.create_directory(working_dir)
            except LiveResponseError:
                logging.debug("working directory already exists")
            self.lr_session.put_file(filedata, working_dir + "procdump.exe")
            procdump_host_path = working_dir + "procdump.exe"

        print("~ Executing procdump..")
        command_str = procdump_host_path + " -accepteula -ma " + str(pid)
        result = self.lr_session.create_process(command_str)
        time.sleep(1)
        print("+ procdump output:\n-------------------------")
        result = result.decode('utf-8')
        print(result + "\n-------------------------")

        # cut off the carriage return and line feed from filename 
        dumpfile_name = result[result.rfind('\\')+1:result.rfind('.dmp')+4]
        while True:
            if 'procdump.exe' not in str(self.lr_session.list_processes()):
                break
            else:
                time.sleep(1)
        # download dumpfile to localdir
        self.getFile_with_timeout(working_dir + dumpfile_name)


    def get_scheduled_tasks(self, schtask_ps_path=None, working_dir="C:\\windows\\carbonblack\\"):
        print("[+] Making scheduledTaskOps.ps1 available on host.")
        if schtask_ps_path is None:
            HOME_DIR = os.path.abspath(os.path.join(os.path.realpath(__file__),'..','..'))
            schtask_ps_path = os.path.join(HOME_DIR, 'lr_tools', 'scheduledTaskOps.ps1')

        filedata = None
        with open(schtask_ps_path, 'rb') as f:
            filedata = f.read()
        try:
            self.lr_session.put_file(filedata, working_dir + "scheduledTaskOps.ps1")
            print("[+] Dropped scheduledTaskOps.ps1.")
        except LiveResponseError as e:
            if "ERROR_FILE_EXISTS" in str(e):
                print("[+] scheduledTaskOps.ps1 already on host.")
            else:
                logging.error(str(e))
                return False

        # execute
        cmd = "powershell.exe -ExecutionPolicy Bypass -File " + working_dir + "scheduledTaskOps.ps1 -Get"
        print("[+] Executing: {}".format(cmd))
        result = self.lr_session.create_process(cmd)
        result = result.decode('utf-8')
        print("[+] Execution Results:\n-------------------------")
        print(result + "\n-------------------------")
        print()
        return True

