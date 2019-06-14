#/usr/bin/python3

import os
import logging
import datetime

from cbapi.response import models
from cbapi.errors import ApiError, ObjectNotFoundError, TimeoutError, MoreThanOneResultError

from .helpers import CONFIG, as_configured_timezone


class ProcessWrapper():
    def __init__(self, process, suppressed_data={}):
        if not isinstance(process, models.Process):
            raise Exception("process must be cbapi.response.models.Process")
        self.proc = process
        if suppressed_data:
            self.command = suppressed_data['cmdline']
            self.pid = suppressed_data['pid']
            self.parent_pid = suppressed_data['parent_pid']
            self.name = suppressed_data['process_name']
            self.id = suppressed_data['id']
            self.is_suppressed = True
        else:
            self.command = self.proc.cmdline
            self.pid = self.proc.process_pid
            self.parent_pid = self.proc.parent_pid
            self.name = self.proc.process_name
            self.id = self.proc.id
            self.is_suppressed = False

    @property
    def is_suppressed(self):
        return self.__is_suppressed

    @is_suppressed.setter
    def is_suppressed(self, is_suppressed):
        self.__is_suppressed = bool(is_suppressed)

    @property
    def id(self):
        return self.__id
    
    @id.setter
    def id(self, id):
        self.__id = str(id)

    @property
    def command(self):
        return self.__command
    
    @command.setter
    def command(self, command):
        if isinstance(command, str):
            self.__command = command
        else:
            self.__command = ""
            
    @property
    def pid(self):
        return self.__pid
    
    @pid.setter
    def pid(self, pid):
        self.__pid = str(pid)
        
    @property
    def parent_pid(self):
        return self.__parent_pid
    
    @parent_pid.setter
    def parent_pid(self, parent_pid):
        self.__parent_pid = str(parent_pid)

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = str(name)

    def show_ancestry(self):
        def _print_parent_details(proc, depth):
            try:
                start_time = proc.start or "<unknown>"
                print("%s%s:  %s %s - %s" % ('  '*(depth + 1), start_time, proc.cmdline,
                                             "(suppressed)" if proc.suppressed_process else "", proc.id))
            except Exception as e:
                return
        print("  === Process Ancestry ===\n")
        self.proc.walk_parents(_print_parent_details)

    def events_to_json(self, segment_limit=None):
        """Attempt to build a comprehensive json document for this process.
        Note: This can be problematic for excessivly large processes. 

        :param int segment_limit: Stop building the document after this many process segments.
        :return: A dictionary of process events and details.
        """
        process_raw_sum_data = self.proc._cb.get_object("/api/v1/process/{0}".format(self.proc.id))
        process_summary = process_raw_sum_data['process']
        process_summary['parent'] = process_raw_sum_data['parent']
        start_time = process_summary['start'].replace('T', ' ')
        start_time = start_time.replace('Z','')
        try:
            start_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError as e:
            logging.info("Unexpected result. Probably incomplete process data.")
        process_summary['start'] = (start_time)
        process_summary['filemods'] = []
        process_summary['regmods'] = []
        process_summary['unsigned_modloads'] = []
        process_summary['netconns'] = []
        process_summary['crossprocs'] = []
        process_summary['children'] = []
        process_summary['segment_count'] = len(self.proc.get_segments())

        if segment_limit and not isinstance(segment_limit, int):
            raise TypeError("segment_limit is not an integer.")
       
        process_summary['segments_processed'] = 0
        for segment in self.proc.get_segments():
            if segment_limit:
                if process_summary['segments_processed'] > segment_limit:
                    break

            self.proc.current_segment = segment

            for nc in self.proc.netconns:
                nc_dict = { 'timestamp': str((nc.timestamp)), 'domain': nc.domain,
                            'remote_ip': nc.remote_ip, 'remote_port': nc.remote_port,
                            'proto': nc.proto, 'direction': nc.direction, 'local_ip': nc.local_ip,
                            'local_port': nc.local_port, 'proxy_ip': nc.proxy_ip,
                            'proxy_port': nc.proxy_port, 'segment': segment }
                process_summary['netconns'].append(nc_dict)

            for child in self.proc.children:
                child = { 'timestamp': str((child.timestamp)), 'procguid': child.procguid,
                          'pid': child.pid, 'path': child.path, 'md5': child.md5, 'segment': segment }
                process_summary['children'].append(child)

            for fm in self.proc.filemods:
                fm_dict = { 'timestamp': str((fm.timestamp)), 'type': fm.type, 'path': fm.path,
                            'filetype': fm.filetype, 'md5': fm.md5, 'segment': segment }
                # note we can also cb.select the md5 and see if it's signed, etc.
                process_summary['filemods'].append(fm_dict)

            for rm in self.proc.regmods:
                rm_dict = { 'timestamp': str((rm.timestamp)), 'type': rm.type,
                            'path': rm.path, 'segment': segment }
                process_summary['regmods'].append(rm_dict)

            for ml in self.proc.unsigned_modloads:
                unsml_dict = { 'timestamp': str((ml.timestamp)), 'md5': ml.md5,
                               'path': ml.path, 'segment': segment }
                process_summary['unsigned_modloads'].append(unsml_dict)

            for crossp in self.proc.crossprocs:
                cp_dict = { 'timestamp': str((crossp.timestamp)), 'type': crossp.type,
                            'privileges': crossp.privileges, 'target_md5': crossp.target_md5,
                            'target_path': crossp.target_path, 'segment': segment,
                            'source_path': crossp.source_path, 'source_web_link': crossp.source_proc.webui_link,
                            'target_web_link': crossp.target_proc.webui_link, 'source_proc_guid': crossp.source_proc.id,
                            'target_proc_guid': crossp.target_proc.id, 'source_md5': crossp.source_md5}
                process_summary['crossprocs'].append(cp_dict)

            process_summary['segments_processed'] += 1

        return process_summary


    def print_filemods(self):
        print("%s=== FILEMODS ====" % ('  '))
        for segment in self.proc.get_segments():
            self.proc.current_segment = segment
            for fm in self.proc.filemods:

                signed = ""
                product_name = ""
                if fm.type != "CreatedFile" and fm.md5:
                    try:
                        b = self.proc._cb.select(models.Binary, fm.md5)
                        signed = b.signed
                        product_name = b.product_name
                        print("%s%s: %s: %s , type:%s , md5:%s, signed:%s, product_name:%s" % ('  ',
                              as_configured_timezone(fm.timestamp), fm.type, fm.path, fm.filetype,
                              fm.md5, signed, product_name))
                    except ObjectNotFoundError:
                        print("%s%s: %s: %s , type:%s , md5:%s" % ('  ', as_configured_timezone(fm.timestamp),
                              fm.type, fm.path, fm.filetype, fm.md5))
                elif fm.type != "CreatedFile":
                    if fm.filetype != "Unknown":
                        print("%s%s: %s: %s , type:%s" % ('  ', as_configured_timezone(fm.timestamp), fm.type, fm.path, fm.filetype))
                    else:
                        print("%s%s: %s: %s" % ('  ', as_configured_timezone(fm.timestamp), fm.type, fm.path))
        print()


    def print_netconns(self):
        print("%s=== NETCONNS ====" % ('  '))
        for segment in self.proc.get_segments():
            self.proc.current_segment = segment
            for nc in self.proc.netconns:
                print("  {}: ({}) local/proxy IP:{}/{} remote IP:{} remote port:{} domain:{}".format(as_configured_timezone(nc.timestamp),
                                                                                nc.direction, nc.local_ip, nc.proxy_ip, nc.remote_ip,
                                                                                nc.remote_port, nc.domain))
        print()


    def print_regmods(self):
        print("  === REGMODS ====")
        for segment in self.proc.get_segments():
            self.proc.current_segment = segment
            for rm in self.proc.regmods:
                print("  {}: {} {}".format(as_configured_timezone(rm.timestamp), rm.type, rm.path))
        print()


    def print_modloads(self):
        print("%s=== MODLOADS ====" % ('  '))
        for segment in self.proc.get_segments():
            self.proc.current_segment = segment
            for modload in self.proc.modloads:
                sig_status = 'signed' if modload.is_signed else 'unsigned'
                print("  {}: ({}) {} , md5:{}".format(as_configured_timezone(modload.timestamp),
                                                      sig_status, modload.path, modload.md5))
        print()

    def print_unsigned_modloads(self):
        print("%s=== UNSIGNED MODLOADS ====" % ('  '))
        for segment in self.proc.get_segments():
            self.proc.current_segment = segment
            for unmodload in self.proc.unsigned_modloads:
                print("  {}: {} , md5:{}".format(as_configured_timezone(unmodload.timestamp),
                                                 unmodload.path, unmodload.md5))
        print()

    def print_crossprocs(self):
        print("%s=== CROSSPROCS ====" % ('  '))
        for segment in self.proc.get_segments():
            self.proc.current_segment = segment
            for cross in self.proc.crossprocs:
                print("  {} | {} | {} -> {} | {} -> {}".format(as_configured_timezone(cross.timestamp),
                                                               cross.type,
                                                               cross.source_path,
                                                               cross.target_path,
                                                               cross.source_proc.id,
                                                               cross.target_proc.id))
                print()
        print()


    def print_child_events(self):
        print("  == CHILDPROC Start/End Events ==")
        children = {}
        # group childproc events together for printing
        for childproc in self.proc.children:
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
                print("  {}: {} (PID={}) - {}".format(as_configured_timezone(c.timestamp),
                                                      c.path,
                                                      c.pid,
                                                      c.procguid))
            print()


    def default_print(self):
        self.print_filemods()
        self.print_netconns()
        self.print_regmods()
        self.print_unsigned_modloads()
        self.print_crossprocs()


    def __str__(self):
        binary_vinfo = None
        binary_sdata = None
        binary_vt = None
        try:
            binary_vinfo = self.proc.binary.version_info
            binary_sdata = self.proc.binary.signing_data
            binary_vt = self.proc.binary.virustotal
        except AttributeError as e:
            logging.info("Missing binary attributes from Cb data: {}".format(e))
        text = ""
        text += "\n\t-------------------------\n"
        text += "\tProcess Name: {}\n".format(self.proc.process_name)
        text += "\tProcess PID: {}\n".format(self.proc.process_pid)
        text += "\tProcess Start: {}\n".format(as_configured_timezone(self.proc.start))
        text += "\tProcess MD5: {}\n".format(self.proc.process_md5)
        text += "\tCommand Line: {}\n".format(self.proc.cmdline)
        text += "\tParent Name: {}\n".format(self.proc.parent_name)
        text += "\tParent GUID: {}\n".format(self.proc.parent_id)
        text += "\tHostname: {}\n".format(self.proc.hostname)
        text += "\tUsername: {}\n".format(self.proc.username)
        text += "\tComms IP: {}\n".format(self.proc.comms_ip)
        text += "\tInterface IP: {}\n".format(self.proc.interface_ip)
        try:
            text += "\tBinary Description: {}\n".format(binary_vinfo.file_desc)
            text += "\tProduct Name: {}\n".format(binary_vinfo.product_name)
            text += "\tDigital Copyright: {}\n".format(binary_vinfo.legal_copyright)
            text += "\tOriginal filename: {}\n".format(binary_vinfo.original_filename)
            text += "\tSigned Status: {}\n".format(binary_sdata.result)
            text += "\tSignature Publisher: {}\n".format(binary_sdata.publisher)
            text += "\tSignature Issuer: {}\n".format(binary_sdata.issuer)
            text += "\tSignature Subject: {}\n".format(binary_sdata.subject)
            text += "\tVirusTotal Score: {}\n".format(binary_vt.score)
            text += "\tVirusTotal Link: {}\n".format(binary_vt.link)
        except AttributeError as e:
            pass
        text += "\tGUI Link: {}\n".format(self.proc.webui_link)
        return text


class ProcessList():
    def __init__(self):
        self._list = []
        self.size = 0
 
    def add_process(self, new_process):
        if isinstance(new_process, ProcessWrapper):
            self._list.append(new_process)
            self.size += 1
    
    def __getitem__(self, index):
        result = self._list[index]
        return result

    def structure(self):
        # Operate on a copy of the list.
        tree = self._list[:]
        
        # Get a list of process ID's.
        pid_list = [proc.pid for proc in tree]
    
        # Get a list of the "root" process ID's.
        root_pids = [proc.pid for proc in tree if proc.parent_pid not in pid_list]
        
        # Loop over the process list.
        for process in tree:
            # Set the "children" equal to a list of its child PIDs.
            process.children = [proc for proc in tree if proc.parent_pid == process.pid]
            
        # At this point we have some duplicate elements in self._list that
        # appear at the root process level that need to be removed.
        return [proc for proc in tree if proc.pid in root_pids]

    def tuple_list(self, process_tree=None, tupled_list=None, depth=0):
        if not process_tree:
            process_tree = self.structure()

        if tupled_list is None: tupled_list = []

        for process in process_tree:
            if depth > CONFIG['DEFAULT'].getint('max_recursive_depth'):
                # Preventing maximum recursion depth exceeded RunTime error
                tupled_list.append((depth, "WARNING: This Process Tree exceeded the configured Maximum Recursive Depth. Not Proceeding."))
                logging.warn("Process Tree exceeded the configured Maximum Recursive Depth.")
                return tupled_list

            tupled_list.append((depth, (process.command + " (PID=" + process.pid + ")")))

            if process.children:
                tupled_list = self.tuple_list(process.children, tupled_list, depth+1)

        return tupled_list

    def __str__(self, process_tree=None, text="", depth=0):
        if not process_tree:
            process_tree = self.structure()
            
        max_depth = False
        for process in process_tree:
            if depth > CONFIG['DEFAULT'].getint('max_recursive_depth'):
                # Preventing maximum recursion depth exceeded RunTime error
                max_depth = True
                logging.warn("Process Tree exceeded the configured Maximum Recursive Depth.")
                return text

            text += "  " * depth + " " + process.command + " (PID=" + process.pid + ")\n"

            if process.children:
                text = self.__str__(process.children, text, depth+1)

        if max_depth:
            text = "WARNING: This Process Tree exceeded the configured Maximum Recursive Depth, at least once.\n\n" + text
        return text


## -- Process analysis functions -- ##
class SuperProcess(ProcessWrapper):#models.Process):

    def __init__(self, process):
        super().__init__(process)
        self.process_tree = ProcessList()
        self.process_tree.add_process(self)


    def walk_process_tree(self):
        def crawler(process_list, proc, depth=0):
            childguids = []
            for childproc in proc.children:
                if childproc.procguid not in childguids:
                    childguids.append(childproc.procguid)

                    # Get all events by selecting the process (CbChildProcEvent != Process)
                    cProc = self.proc._cb.select(models.Process, self.proc._cb.select(models.Process, childproc.procguid).id)
                    if childproc.is_suppressed:
                        data = {'cmdline': "[DATA SUPPRESSED] "+childproc.proc_data['cmdline'],
                                'pid': childproc.pid,
                                'parent_pid': proc.process_pid,
                                'process_name': childproc.path,
                                'id': childproc.procguid}
                        process_list.add_process(ProcessWrapper(cProc, suppressed_data=data))
                    elif depth > CONFIG['DEFAULT'].getint('max_recursive_depth'):
                        logging.debug("Process Tree exceeded the configured Maximum Recursive Depth.")
                        return process_list
                    else:
                        process_list.add_process(ProcessWrapper(cProc))
                        crawler(process_list, cProc, depth+1)

            return process_list

        self.process_tree = crawler(self.process_tree, self.proc)

        return self.process_tree
