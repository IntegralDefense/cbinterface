#!/usr/bin/python3

# barrowed and modified from mwilson and
# pulled from: https://github.com/IntegralDefense/integralutils/blob/master/integralutils/BaseSandboxParser.py

class ProcessWrapper():
    def __init__(self, command, pid, parent_pid, proc_name, id, is_suppressed=False):
        self.command = command
        self.pid = pid
        self.parent_pid = parent_pid
        self.proc_name = proc_name
        self.id = id
        self.is_suppressed = is_suppressed

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

    # added this proc_name item - smcfeely
    @property
    def proc_name(self):
        return self.__proc_name

    @proc_name.setter
    def proc_name(self, proc_name):
        self.__proc_name = str(proc_name)

class ProcessList():
    def __init__(self):
        self._list = []
        self.size = 0
 
    def add_process(self, new_process):
        if isinstance(new_process, ProcessWrapper):
            self._list.append(new_process)
            self.size += 1
    
    # making this object iterable - smcfeely
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
            tupled_list.append((depth, (process.command + " (PID=" + process.pid + ")")))

            if process.children:
                tupled_list = self.tuple_list(process.children, tupled_list, depth+1)

        return tupled_list

    def __str__(self, process_tree=None, text="", depth=0):
        if not process_tree:
            process_tree = self.structure()
            
        for process in process_tree:
            text += "  " * depth + " " + process.command + " (PID=" + process.pid + ")\n"

            if process.children:
                text = self.__str__(process.children, text, depth+1)

        return text
