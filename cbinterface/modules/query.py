
import datetime
import logging
from dateutil import tz
from cbapi.response import *
from .helpers import eastern_time


## -- Process querying functions -- ##
class CBquery():
    cb = None
    LOGGER = logging.getLogger(__name__)

    def __init__(self, profile=None):
        self.cb = CbResponseAPI(profile=profile) if profile else CbResponseAPI()

    def print_facet_histogram(self, facets):
        total_results = sum([entry['value'] for entry in facets])
        #longest_process_name = len(max(process_names, key=len))
        print("\n\t\t\tTotal results: {}".format(total_results))
        print("\t\t\t--------------------------")
        for entry in facets:
            print("%50s: %5s %5s%% %s" % (entry["name"][:45], entry['value'], entry["ratio"],
                  u"\u25A0"*(int(entry['percent']/2))))
        return


    def process_query(self, args):
        processes = None
        if args.logon_history:
            # Requiring that user input specifies the username or hostname field, because I'm lazy today
            query = "process_name:userinit.exe parent_name:winlogon.exe {}".format(args.query)
            processes = self.cb.select(Process).where(query).group_by('id')
            print("\n\tEastern Time\t|\tUsername\t|\tHostname")
            for proc in processes:
                start_time = str(eastern_time(proc.start))
                start_time = start_time[:start_time.rfind('.')]
                print("  {}\t    {}\t\t{}".format(start_time, proc.username, proc.hostname))
            print()
            return

        if args.start_time:
            try:
                start_time = datetime.datetime.strptime(args.start_time, '%Y-%m-%d %H:%M:%S')
            except Exception as e:
                raise e

            start_time = start_time.replace(tzinfo=tz.gettz('America/New_York')).astimezone(tz.gettz('UTC'))

            if args.end_time:
                try:
                    end_time =  datetime.datetime.strptime(args.end_time, '%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    raise e
                end_time = end_time.replace(tzinfo=tz.gettz('America/New_York')).astimezone(tz.gettz('UTC'))
                processes = self.cb.select(Process).where(args.query).group_by('id').min_last_server_update(start_time).max_last_server_update(end_time)
            else:
                processes = self.cb.select(Process).where(args.query).group_by('id').min_last_server_update(start_time)
        else:
            processes = self.cb.select(Process).where(args.query).group_by('id')

        # note, getting the len of the process query object doesn't account for our 'group_by('id')'
        # instead, len() returns the number of process segments returned
        process_name_facet = processes.facets('process_name')['process_name']
        #total_unique_processes = sum([process['value'] for process in process_name_facet])

        if args.facet:
            if args.facet == 'process_name':
                self.print_facet_histogram(process_name_facet)
            else:
                self.print_facet_histogram(processes.facets(args.facet)[args.facet])

        print("\n{} process segments returned by the query,".format(len(processes)))
        #print(" from approximately {} unique processes".format(total_unique_processes))

        print_results = True
        #if total_unique_processes > 10:
        if len(processes) > 10 and args.no_warnings != True:
            print_results = input("Print all results? (y/n) [y] ") or 'y'
            print_results = True if print_results == 'y' else False

        if print_results and len(processes) > 0:
            for proc in processes:
                print("\n\t-------------------------")
                print("\tProcess GUID: {}".format(proc.id))
                print("\tProcess Name: {}".format(proc.process_name))
                print("\tProcess PID: {}".format(proc.process_pid))
                print("\tProcess MD5: {}".format(proc.process_md5))
                print("\tCommand Line: {}".format(proc.cmdline))
                print("\tParent Name: {}".format(proc.parent_name))
                print("\tHostname: {}".format(proc.hostname))
                print("\tUsername: {}".format(proc.username))
                print("\tStart Time: {}".format(eastern_time(proc.start)))
                print("\tGUI Link: {}".format(proc.webui_link))
            print()
        return

