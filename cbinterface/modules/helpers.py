
import os
import datetime
import logging

from configparser import ConfigParser
from dateutil import tz
from dateutil.zoneinfo import get_zonefile_instance

## -- Global variables -- ##
# Configuration
HOME_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
CONFIG_PATH = os.path.join(HOME_DIR, 'etc', 'config.ini')

# load the default config
CONFIG = ConfigParser()
CONFIG.read(CONFIG_PATH)
# get the default configuration file paths (allows for users to easily override settings)
# and re-load the config to account for all config items
CONFIG.read(CONFIG['DEFAULT']['config_path_list'].split(','))

DEFAULT_TIMEBASE = tz.gettz('GMT')
CONFIGURED_TIMEBASE = None
try:
   CONFIGURED_TIMEBASE = CONFIG['DEFAULT']['time_zone']
   zonenames = list(get_zonefile_instance().zones)
   if CONFIGURED_TIMEBASE not in zonenames:
       logging.error("'{}' not a recognized timezone. Using default timezone.".format(CONFIGURED_TIMEBASE))
       CONFIGURED_TIMEBASE = DEFAULT_TIMEBASE
   else:
       CONFIGURED_TIMEBASE = tz.gettz(CONFIGURED_TIMEBASE)
except Exception as e:
   logging.error("Exception occured setting CONFIGURED_TIMEZONE: {}".format(e))
   CONFIGURED_TIMEBASE = DEFAULT_TIMEBASE


## -- Global helper functions -- ##
def as_configured_timezone(timestamp):
    """Convert timestamp to the configured default timezone.
    """
    # the timestamps from CbR are not timezone aware, but they are GMT.
    _time = timestamp.replace(tzinfo=DEFAULT_TIMEBASE)
    if 'CBINTERFACE_TIMEZONE' in os.environ:
        env_timebase = os.environ['CBINTERFACE_TIMEZONE']
        zonenames = list(get_zonefile_instance().zones)
        if env_timebase not in zonenames:
            logging.error("'{}' not a recognized timezone. Using default timezone.".format(env_timebase))
            return _time.strftime('%Y-%m-%d %H:%M:%S.%f%z')
        else:
            env_timebase = tz.gettz(env_timebase)
            return _time.astimezone(env_timebase).strftime('%Y-%m-%d %H:%M:%S.%f%z')
    elif CONFIGURED_TIMEBASE is not DEFAULT_TIMEBASE:
        return _time.astimezone(CONFIGURED_TIMEBASE).strftime('%Y-%m-%d %H:%M:%S.%f%z')
    else:
        return _time.strftime('%Y-%m-%d %H:%M:%S.%f%z')

## OLD Stuff, not used anymore
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

