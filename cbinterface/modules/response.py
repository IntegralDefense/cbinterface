
import sys
import time
import logging
import datetime
from cbapi.response import models 

logging.getLogger(__name__)

try:
    from ..library import lerc_api
except:
    logging.debug("failed to import lerc_api. Will fallback to pure cb live response")


## -- Live Response (collect/remediate) -- ##
class hyperLiveResponse():

    lr_session = None
    lerc_session = None
    lerc_status = None


    def __init__(self, sensor):
        if not isinstance(sensor, models.Sensor):
            raise Exception("sensor is no cbapi.response.models.Sensor")
        self.sensor = sensor
        self.hostname = self.sensor.hostname


    def go_live(self):
        if self.lr_session:
            return self.lr_session
        start_time = time.time()
        timeout = 604800 # seven days
        current_day = 0
        if self.sensor.status == 'Offline':
            logging.info("Waiting for sensor to come online..")
        while time.time() - start_time < timeout:
            try:
                self.lr_session = self.sensor.lr_session()
                logging.info("[+] LR session started at {}".format(time.ctime()))
                break
            except TimeoutError:
                elapsed_time = time.time() - start_time
                if current_day != elapsed_time // 86400:
                    current_day+=1
                    logging.info("24 hours of timeout when polling for LR session")
                    logging.info("Attempting LR session again on {} @ {}".format(self.hostname,
                                                                                   time.ctime()))
        return self.lr_session


    def deploy_lerc(self, install_cmd, lerc_installer_path=None):

        if 'lerc_api' not in sys.modules:
            logging.error("lerc_api module not found.")
            return False

        default_lerc_path = '/opt/lerc_control/lercSetup.msi'
        if lerc_installer_path:
            default_lerc_path = lerc_installer_path

        # lerc session
        if self.lerc_session is None:
            self.lerc_session = lerc_api.lerc_session()
        ls = self.lerc_session

        # check and see if the client's already installed
        result = None
        try:
            result = ls.check_host(self.hostname)
        except:
            logging.warning("Can't reach the lerc control server")

        previously_installed = False
        if result and 'client' in result:
            client = result['client']
            if client['status'] != 'UNINSTALLED':
                logging.warning("lerc server reports the client is already installed on a system with this hostname.")
                self.lerc_status = client
                return client
            else:
                previously_installed = True
                logging.info("A client was previously uninstalled on this host: {}".format(pprint.pformat(client)))

        with self.lr_session:
            logging.info("~ dropping Live Endpoint Response Client onto {}".format(self.hostname))
            filedata = None
            with open(default_lerc_path, 'rb') as f:
                filedata = f.read()
            try:
                self.lr_session.put_file(filedata, "C:\\Windows\\Carbonblack\\lercSetup.msi")
            except Exception as e:
                if 'ERROR_FILE_EXISTS' in str(e):
                    logging.info("~ lercSetup.msi already on host")
                    pass
                else:
                    raise e

            logging.info("~ installing the lerc service")
            result = self.lr_session.create_process(install_cmd, wait_timeout=60, wait_for_output=True)

        def _get_install_log(logfile=None):
            logging.info("Getting install log..")
            logfile = logfile if logfile else r"C:\\Windows\\Carbonblack\\lerc_install.log"
            content = self.lr_session.get_file(logfile)
            with open(self.hostname+"_lerc_install.log", 'wb') as f:
                f.write(content)
            logging.info("wrote log file to {}_lerc_install.log".format(self.hostname))

        wait = 5 #seconds
        attempts = 6
        if previously_installed:
            attempts += attempts
        logging.info("~ Giving client up to {} seconds to check in with the lerc control server..".format(attempts*wait))

        for i in range(attempts):
            try:
                result = ls.check_host(self.hostname)
            except:
                logging.warning("Can't reach the lerc control server")
                break
            if result:
                if 'error' not in result:
                    if result['client']['status'] != 'UNINSTALLED':
                        break
            logging.info("~ giving the client {} more seconds".format(attempts*wait - wait*i))
            time.sleep(wait)

        if not result:
            logging.warning("failed to auto-confirm install with lerc server.")
            _get_install_log()
            return None
        elif 'error' in result:
            logging.error("'{}' returned from server. Client hasn't checked in.".format(result['error']))
            _get_install_log()
            return False
        elif previously_installed and result['client']['status'] == 'UNINSTALLED':
            logger.warning("Failed to auto-confirm install. Client hasn't checked in.")
            _get_install_log()
            return False

        client = result['client']
        logging.info("Client installed on {} at '{}' - status={} - last check-in='{}'".format(hostname,
                                     client['install_date'], client['status'], client['last_activity']))

        self.lerc_status = client
        return client



