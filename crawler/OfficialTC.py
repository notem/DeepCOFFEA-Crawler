import signal
import os
from contextlib import contextmanager
from tbselenium.common import DEFAULT_TOR_DATA_PATH, DEFAULT_TOR_BINARY_PATH

import subprocess
import os
import psutil
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from stem.control import Controller, CircStatus, Signal
import stem.process
from time import sleep, time, strftime
import shutil
import scapy.all
import scapy.utils
import pandas


class TimeoutException(Exception):
    pass


@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


class TorCollector:

    def __init__(self, name, host, password, torrc_dict, tbb_path, host_nic):
        """
        Initializes Torcollector, param size is the number of websites to scan from the csv, and param length is how many packets to capture per flow 
        """
        self.password = password
        self.sshName = name
        self.ran = False
        self.sshHost = host
        self.socks = int(torrc_dict['socksport'])
        self.control = int(torrc_dict['controlport'])
        self.devnull = open(os.devnull, 'w')
        self.torrc_dict = torrc_dict
        self.ssh_cmd_prefix = f"sshpass -p {self.password} ssh -l {self.sshName} -t {self.sshHost}"
        self.host_nic = host_nic
        self.crawldir = os.path.join('results', strftime('%y%m%d_%H%M%S'))

        # setup TBB environment libraries
        if tbb_path:
            tbb_path = tbb_path.rstrip('/')
            self.tor_binary_path = os.path.join(tbb_path, DEFAULT_TOR_BINARY_PATH)
            self.tor_data_path = os.path.join(tbb_path, DEFAULT_TOR_DATA_PATH)
        os.environ["LD_LIBRARY_PATH"] = os.path.dirname(self.tor_binary_path)

        self.launchProcesses()

    def launchProxy(self):
        """
        """
        tunnelport = self.socks + 8
        cmd = f"sshpass -p {self.password} ssh -D {tunnelport} -o".split(" ") \
              + [f"ProxyCommand=nc -X 5 -x 127.0.0.1:{self.socks} %h %p"] \
              + [f"{self.sshName}@{self.sshHost}"]
        self.sshProcess = subprocess.Popen(cmd,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)


    def launchProcesses(self):
        """
        """
        # launch tor process
        print(("Tor config: %s" % self.torrc_dict))
        self.tor = stem.process.launch_tor_with_config(
                       config=self.torrc_dict, 
                       tor_cmd=self.tor_binary_path, 
                       timeout=270)
        # launch proxy
        tunnelport = self.socks + 8
        #cmd = f"sshpass -p {self.password} ssh -D {tunnelport} -o".split(" ") \
        #      + [f"ProxyCommand=nc -X 5 -x 127.0.0.1:{self.socks} %h %p"] \
        #      + [f"{self.sshName}@{self.sshHost}"]
        #self.sshProcess = subprocess.Popen(cmd,
        #                      stdout=subprocess.PIPE,
        #                      stderr=subprocess.STDOUT)

        # setup selenium firefox profile w/ proxy
        self.profile = webdriver.FirefoxProfile()
        self.profile.set_preference('network.proxy.type', 1)
        self.profile.set_preference("network.proxy.socks_version", 5)
        self.profile.set_preference('network.proxy.socks', '127.0.0.1')
        self.profile.set_preference('network.proxy.socks_port', tunnelport)

    def launchBrowser(self):
        """ """
        options = Options()
        options.headless = True
        self.browser = webdriver.Firefox(self.profile, options=options)

    def killProcesses(self):
        """ """
        self.tor.kill()
        self.browser.close()

    def run(self,
            start,
            batch_count,
            chsize,
            webFile="top-1m.csv",
            timeout_val=120,
            outflowfolder="outflow"):
        """ 
        Runs TorCollector, webfile being the file that contains the websites, and resFile beign the file that contains the Flow information
        """
        self.ran = True

        # make client directories
        self.outflow_savedir = os.path.join(self.crawldir, 'outflow')
        self.logs_savedir = os.path.join(self.crawldir, 'logs')
        self.inflow_savedir = os.path.join(self.crawldir, 'inflow')
        self.screens_savedir = os.path.join(self.crawldir, 'screenshots')
        try:
            for directory in [self.outflow_savedir, self.logs_savedir, self.inflow_savedir, self.screens_savedir]:
                if not os.path.exists(directory):
                    os.makedirs(directory)
        except Exception:
            pass

        # create outflow directory on proxy
        cmd = f"{self.ssh_cmd_prefix} mkdir {outflowfolder}"
        self.runProcess(cmd.split(" "))

        self.total_count = 0
        self.read_pos = start

        # launch the webdriver
        self.launchBrowser()
        for batch_no in range(batch_count):
            self.cur_batch = batch_no

            # read in URLs
            self.batch_urls = pandas.read_csv(webFile, header=None, chunksize=chsize, skiprows=self.read_pos).get_chunk(chsize)
            start_time = time()

            self.errorSites = set()
            self.runURLS(chsize, timeout_val, outflowfolder)
            self.read_pos += chsize

        print(f"Total Capture Time: {time() - start_time}, {(time() - start_time) / (chsize * batch_count)} per website")

    def runURLS(self, chsize, timeout_val, outflowfolder):
        """ """
        self.resetExit()
        self.resetEntry()
        for j in range(0, chsize):

            self.launchProxy()
            sleep(1)

            url = self.batch_urls.iloc[j][1]
            print(url, end='\n\r')
            self.lastURL = url
            self.runURL(url, j, timeout_val, outflowfolder)
            self.total_count += 1

            self.sshProcess.terminate()

        self.killProcesses()
        self.launchProcesses()
        self.launchBrowser()

    def runURL(self, url, j, timeout_val, outflowfolder):
        """ """
        url_id = f"{self.cur_batch}_{self.read_pos}_{j}_{self.total_count}"
        start_time = time()

        # start capture on proxy
        cmd = f"{self.ssh_cmd_prefix} tcpdump -w {outflowfolder}/{url_id}.pcap"
        self.tcpdumpProcessOut = self.startTcpDump(cmd, f'{self.logs_savedir}/proxy_{url_id}.log')

        # start capture on client
        cmd = f"LD_LIBRARY_PATH= tcpdump -Z root -w {self.inflow_savedir}/{url_id}.pcap -i {self.host_nic}"
        self.tcpdumpProcessIn = self.startTcpDump(cmd, f'{self.logs_savedir}/client_{url_id}.log')

        sleep(1)

        # attempt a visit
        err = False
        try:
            with time_limit(timeout_val):
                self.browser.get("http://" + url)
                self.browser.save_screenshot(f'{self.screens_savedir}/{url_id}.png')

        except TimeoutException as e:
            # site timed-out due to either length or is unavailable
            self.writeFile("{}: {}\n".format(url, "Timed Out"),
                           f"{self.logs_savedir}/errorSitesFULL.txt")
            self.errorSites.add((url, "Timed Out"))
            err = True

        except Exception as e:
            # unknown issue
            self.writeFile("{}: {}\n".format(url, str(e)),
                           f"{self.logs_savedir}/errorSitesFULL.txt")
            self.errorSites.add((url, str(e)))
            err = True

        timeElapsed = time() - start_time
        #if timeElapsed > 0 and not err:
        #    sleep(timeout_val - timeElapsed)
        sleep(3)
        self.killTcpDump()

        # grab outflow capture from proxy
        scp_cmd = f"sshpass -p {self.password} scp {self.sshName}@{self.sshHost}:/home/{self.sshName}/{outflowfolder}/{url_id}.pcap {self.outflow_savedir}"
        self.runProcess(scp_cmd.split(" "))
        if not os.path.isfile(f"{self.outflow_savedir}/{url_id}.pcap"):
            print("ERROR: SCP copy failed!")

        # delete pcap from proxy
        cmd = f"{self.ssh_cmd_prefix} rm {outflowfolder}/*"
        self.runProcess(cmd.split(" "))

        # log elapsed time
        self.writeFile(string = f"[{url_id}] {url} visit in {timeElapsed}, full process in {time() - start_time}\n", 
                       filename = f"{self.logs_savedir}/timeElapsed.txt")

    def writeFile(self, string, filename):
        with open(filename, "a") as file:
            file.write(string)

    def runProcess(self, command):
        """
        helper function to run system processes 
        """
        proc = subprocess.Popen(command,
                                stdout=self.devnull,
                                stderr=subprocess.PIPE)
        proc.wait()
        #while (proc.poll() is None):
        #    pass
        proc.terminate()

    def killTcpDump(self):
        self.tcpdumpProcessIn.terminate()
        self.tcpdumpProcessOut.terminate()
        cmd = f"{self.ssh_cmd_prefix} pkill tcpdump"
        self.runProcess(cmd.split(" "))


    def startTcpDump(self, command, log):
        with open(log, 'w') as fi:
            return subprocess.Popen(command,
                                    stdout=fi,
                                    stderr=fi, shell=True)

    def get_guard_ips(self, controller, flow):
        """ """
        ips = []
        for circ in controller.get_circuits():
            # filter empty circuits out
            if len(circ.path) == 0:
                continue
            ip = controller.get_network_status(circ.path[flow][0]).address
            if ip not in ips:
                ips.append(ip)
        return ips

    def resetExit(self):
        """
        Resets the circuit to all new nodes, for sure changes the exit node as tested by checking ip before and after changing them.
        """
        with Controller.from_port(port=self.control) as cont:
            cont.authenticate()
            cont.signal(Signal.NEWNYM)
            with open(f"{self.logs_savedir}/exitIps.txt", "a") as file:
                file.write(' '.join(self.get_guard_ips(cont, -1)) + '\n')

    def resetEntry(self):
        """ """
        with Controller.from_port(port=self.control) as cont:
            cont.authenticate()
            cont.drop_guards(
            )  #Not sure how to check the entry nodes and middle nodes yet, so it is unconfirmed if this change works properly
            with open(f"{self.logs_savedir}/entryIps.txt", "a") as file:
                file.write(' '.join(self.get_guard_ips(cont, 0)) + '\n')

    def __del__(self):
        """
        """
        if(self.ran):
            self.killProcesses()
