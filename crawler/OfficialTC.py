#DeepCorr: Longer csv's, similar packet sizes, keeps 0's. LOTS of repeats??
# Test
import signal
import os
from contextlib import contextmanager
from tbselenium.common import DEFAULT_TOR_DATA_PATH, DEFAULT_TOR_BINARY_PATH


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
    import subprocess
    import os
    import psutil
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from stem.control import Controller, CircStatus, Signal
    import stem.process
    from time import sleep, time
    import shutil
    import scapy.all
    import scapy.utils
    import pandas

    #Initializes Torcollector, param size is the number of websites to scan from the csv, and param length is how many packets to capture per flow
    def __init__(self, name, host, password, torrc_dict, tbb_path):
        if tbb_path:
            tbb_path = tbb_path.rstrip('/')
            self.tor_binary_path = os.path.join(tbb_path, DEFAULT_TOR_BINARY_PATH)
            self.tor_data_path = os.path.join(tbb_path, DEFAULT_TOR_DATA_PATH)

        #password is the password in the torrc file
        self.password = password
        self.sshName = name
        self.ran = False
        self.sshHost = host
        self.socks = int(torrc_dict['socksport'])
        self.control = int(torrc_dict['controlport'])
        self.devnull = open(self.os.devnull, 'w')
        self.torrc_dict = torrc_dict
        os.environ["LD_LIBRARY_PATH"] = os.path.dirname(self.tor_binary_path)

        for directory in ['zips', 'inflow', 'misc']:
            if not os.path.exists(directory):
                os.makedirs(directory)

        self.ssh_cmd_prefix = f"sshpass -p {self.password} ssh -l {self.sshName} -t {self.sshHost}"
        #launches Tor here, starts the tcpdump (which won't scan anything until the website opens), and initializes the selenium firefox profile
        self.launchProcesses()

    def launchProcesses(self):
        tunnelport = self.socks + 8
        print(("Tor config: %s" % self.torrc_dict))
        self.tor = self.stem.process.launch_tor_with_config(
                       config=self.torrc_dict, 
                       tor_cmd=self.tor_binary_path, 
                       timeout=270
                   )
        cmd = f"sshpass -p {self.password} ssh -D {tunnelport} -o".split(" ") \
              + [f"ProxyCommand=nc -X 5 -x 127.0.0.1:{self.socks} %h %p"] \
              + [f"{self.sshName}@{self.sshHost}"]
        print(' '.join(cmd))
        self.sshProcess = self.subprocess.Popen(cmd,
                              stdout=self.subprocess.PIPE,
                              stderr=self.subprocess.STDOUT)
        print(self.sshProcess.stdout.readline())
        self.profile = self.webdriver.FirefoxProfile()
        self.profile.set_preference('network.proxy.type', 1)
        self.profile.set_preference("network.proxy.socks_version", 5)
        self.profile.set_preference('network.proxy.socks', '127.0.0.1')
        self.profile.set_preference('network.proxy.socks_port', tunnelport)

    def launchBrowser(self):
        options = self.Options()
        options.headless = True
        self.browser = self.webdriver.Firefox(self.profile, options=options)

    def killProcesses(self):
        self.tor.kill()
        self.sshProcess.terminate()
        self.browser.close()

    #Runs TorCollector, webfile being the file that contains the websites, and resFile beign the file that contains the Flow information
    def run(self,
            start,
            chsize,
            webFile="majestic_million.csv",
            size=1,
            length=60,
            reset=50,
            outflowfolder="outflow"):
        self.ran = True
        cmd = f"{self.ssh_cmd_prefix} mkdir {outflowfolder}"
        self.runProcess(cmd.split(" "))
        #creates new "browser" which can launch urls given text as an input
        self.folder = "_{}_{}_{}_{}".format(str(start), str(chsize), str(size), str(reset))
        self.zipfolder = 'zips/zips{}'.format(self.folder)
        try:
            self.os.mkdir(self.zipfolder)
        except Exception:
            pass
        self.launchBrowser()
        #opens results file now and keeps it open until the class is deconstructed, sets the counter for how many websites are visited to 0.
        self.readURL = self.pandas.read_csv(webFile,header=None,
                                            chunksize=chsize,                                                                                                            skiprows=start).get_chunk(chsize)
        start_time = self.time()
        self.errorSites = set()
        self.runURLS(
            size, start, chsize, reset, length,
            outflowfolder)  #runs a for loop through each url in the csv
        errors = self.errorSites.copy()
        self.errorSites = set()
        while errors:
            self.runURL(errors.pop()[0], 0, 0, reset, length, outflowfolder)
        for er in self.errorSites:
            self.writeFile("{}: {}\n".format(er[0], er[1]),
                           "misc/errorSites{}.txt".format(self.folder))
        cmd = f"{self.ssh_cmd_prefix} zip -r outflows{self.folder}.zip {outflowfolder}/"
        self.runProcess(cmd.split(" "))
        scp_cmd = f"sshpass -p {self.password} scp {self.sshName}@{self.sshHost}:outflows{self.folder}.zip {self.zipfolder}/"
        self.runProcess(scp_cmd.split(" "))
        if (self.os.path.isfile("{}/outflows{}.zip".format(
                self.zipfolder, self.folder))):
            cmd = f"{self.ssh_cmd_prefix} rm -r {outflowfolder}*"
            self.runProcess(cmd.split(" "))
        else:
            print("ERROR: SCP copy failed!")
        print("Total Capture Time: {}, {} per website".format(
            self.time() - start_time,
            (self.time() - start_time) / (chsize * size)))

    # Goes through each url, if it has read too many then it breaks out of the loop. Otherwise, if it's the first one, skip it as it's a header
    def runURLS(self, size, start, chsize, reset, length, outflowfolder):
        count = 0
        self.resetExit()
        self.resetEntry()
        for i in range(0, size):
            for j in range(0,chsize):
                url = self.readURL.iloc[j][2]
                print(url)
                self.lastURL = url
                self.runURL(url, i, count, reset, length, outflowfolder)
                count += 1

# fix var names (bad names and bad capitalization)

    def runURL(self, url, i, count, reset, length, outflowfolder):
        urlnum = url + str(i)
        if (count % reset == 0 and not count == 0):
            self.killProcesses()
            self.launchProcesses()
            self.launchBrowser()
            self.resetExit()
            self.resetEntry()
        #if it's not the first one, set the url to the proper spot in the file, and every 50 websites reset the IP.
        cmd = f"{self.ssh_cmd_prefix} tcpdump -s 114 -w {outflowfolder}/{urlnum}.pcap"
        self.tcpdumpProcessOut = self.startTcpDump(cmd.split(" "))
        cmd = f"tcpdump -s 114 -w inflow/{urlnum}.pcap"
        self.tcpdumpProcessIn = self.startTcpDump(cmd.split(" "))
        start_time = self.time()
        try:
            with time_limit(60):
                self.browser.get("http://" + url)
                self.browser.save_screenshot(
                    'screenshots/{}.png'.format(urlnum))
        except TimeoutException as e:
            self.killTcpDump()
            cmd = f"{self.ssh_cmd_prefix} rm {outflowfolder}/{urlnum}.pcap"
            self.runProcess(cmd.split(" "))
            self.writeFile("{}: {}\n".format(url, "Timed Out"),
                           "misc/errorSitesFULL{}.txt".format(self.folder))
            self.errorSites.add((url, "Timed Out"))
            return
        except Exception as e:
            self.killTcpDump()
            cmd = f"{self.ssh_cmd_prefix} rm rm outflows/{urlnum}.pcap"
            self.runProcess(cmd.split(" "))
            self.writeFile("{}: {}\n".format(url, str(e)),
                           "misc/errorSitesFULL{}.txt".format(self.folder))
            self.errorSites.add((url, str(e)))
            return
        timeElapsed = self.time() - start_time
        if (timeElapsed > 0):
            self.sleep(
                length -
                (timeElapsed))  # THIS SLEEP IS TO MEASURE 10 SECONDS OF FLOWS
        self.killTcpDump()
        self.writeFile(
            "Total Time for {}: {}\n".format(url,
                                             self.time() - start_time),
            "misc/timeElapsed{}.txt".format(self.folder))
        self.writeFile("Time Loading for {}: {}\n".format(url, timeElapsed),
                       "misc/timeElapsed{}.txt".format(self.folder))

    def writeFile(self, string, filename):
        with open(filename, "a") as file:
            file.write(string)

    def runProcess(self, command):
        proc = self.subprocess.Popen(command,
                                     stdout=self.devnull,
                                     stderr=self.subprocess.STDOUT)
        while (proc.poll() is None):
            pass
        proc.terminate()

    def killTcpDump(self):
        self.tcpdumpProcessIn.terminate()
        self.tcpdumpProcessOut.terminate()

    def startTcpDump(self, command):
        return self.subprocess.Popen(command,
                                     stdout=self.devnull,
                                     stderr=self.subprocess.STDOUT)

    def get_guard_ips(self, controller, flow):
        ips = []
        for circ in controller.get_circuits():
            # filter empty circuits out
            if len(circ.path) == 0:
                continue
            ip = controller.get_network_status(circ.path[flow][0]).address
            if ip not in ips:
                ips.append(ip)
        return ips

    #Resets the circuit to all new nodes, for sure changes the exit node as tested by checking ip before and after changing them.
    def resetExit(self):
        with self.Controller.from_port(port=self.control) as cont:
            cont.authenticate()
            cont.signal(self.Signal.NEWNYM)
            with open("misc/exitIps{}.txt".format(self.folder), "a") as file:
                file.write(' '.join(self.get_guard_ips(cont, -1)) + '\n')
            #cont.drop_guards() #Not sure how to check the entry nodes and middle nodes yet, so it is unconfirmed if this change works properly

    def resetEntry(self):
        with self.Controller.from_port(port=self.control) as cont:
            cont.authenticate()
            cont.drop_guards(
            )  #Not sure how to check the entry nodes and middle nodes yet, so it is unconfirmed if this change works properly
            with open("misc/entryIps{}.txt".format(self.folder), "a") as file:
                file.write(' '.join(self.get_guard_ips(cont, 0)) + '\n')

    #basic deconstructor that kills tor and closes the file being written
    def __del__(self):
        if(self.ran):
            self.shutil.make_archive(
                '{}/inflows{}'.format(self.zipfolder, self.folder), 'zip',
                'inflowPCAP')
            self.shutil.make_archive(
                '{}/screenshots{}'.format(self.zipfolder, self.folder), 'zip',
                'screenshots')
            self.shutil.make_archive(
                '{}/misc{}'.format(self.zipfolder, self.folder), 'zip', 'misc')
            print(self.lastURL)
            self.killProcesses()
