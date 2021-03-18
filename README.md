# DeepCOFFEA-Crawler

# Usage
* Install docker
* Build the container using `make build`
* Edit the `CRAWL_PARAMS` in the `Makefile` to correctly reflect the login credentials to the server that will act as the proxy
  * make sure `tcpdump` is installed and usable by your user account for the proxy server (nothing else is needed)
* Run the crawler using `make run`
