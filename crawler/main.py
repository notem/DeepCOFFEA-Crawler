from OfficialTC import TorCollector, BASE_DIR
from argparse import ArgumentParser 
from tbselenium.utils import start_xvfb, stop_xvfb
import configparser
import os
from os.path import abspath, join, dirname, pardir


def get_dict_subconfig(config, section, prefix):
    """Return options in config for options with a `prefix` keyword."""
    return {option.split()[1]: config.get(section, option)
            for option in config.options(section) if option.startswith(prefix)}


def main():

    parser = ArgumentParser()
    parser.add_argument('--user', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--password', required=True)
    parser.add_argument('--nic', default='eno1')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--batches', default=10, type=int)
    parser.add_argument('--chunksize', default=100, type=int)
    parser.add_argument('--config', default="default")
    parser.add_argument('--sites', default="majestic_million.csv")
    parser.add_argument('--virtual_display', default="720x1280")
    args = parser.parse_args()

    config = configparser.RawConfigParser()
    config.read(join(BASE_DIR, "config.ini"))

    torrc_config = get_dict_subconfig(config, args.config, "torrc")
    ffprefs = get_dict_subconfig(config, args.config, "ffpref")

    # Setup stem headless display
    xvfb_h = int(args.virtual_display.split('x')[0])
    xvfb_w = int(args.virtual_display.split('x')[1])
    xvfb_display = start_xvfb(xvfb_w, xvfb_h)

    try:
        tbb_path = join(BASE_DIR, 'tor-browser_en-US')
        collector = TorCollector(args.user, args.host, args.password, torrc_config, ffprefs, tbb_path, args.nic)
        collector.run(args.start, args.batches, args.chunksize, webFile=join(BASE_DIR, args.sites))
    finally:
        # Close display
        stop_xvfb(xvfb_display)


if __name__ == '__main__':
    main()
