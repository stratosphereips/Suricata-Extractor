#!/usr/bin/python -u
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import sys
from datetime import datetime
from datetime import timedelta
import argparse
import time
from os.path import isfile, join
import json
from pprint import pprint
import matplotlib.pyplot as plt
import pandas as pd

version = '0.1'

timewindows = {}



###################
# TimeWindow
class TimeWindow(object):
    """ Store info about the time window """
    def __init__(self, hourstring):
        self.hour = hourstring
        self.start_time = hourstring
        self.categories = {}

    def add_category(self, category):
        try:
            self.categories[category] += 1
        except KeyError:
            self.categories[category] = 1

    def __repr__(self):
        return 'TW: {}. #Categories: {}'.format(str(self.hour), len(self.categories))

def get_tw(col_time):
    """
    """
    timeStampFormat = '%Y-%m-%dT%H:%M:%S.%f'
    hourstring = col_time.split(':')[0]
    timestamp = datetime.strptime(col_time, timeStampFormat)
    try:
        tw = timewindows[hourstring]
    except KeyError:
        # New tw
        # Print old. Becareful with the order
        try:
            print '1'
            output_tw(timewindows[timewindows.keys()[-1]])
        except IndexError:
            # No old tw
            pass
        tw = TimeWindow(hourstring)
        tw.set_start_time = timestamp
        timewindows[hourstring] = tw
        print 'New tw created at {}'.format(hourstring)
    return tw

def output_tw(tw):
    """
    """
    print tw
    for cat in tw.categories:
        print '\t{}: {}'.format(cat, tw.categories[cat])
    #plot(tw.categories)

def plot(data):
    print 'Plotting'
    data = data.items()
    #print data
    print data[1:,1:]
    values = numpy.zeros(20, dtype=dtype)
    pd.DataFrame(data=data[1:,1:],index=data[1:,0],columns=data[0,1:])

    #y = data.keys()
    #N = len(y)
    #x = data.values()
    #width = 1/1.5
    #plt.bar(x, y, width, color="blue")
    #fig = plt.gcf()
    #plot_url = py.plot_mpl(fig, filename='mpl-basic-bar')

def process_line(line):
    """
    """
    json_line = json.loads(line)
    if json_line['event_type'] != 'alert':
        return False
    #pprint(json_line) 
    # timestamp
    #2017-05-05T21:49:10.839729+0200
    # forget the timezone for now with split
    col_time = json_line['timestamp'].split('+')[0]
    col_category = json_line['alert']['category']
    # Get the time window object
    current_tw = get_tw(col_time)
    current_tw.add_category(col_category)

####################
# Main
####################
if __name__ == '__main__':  
    print 'Suricata Extractor. Version {}'.format(version)
    print('https://stratosphereips.org')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int, default=1)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the flows.', action='store', required=False, type=int, default=0)
    parser.add_argument('-f', '--file', help='Suricata eve.json file.', action='store', required=False)
    args = parser.parse_args()

    # Get the verbosity, if it was not specified as a parameter 
    if args.verbose < 1:
        args.verbose = 1

    # Limit any debuggisity to > 0
    if args.debug < 0:
        args.debug = 0

    if args.file:
        print 'Working with the file {} as parameter'.format(args.file)
        f = open(args.file)
        line = f.readline()
        while line:
            process_line(line)
            line = f.readline()
        print '2'
        output_tw(timewindows[timewindows.keys()[-1]])
        f.close()
    else:
        for line in sys.stdin:
            process_line(line)
        print '3'
        output_tw(timewindows[timewindows.keys()[-1]])

