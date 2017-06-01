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
timeStampFormat = '%Y-%m-%dT%H:%M:%S.%f'



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
    timestamp = datetime.strptime(col_time, timeStampFormat)
    # Get the closest down time rounded
    round_down_timestamp = roundTime(timestamp,timedelta(minutes=args.width), 'down')
    str_round_down_timestamp = round_down_timestamp.strftime(timeStampFormat)
    try:
        tw = timewindows[str_round_down_timestamp]
    except KeyError:
        # New tw
        # Get the previous TW id
        prev_tw_date = round_down_timestamp - timedelta(minutes=int(args.width))
        str_prev_round_down_timestamp = prev_tw_date.strftime(timeStampFormat)
        output_tw(str_prev_round_down_timestamp)
        tw = TimeWindow(str_round_down_timestamp)
        tw.set_start_time = timestamp
        timewindows[str_round_down_timestamp] = tw
        if args.verbose > 2:
            print 'New tw created at {}'.format(str_round_down_timestamp)
    return tw

def output_tw(time_tw):
    """
    Print the TW
    """
    try:
        tw = timewindows[time_tw]
        if args.verbose > 1:
            print 'Printing TW that started in: {}'.format(time_tw)
        print tw
    except KeyError:
        return False
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
    return current_tw

def roundTime(dt=None, date_delta=timedelta(minutes=1), to='average'):
    """
    Round a datetime object to a multiple of a timedelta
    dt : datetime.datetime object, default now.
    dateDelta : timedelta object, we round to a multiple of this, default 1 minute.
    from:  http://stackoverflow.com/questions/3463930/how-to-round-the-minute-of-a-datetime-object-python
    """
    round_to = date_delta.total_seconds()
    if dt is None:
        dt = datetime.now()
    seconds = (dt - dt.min).seconds
    if to == 'up':
        # // is a floor division, not a comment on following line (like in javascript):
        rounding = (seconds + round_to) // round_to * round_to
    elif to == 'down':
        rounding = seconds // round_to * round_to
    else:
        rounding = (seconds + round_to / 2) // round_to * round_to
    return dt + timedelta(0, rounding - seconds, -dt.microsecond)

####################
# Main
####################
if __name__ == '__main__':  
    print 'Suricata Extractor. Version {} (https://stratosphereips.org)'.format(version)
    print

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int, default=1)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the flows.', action='store', required=False, type=int, default=0)
    parser.add_argument('-f', '--file', help='Suricata eve.json file.', action='store', required=False)
    parser.add_argument('-w', '--width', help='Width of the time window to process. In minutes.', action='store', required=False, type=int, default=60)
    args = parser.parse_args()

    # Get the verbosity, if it was not specified as a parameter 
    if args.verbose < 1:
        args.verbose = 1

    # Limit any debuggisity to > 0
    if args.debug < 0:
        args.debug = 0

    if args.file:
        if args.verbose > 1:
            print 'Working with the file {} as parameter'.format(args.file)
        f = open(args.file)
        line = f.readline()
        while line:
            current_tw = process_line(line)
            line = f.readline()
        f.close()
    else:
        for line in sys.stdin:
            current_tw = process_line(line)
    ## Print last tw
    timestamp = datetime.strptime(current_tw.start_time, timeStampFormat)
    round_down_timestamp = roundTime(timestamp,timedelta(minutes=args.width), 'down')
    str_round_down_timestamp = round_down_timestamp.strftime(timeStampFormat)
    output_tw(str_round_down_timestamp)

