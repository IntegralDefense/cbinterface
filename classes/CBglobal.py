
import datetime
from dateutil import tz

## -- Global helper functions -- ##
def eastern_time(timestamp):
    eastern_timebase = tz.gettz('America/New_York')
    eastern_time = timestamp.replace(tzinfo=tz.gettz('UTC'))
    return eastern_time.astimezone(eastern_timebase).strftime('%Y-%m-%d %H:%M:%S.%f%z')
