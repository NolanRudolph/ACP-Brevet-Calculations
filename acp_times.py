"""
Open and close time calculations
for ACP-sanctioned brevets
following rules described at https://rusa.org/octime_alg.html
and https://rusa.org/pages/rulesForRiders
"""
import arrow

#  Note for CIS 322:
#  You MUST provide the following two functions
#  with these signatures, so that I can write
#  automated tests for grading.  You must keep
#  these signatures even if you don't use all the
#  same arguments.  Arguments are explained in the
#  javadoc comments.
#


# Minimum times as [(from_dist, to_dist, speed),
#                   (from_dist, to_dist, speed), ... ]
min_speed = [(0, 200, 15), (200, 400, 15), (400, 600, 15),
             (600, 1000, 11.428), (1000, 1300, 13.333)]
max_speed = [(0, 200, 34), (200, 400, 32), (400, 600, 30),
             (600, 1000, 28), (1000, 1300, 28)]

# Final control times (at or exceeding brevet distance) are special cases
final_close = {200: 13.5, 300: 20, 400: 27, 600: 40, 1000: 75}
max_dist = 1300


def open_time(control_dist_km, brevet_dist_km, brevet_start_time):
    """
    Args:
       control_dist_km:  number, the control distance in kilometers
       brevet_dist_km: number, the nominal distance of the brevet
       in kilometers, which must be one of 200, 300, 400, 600, or
           1000 (the only official ACP brevet distances)
       brevet_start_time:  An ISO 8601 format date-time string
           indicating the official start time of the brevet
    Returns:
       An ISO 8601 format date string indicating the control open time.
       This will be in the same time zone as the brevet start time.
    """
    start_time = arrow.get(brevet_start_time)
    elapsed_hours = 0
    distance_left = control_dist_km
    for from_dist, to_dist, speed in max_speed:
        seg_length = to_dist - from_dist
        if distance_left > seg_length:
            elapsed_hours += seg_length / speed
            distance_left -= seg_length
        else:
            elapsed_hours += distance_left / speed
            open_time = start_time.replace(hours=elapsed_hours)
            return open_time.isoformat()


def close_time(control_dist_km, brevet_dist_km, brevet_start_time):
    """
    Args:
       control_dist_km:  number, the control distance in kilometers
       brevet_dist_km: number, the nominal distance of the brevet
           in kilometers, which must be one of 200, 300, 400, 600,
           or 1000 (the only official ACP brevet distances)
       brevet_start_time:  An ISO 8601 format date-time string indicating
           the official start time of the brevet
    Returns:
       An ISO 8601 format date string indicating the control close time.
       This will be in the same time zone as the brevet start time.
    """
    start_time = arrow.get(brevet_start_time)
    if control_dist_km >= brevet_dist_km:
        duration = final_close[brevet_dist_km]
        finish_time = start_time.replace(hours=duration)
        return finish_time.isoformat()
    elapsed_hours = 0
    distance_left = control_dist_km
    for from_dist, to_dist, speed in min_speed:
        seg_length = to_dist - from_dist
        if distance_left > seg_length:
            elapsed_hours += seg_length / speed
            distance_left -= seg_length
        else:
            elapsed_hours += distance_left / speed
            cut_time = start_time.replace(hours=elapsed_hours)
            return cut_time.isoformat()

    return arrow.now().isoformat()

