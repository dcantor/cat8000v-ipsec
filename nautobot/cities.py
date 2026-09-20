"""US cities a site can be placed in: name -> (lat, lon). The portal's map projects a site by its coordinates; the wizard offers
this list (a city outside it can be given as raw lat / lon). Regions are assigned by longitude — West / Central / East — which
matches the lab's regions; `suggest_city` hands the wizard the first city of a region no site uses yet."""
CITIES = {
    "New York, NY": (40.7128, -74.0060), "Boston, MA": (42.3601, -71.0589), "Philadelphia, PA": (39.9526, -75.1652), "Washington, DC": (38.9072, -77.0369),
    "Atlanta, GA": (33.7490, -84.3880), "Miami, FL": (25.7617, -80.1918), "Charlotte, NC": (35.2271, -80.8431), "Pittsburgh, PA": (40.4406, -79.9959),
    "Detroit, MI": (42.3314, -83.0458), "Cleveland, OH": (41.4993, -81.6944), "Columbus, OH": (39.9612, -82.9988), "Nashville, TN": (36.1627, -86.7816),
    "Orlando, FL": (28.5383, -81.3792), "Raleigh, NC": (35.7796, -78.6382), "Richmond, VA": (37.5407, -77.4360), "Baltimore, MD": (39.2904, -76.6122),
    "Chicago, IL": (41.8781, -87.6298), "Dallas, TX": (32.7767, -96.7970), "Houston, TX": (29.7604, -95.3698), "Austin, TX": (30.2672, -97.7431),
    "Minneapolis, MN": (44.9778, -93.2650), "St. Louis, MO": (38.6270, -90.1994), "Kansas City, MO": (39.0997, -94.5786), "Denver, CO": (39.7392, -104.9903),
    "Omaha, NE": (41.2565, -95.9345), "Oklahoma City, OK": (35.4676, -97.5164), "New Orleans, LA": (29.9511, -90.0715), "Memphis, TN": (35.1495, -90.0490),
    "Milwaukee, WI": (43.0389, -87.9065), "Indianapolis, IN": (39.7684, -86.1581), "San Antonio, TX": (29.4241, -98.4936), "Des Moines, IA": (41.5868, -93.6250),
    "Los Angeles, CA": (34.0522, -118.2437), "San Francisco, CA": (37.7749, -122.4194), "Seattle, WA": (47.6062, -122.3321), "Phoenix, AZ": (33.4484, -112.0740),
    "San Diego, CA": (32.7157, -117.1611), "Las Vegas, NV": (36.1699, -115.1398), "Portland, OR": (45.5152, -122.6784), "Salt Lake City, UT": (40.7608, -111.8910),
    "Sacramento, CA": (38.5816, -121.4944), "San Jose, CA": (37.3382, -121.8863), "Albuquerque, NM": (35.0844, -106.6504), "Boise, ID": (43.6150, -116.2023),
    "Tucson, AZ": (32.2226, -110.9747), "Spokane, WA": (47.6588, -117.4260), "Reno, NV": (39.5296, -119.8138), "El Paso, TX": (31.7619, -106.4850),
}


def region_of(lon, regions):
    """West / Central / East by longitude; with other region names the middle one is returned for everything."""
    if set(regions) >= {"West", "Central", "East"}: return "West" if lon < -104 else ("Central" if lon < -86 else "East")
    return regions[len(regions) // 2]


def cities_of(region, regions):
    return [c for c, (lat, lon) in CITIES.items() if region_of(lon, regions) == region]


def suggest_city(region, regions, used):
    for c in cities_of(region, regions):
        if c not in used: return c
    return cities_of(region, regions)[0] if cities_of(region, regions) else ""


def lookup(city):
    """(lat, lon) of a catalogue city, matched case-insensitively and without the state; None when unknown."""
    if not city: return None
    key = city.strip().lower()
    for c, ll in CITIES.items():
        if c.lower() == key or c.split(",")[0].lower() == key: return ll
    return None
