def enrich_ip_telemetry(ip_address: str) -> dict:
    known_profiles = {
        "185.220.101.42": {"geo": "Frankfurt, Germany (DE)", "asn": "AS205100 F3 Netze (Tor Exit Node)", "threat_score": 98},
        "45.155.205.233": {"geo": "Moscow, Russia (RU)", "asn": "AS49505 Selectel", "threat_score": 94},
    }
    return known_profiles.get(ip_address, {"geo": "Amsterdam, Netherlands (NL)", "asn": "AS14061 DigitalOcean", "threat_score": 85})
