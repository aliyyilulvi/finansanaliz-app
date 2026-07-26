# -*- coding: utf-8 -*-
"""
data_fetcher.py
----------------
FinansAnaliz uygulamasının veri toplama katmanı.
Veri kaynağı: football-data.org REST API'si (ücretsiz plan).

API ANAHTARI: Mobilde ortam değişkeni çalışmadığı için _HARDCODED_API_KEY'e gömülüdür.

AĞ / DNS NOTU: Sistem DNS çözümleyicisi bazı cihazlarda bozuk olabiliyor.
Sırasıyla 3 yedek yöntem deneniyor: Android native (pyjnius), DNS-over-TCP,
Cloudflare DoH.

Her lig AYRI AYRI, kanıtlanmış çalışan /v4/competitions/{code}/matches uç
noktasıyla PARALEL sorgulanır (genel /v4/matches uç noktası bazı durumlarda
400 hatası veriyordu).
"""

import os
import csv
import socket
import struct
import random
import time
from datetime import datetime, timedelta
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3.util.connection as _urllib3_cn

_original_getaddrinfo = socket.getaddrinfo


def _allowed_gai_family():
    return socket.AF_INET


_urllib3_cn.allowed_gai_family = _allowed_gai_family

_last_dns_debug = []


def _resolve_via_android(hostname: str) -> list:
    try:
        from jnius import autoclass
        InetAddress = autoclass("java.net.InetAddress")
        addresses = InetAddress.getAllByName(hostname)
        return [a.getHostAddress() for a in addresses]
    except Exception as e:
        _last_dns_debug.append(f"android: {type(e).__name__}: {e}")
        return []


def _build_dns_query(hostname: str) -> bytes:
    transaction_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    parts = hostname.split(".")
    question = b"".join(struct.pack("B", len(p)) + p.encode() for p in parts) + b"\x00"
    question += struct.pack(">HH", 1, 1)
    return header + question


def _parse_dns_response(data: bytes) -> list:
    ancount = struct.unpack(">H", data[6:8])[0]
    idx = 12
    while data[idx] != 0:
        idx += data[idx] + 1
    idx += 5

    ips = []
    for _ in range(ancount):
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[idx:idx + 10])
        idx += 10
        if rtype == 1 and rdlength == 4:
            ip = ".".join(str(b) for b in data[idx:idx + 4])
            ips.append(ip)
        idx += rdlength
    return ips


def _resolve_via_dns_tcp(hostname: str, dns_server: str = "8.8.8.8", port: int = 53, timeout: float = 6.0) -> list:
    try:
        query = _build_dns_query(hostname)
        tcp_query = struct.pack(">H", len(query)) + query

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((dns_server, port))
            sock.sendall(tcp_query)

            length_bytes = sock.recv(2)
            if len(length_bytes) < 2:
                return []
            resp_length = struct.unpack(">H", length_bytes)[0]

            resp_data = b""
            while len(resp_data) < resp_length:
                chunk = sock.recv(resp_length - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk
        finally:
            sock.close()

        return _parse_dns_response(resp_data)
    except Exception as e:
        _last_dns_debug.append(f"dns_tcp: {type(e).__name__}: {e}")
        return []


def _resolve_via_doh(hostname: str, timeout: float = 6.0) -> list:
    try:
        resp = requests.get(
            "https://1.1.1.1/dns-query",
            params={"name": hostname, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        answers = data.get("Answer", [])
        return [a["data"] for a in answers if a.get("type") == 1]
    except Exception as e:
        _last_dns_debug.append(f"doh: {type(e).__name__}: {e}")
        return []


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _original_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror as e:
        _last_dns_debug.append(f"original: {e}")

    ips = _resolve_via_android(host)
    if not ips:
        ips = _resolve_via_dns_tcp(host)
    if not ips:
        ips = _resolve_via_doh(host)

    if not ips:
        debug_info = " | ".join(_last_dns_debug[-4:])
        raise socket.gaierror(f"'{host}' çözümlenemedi -> [{debug_info}]")

    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
        for ip in ips
    ]


socket.getaddrinfo = _patched_getaddrinfo

from models import MatchResult, TeamStats, HeadToHead, WeatherInfo, Fixture

FOOTBALL_DATA_BASE = "https://api.football-data.org/v4"
OPEN_METEO_BASE = "https://api.open-meteo.com/v1/forecast"
GEOCODE_BASE = "https://geocoding-api.open-meteo.com/v1/search"

_HARDCODED_API_KEY = "6fdc17feb0d5436782e4382f3a1daa86"


def _api_key() -> str:
    key = _HARDCODED_API_KEY or os.environ.get("FOOTBALL_DATA_API_KEY", "")
    if not key:
        raise RuntimeError(
            "FOOTBALL_DATA_API_KEY tanımlı değil. Ücretsiz anahtar için: "
            "https://www.football-data.org/client/register"
        )
    return key


def _headers() -> dict:
    return {"X-Auth-Token": _api_key()}


def _get_with_retry(url: str, params: dict = None, max_retries: int = 3, timeout: float = 15) -> requests.Response:
    last_resp = None
    for attempt in range(max_retries):
        resp = requests.get(url, headers=_headers(), params=params, timeout=timeout)
        if resp.status_code != 429:
            return resp
        last_resp = resp
        wait = int(resp.headers.get("Retry-After", 8))
        time.sleep(max(wait, 3))
    return last_resp


FREE_COMPETITIONS = ["PL", "PD", "BL1", "SA", "FL1", "CL", "ELC", "DED", "PPL", "BSA", "WC", "EC"]


def _fetch_one_competition(comp_code: str, date_from: Optional[str], date_to: Optional[str]) -> List[dict]:
    try:
        url = f"{FOOTBALL_DATA_BASE}/competitions/{comp_code}/matches"
        params = {}
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to

        resp = _get_with_retry(url, params)
        if resp is None or resp.status_code != 200:
            return []

        data = resp.json()
        comp_name = data.get("competition", {}).get("name", comp_code)

        results = []
        for m in data.get("matches", []):
            status = m.get("status", "SCHEDULED")
            full_time = (m.get("score") or {}).get("fullTime") or {}
            half_time = (m.get("score") or {}).get("halfTime") or {}
            results.append({
                "home": m["homeTeam"]["name"],
                "away": m["awayTeam"]["name"],
                "home_id": m["homeTeam"]["id"],
                "away_id": m["awayTeam"]["id"],
                "utc_date": m["utcDate"],
                "league": comp_name,
                "status": status,
                "home_goals": full_time.get("home"),
                "away_goals": full_time.get("away"),
                "ht_home_goals": half_time.get("home"),
                "ht_away_goals": half_time.get("away"),
            })
        return results
    except Exception:
        return []


# ----------------------------------------------------------------------
# 1) FİKSTÜR (Bülten) ÇEKME - PARALEL
# ----------------------------------------------------------------------
def fetch_upcoming_fixtures(competition_code: str = "", limit: int = 80,
                             date_from: Optional[str] = None, date_to: Optional[str] = None) -> List[dict]:
    code = (competition_code or "").strip().upper()
    codes = [code] if code else FREE_COMPETITIONS

    all_fixtures = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {
            executor.submit(_fetch_one_competition, c, date_from, date_to): c
            for c in codes
        }
        for future in as_completed(future_map):
            try:
                all_fixtures.extend(future.result())
            except Exception:
                continue

    all_fixtures.sort(key=lambda fx: fx["utc_date"])
    return all_fixtures[:limit]


# ----------------------------------------------------------------------
# 2) TAKIM FORMU (son 5 genel, son 3 ev/deplasman)
# ----------------------------------------------------------------------
def fetch_team_recent_matches(team_id: int, limit: int = 10) -> List[MatchResult]:
    today = datetime.utcnow().date()
    date_from = (today - timedelta(days=220)).isoformat()
    date_to = today.isoformat()

    url = f"{FOOTBALL_DATA_BASE}/teams/{team_id}/matches"
    params = {"status": "FINISHED", "dateFrom": date_from, "dateTo": date_to}
    resp = _get_with_retry(url, params)
    if resp is None or resp.status_code != 200:
        return []
    data = resp.json()

    matches_raw = data.get("matches", [])
    matches_raw = matches_raw[-limit:] if len(matches_raw) > limit else matches_raw

    results = []
    for m in matches_raw:
        is_home = m["homeTeam"]["id"] == team_id
        gf = m["score"]["fullTime"]["home"] if is_home else m["score"]["fullTime"]["away"]
        ga = m["score"]["fullTime"]["away"] if is_home else m["score"]["fullTime"]["home"]
        if gf is None or ga is None:
            continue
        opponent = m["awayTeam"]["name"] if is_home else m["homeTeam"]["name"]
        results.append(MatchResult(
            opponent=opponent, home=is_home,
            goals_for=gf, goals_against=ga, date=m.get("utcDate", "")
        ))
    results.sort(key=lambda r: r.date, reverse=True)
    return results


def build_team_stats(team_name: str, team_id: int) -> TeamStats:
    all_recent = fetch_team_recent_matches(team_id, limit=10)
    last5 = all_recent[:5]
    home_or_away_specific = [m for m in all_recent if m.home][:3]

    stats = TeamStats(name=team_name, last5_all=last5, last3_home_or_away=home_or_away_specific)
    stats.squad_market_value_eur = load_market_value(team_name)
    return stats


def fetch_head_to_head(match_id: int, limit: int = 5) -> HeadToHead:
    url = f"{FOOTBALL_DATA_BASE}/matches/{match_id}/head2head"
    params = {"limit": limit}
    resp = _get_with_retry(url, params)
    if resp is None or resp.status_code != 200:
        return HeadToHead(matches=[])
    data = resp.json()

    matches = []
    for m in data.get("matches", []):
        matches.append({
            "home_team": m["homeTeam"]["name"],
            "away_team": m["awayTeam"]["name"],
            "home_goals": m["score"]["fullTime"]["home"],
            "away_goals": m["score"]["fullTime"]["away"],
            "date": m.get("utcDate", ""),
        })
    return HeadToHead(matches=matches)


# ----------------------------------------------------------------------
# 3) KADRO PİYASA DEĞERİ
# ----------------------------------------------------------------------
_MARKET_VALUE_CSV = os.path.join(os.path.dirname(__file__), "data", "market_values.csv")


def load_market_value(team_name: str) -> float:
    if not os.path.exists(_MARKET_VALUE_CSV):
        return 0.0
    with open(_MARKET_VALUE_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["team_name"].strip().lower() == team_name.strip().lower():
                try:
                    return float(row["market_value_eur"])
                except (ValueError, KeyError):
                    return 0.0
    return 0.0


# ----------------------------------------------------------------------
# 4) HAVA DURUMU
# ----------------------------------------------------------------------
def fetch_city_coordinates(city_name: str) -> Optional[dict]:
    resp = requests.get(GEOCODE_BASE, params={"name": city_name, "count": 1}, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    results = data.get("results")
    if not results:
        return None
    r = results[0]
    return {"lat": r["latitude"], "lon": r["longitude"]}


def fetch_weather(city_name: str, match_date: str) -> WeatherInfo:
    coords = fetch_city_coordinates(city_name)
    if not coords:
        return WeatherInfo()

    params = {
        "latitude": coords["lat"],
        "longitude": coords["lon"],
        "daily": "temperature_2m_max,precipitation_sum,windspeed_10m_max",
        "timezone": "auto",
        "start_date": match_date,
        "end_date": match_date,
    }
    try:
        resp = requests.get(OPEN_METEO_BASE, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        daily = data.get("daily", {})
        temp = daily.get("temperature_2m_max", [None])[0]
        precip = daily.get("precipitation_sum", [None])[0]
        wind = daily.get("windspeed_10m_max", [None])[0]
        condition = "yağışlı" if (precip or 0) > 1 else "açık"
        return WeatherInfo(temperature_c=temp, precipitation_mm=precip,
                            wind_kmh=wind, condition=condition)
    except requests.RequestException:
        return WeatherInfo()


def build_fixture(raw_fixture: dict) -> Fixture:
    home_stats = build_team_stats(raw_fixture["home"], raw_fixture["home_id"])
    away_stats = build_team_stats(raw_fixture["away"], raw_fixture["away_id"])

    match_date = raw_fixture["utc_date"][:10] if raw_fixture.get("utc_date") else \
        datetime.utcnow().strftime("%Y-%m-%d")

    weather = fetch_weather(raw_fixture["home"], match_date)

    return Fixture(
        home_team=raw_fixture["home"],
        away_team=raw_fixture["away"],
        league=raw_fixture.get("league", ""),
        kickoff=raw_fixture.get("utc_date", ""),
        home_stats=home_stats,
        away_stats=away_stats,
        h2h=None,
        weather=weather,
    )
