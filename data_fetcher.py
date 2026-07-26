# -*- coding: utf-8 -*-
"""
data_fetcher.py
----------------
FinansAnaliz uygulamasının veri toplama katmanı.
Veri kaynağı: API-Football (api-football.com) - 1200+ lig, MLS dahil.

MİMARİ: API-Football'ın kendi "hazır tahmini" yerine, GERÇEK takım
istatistiklerini (/teams/statistics -> maç başına ort. gol) çekip
KENDİ kanıtlanmış Poisson motorumuza (analyzer.py) besliyoruz. Böylece
hem geniş lig kapsamı hem Kolik'teki gibi TAM pazar analizi bir arada.

ÖNEMLİ: Ücretsiz planda GÜNDE SADECE 100 İSTEK var (dakika değil, gün).
Bülten: 1 istek. Her analiz: 2 istek (ev+deplasman istatistiği).
"""

import os
import socket
import struct
import random
from datetime import datetime
from typing import List, Optional

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

API_BASE = "https://v3.football.api-sports.io"
OPEN_METEO_BASE = "https://api.open-meteo.com/v1/forecast"
GEOCODE_BASE = "https://geocoding-api.open-meteo.com/v1/search"

_HARDCODED_API_KEY = "b7e3704ff369331fc8d57a5d6036a067"


def _headers() -> dict:
    return {"x-apisports-key": _HARDCODED_API_KEY}


def _get(url: str, params: dict = None, timeout: float = 15):
    try:
        return requests.get(url, headers=_headers(), params=params, timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"Baglanti hatasi: {type(e).__name__}: {e}")


# ----------------------------------------------------------------------
# 1) FİKSTÜR (Bülten) ÇEKME - TEK İSTEKLE TÜM LİGLER (1200+)
# ----------------------------------------------------------------------
def fetch_upcoming_fixtures(competition_code: str = "", limit: int = 100,
                             date_from: Optional[str] = None, date_to: Optional[str] = None) -> List[dict]:
    date_str = date_from or date_to or datetime.utcnow().strftime("%Y-%m-%d")

    resp = _get(f"{API_BASE}/fixtures", params={"date": date_str})
    if resp.status_code != 200:
        raise RuntimeError(f"Fikstur alinamadi: HTTP {resp.status_code} - {resp.text[:200]}")

    payload = resp.json()
    matches = payload.get("response", [])

    fixtures = []
    for m in matches:
        fixture_info = m.get("fixture", {})
        league_info = m.get("league", {})
        teams = m.get("teams", {})
        goals = m.get("goals", {})

        status_short = (fixture_info.get("status") or {}).get("short", "NS")
        is_finished = status_short in ("FT", "AET", "PEN")
        status = "FINISHED" if is_finished else "SCHEDULED"

        fixtures.append({
            "fixture_id": fixture_info.get("id"),
            "home": (teams.get("home") or {}).get("name", "?"),
            "away": (teams.get("away") or {}).get("name", "?"),
            "home_id": (teams.get("home") or {}).get("id"),
            "away_id": (teams.get("away") or {}).get("id"),
            "league_id": league_info.get("id"),
            "season": league_info.get("season"),
            "utc_date": fixture_info.get("date", ""),
            "league": league_info.get("name", ""),
            "status": status,
            "home_goals": goals.get("home"),
            "away_goals": goals.get("away"),
            "ht_home_goals": ((m.get("score") or {}).get("halftime") or {}).get("home"),
            "ht_away_goals": ((m.get("score") or {}).get("halftime") or {}).get("away"),
        })

    fixtures.sort(key=lambda fx: fx.get("utc_date", ""))
    return fixtures[:limit]


# ----------------------------------------------------------------------
# 2) TAKIM İSTATİSTİKLERİ - /teams/statistics (gerçek sezon ortalaması)
# ----------------------------------------------------------------------
def build_team_stats(team_name: str, team_id: int, league_id: int = None, season: int = None) -> TeamStats:
    stats = TeamStats(name=team_name)

    if not team_id or not league_id or not season:
        return stats

    try:
        resp = _get(f"{API_BASE}/teams/statistics",
                     params={"team": team_id, "league": league_id, "season": season})
        if resp.status_code != 200:
            return stats

        data = resp.json().get("response", {})
        if not data:
            return stats

        fixtures_played = (data.get("fixtures", {}) or {}).get("played", {}) or {}
        played_total = fixtures_played.get("total", 0) or 0

        goals_for = (data.get("goals", {}) or {}).get("for", {}) or {}
        goals_against = (data.get("goals", {}) or {}).get("against", {}) or {}

        avg_for = (goals_for.get("average", {}) or {}).get("total")
        avg_against = (goals_against.get("average", {}) or {}).get("total")

        if avg_for is not None:
            stats.season_avg_goals_for = float(avg_for)
        if avg_against is not None:
            stats.season_avg_goals_against = float(avg_against)

        wins = (data.get("fixtures", {}) or {}).get("wins", {}).get("total", 0) or 0
        draws = (data.get("fixtures", {}) or {}).get("draws", {}).get("total", 0) or 0
        if played_total > 0:
            max_points = played_total * 3
            actual_points = wins * 3 + draws
            stats.season_form_score = actual_points / max_points if max_points else 0.5

    except Exception:
        pass

    return stats


def fetch_team_recent_matches(team_id: int, limit: int = 10) -> List[MatchResult]:
    return []


def fetch_head_to_head(match_id: int, limit: int = 5) -> HeadToHead:
    return HeadToHead(matches=[])


def load_market_value(team_name: str) -> float:
    return 0.0


# ----------------------------------------------------------------------
# 3) HAVA DURUMU
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
    league_id = raw_fixture.get("league_id")
    season = raw_fixture.get("season")

    home_stats = build_team_stats(raw_fixture["home"], raw_fixture["home_id"], league_id, season)
    away_stats = build_team_stats(raw_fixture["away"], raw_fixture["away_id"], league_id, season)

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
