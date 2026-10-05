import re
import html
import json
import sys
import atexit
import importlib
import importlib.util
import subprocess
from datetime import datetime
from pathlib import Path
import webbrowser
import os
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

def get_data_dir() -> Path:
    override = os.environ.get("MAPS_INTERCEPTOR_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return root / "MapsInterceptor"


DATA_DIR = get_data_dir()
DEPENDENCY_DIR = DATA_DIR / "python_packages"


def ensure_python_requirements():
    if DEPENDENCY_DIR.exists():
        sys.path.insert(0, str(DEPENDENCY_DIR))

    requirements = {"mitmproxy": "mitmproxy", "folium": "folium"}
    missing = []
    for module_name, package_name in requirements.items():
        already_loaded = module_name in sys.modules
        available = already_loaded or importlib.util.find_spec(module_name) is not None
        if not available:
            missing.append(package_name)

    if not missing:
        return

    DEPENDENCY_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[+] Installing missing Python requirements: {', '.join(missing)}")
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--target",
        str(DEPENDENCY_DIR),
        *missing,
    ]
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        packages = " ".join(missing)
        raise RuntimeError(
            f"Automatic dependency installation failed. Try: "
            f"{sys.executable} -m pip install {packages}"
        ) from exc

    if str(DEPENDENCY_DIR) not in sys.path:
        sys.path.insert(0, str(DEPENDENCY_DIR))
    importlib.invalidate_caches()
    unresolved = [name for name in requirements if importlib.util.find_spec(name) is None]
    if unresolved:
        raise RuntimeError(f"Installed packages could not be imported: {', '.join(unresolved)}")
    print(f"[+] Requirements installed in {DEPENDENCY_DIR}")


ensure_python_requirements()

from mitmproxy import http
import folium
from folium.plugins import Fullscreen

MAP_FILE = DATA_DIR / "live_maps_locations.html"
TIMESTAMP_FILE = DATA_DIR / "maps_last_update.txt"
_server_started = False

OPEN_BROWSER_ON_FIRST_LOCATION = False

AUTO_MANAGE_SYSTEM_PROXY = True
DEFAULT_PROXY_PORT = int(os.environ.get("MAPS_PROXY_PORT", "8080"))


class SystemProxyManager:

    def __init__(self):
        self.active = False
        self._mac_previous = {}
        self._windows_previous = {}
        atexit.register(self.restore)

    @staticmethod
    def _run(command):
        return subprocess.run(command, capture_output=True, text=True, timeout=8)

    @staticmethod
    def _proxy_fields(output):
        fields = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        return fields

    def _mac_active_services(self):
        route = self._run(["route", "-n", "get", "default"])
        match = re.search(r"^\s*interface:\s*(\S+)", route.stdout, re.MULTILINE)
        active_device = match.group(1) if match else None

        listing = self._run(["networksetup", "-listnetworkserviceorder"])
        if listing.returncode != 0:
            raise RuntimeError(listing.stderr.strip() or listing.stdout.strip())

        services = []
        pending_name = None
        for line in listing.stdout.splitlines():
            name_match = re.match(r"^\(\d+\)\s+(.+)$", line.strip())
            if name_match:
                pending_name = name_match.group(1).strip()
                continue
            device_match = re.search(r"Device:\s*([^\)]+)", line)
            if pending_name and device_match:
                services.append((pending_name, device_match.group(1).strip()))
                pending_name = None

        enabled_services = [(name, device) for name, device in services if not name.startswith("*")]
        if active_device:
            active = [name for name, device in enabled_services if device == active_device]
            if active:
                return active

        active = []
        for name, _ in enabled_services:
            info = self._run(["networksetup", "-getinfo", name])
            ip_match = re.search(r"^IP address:\s*(.+)$", info.stdout, re.MULTILINE)
            if ip_match and ip_match.group(1).strip().lower() not in {"none", "0.0.0.0"}:
                active.append(name)
        return active or [name for name, _ in enabled_services[:1]]

    def _mac_read_proxy(self, service, secure=False):
        option = "-getsecurewebproxy" if secure else "-getwebproxy"
        result = self._run(["networksetup", option, service])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return self._proxy_fields(result.stdout)

    def _mac_set_proxy(self, service, host, port, secure=False):
        option = "-setsecurewebproxy" if secure else "-setwebproxy"
        return self._run(["networksetup", option, service, host, str(port), "off"])

    def _mac_set_state(self, service, enabled, secure=False):
        option = "-setsecurewebproxystate" if secure else "-setwebproxystate"
        return self._run(["networksetup", option, service, "on" if enabled else "off"])

    def _enable_mac(self, host, port):
        services = self._mac_active_services()
        if not services:
            raise RuntimeError("No active macOS network service was found")

        for service in services:
            web = self._mac_read_proxy(service, secure=False)
            secure = self._mac_read_proxy(service, secure=True)
            authenticated_values = {"1", "yes", "on", "true"}
            if (
                web.get("Authenticated Proxy Enabled", "").lower() in authenticated_values
                or secure.get("Authenticated Proxy Enabled", "").lower() in authenticated_values
            ):
                raise RuntimeError(f"{service} uses an authenticated proxy; leaving it unchanged")
            self._mac_previous[service] = {"web": web, "secure": secure}

        for service in services:
            for secure in (False, True):
                changed = self._mac_set_proxy(service, host, port, secure)
                if changed.returncode != 0:
                    raise RuntimeError(changed.stderr.strip() or changed.stdout.strip())
                enabled = self._mac_set_state(service, True, secure)
                if enabled.returncode != 0:
                    raise RuntimeError(enabled.stderr.strip() or enabled.stdout.strip())

        self.active = True
        print(f"[+] System proxy enabled on {', '.join(services)} → {host}:{port}")

    @staticmethod
    def _windows_notify():
        import ctypes
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)
        internet_set_option(0, 37, 0, 0)

    def _enable_windows(self, host, port):
        import winreg
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            for name in ("ProxyEnable", "ProxyServer"):
                try:
                    value, value_type = winreg.QueryValueEx(key, name)
                    self._windows_previous[name] = (True, value, value_type)
                except FileNotFoundError:
                    self._windows_previous[name] = (False, None, None)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"http={host}:{port};https={host}:{port}")
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        self._windows_notify()
        self.active = True
        print(f"[+] Windows system proxy enabled → {host}:{port}")

    def enable(self, host="127.0.0.1", port=DEFAULT_PROXY_PORT):
        if self.active or not AUTO_MANAGE_SYSTEM_PROXY:
            return
        try:
            if sys.platform == "darwin":
                self._enable_mac(host, port)
            elif os.name == "nt":
                self._enable_windows(host, port)
            else:
                print("[!] Automatic system proxy is currently supported on macOS and Windows only.")
        except Exception as exc:
            if self._mac_previous:
                try:
                    self._restore_mac()
                except Exception as restore_exc:
                    print(f"[!] Partial proxy change also failed to roll back: {restore_exc}")
            print(f"[!] Could not enable the system proxy automatically: {exc}")
            print(f"    Set HTTP and HTTPS proxy to {host}:{port}, or run with permission to change network settings.")

    def _restore_mac(self):
        errors = []
        for service, previous in self._mac_previous.items():
            for label, secure in (("web", False), ("secure", True)):
                settings = previous[label]
                server = settings.get("Server", "")
                port = settings.get("Port", "0")
                was_enabled = settings.get("Enabled", "No").lower() == "yes"
                if server and port not in {"", "0"}:
                    result = self._mac_set_proxy(service, server, port, secure)
                    if result.returncode != 0:
                        errors.append(result.stderr.strip() or result.stdout.strip())
                state = self._mac_set_state(service, was_enabled, secure)
                if state.returncode != 0:
                    errors.append(state.stderr.strip() or state.stdout.strip())
        self._mac_previous.clear()
        self.active = False
        if errors:
            raise RuntimeError("; ".join(error for error in errors if error))

    def _restore_windows(self):
        import winreg
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            for name, (existed, value, value_type) in self._windows_previous.items():
                if existed:
                    winreg.SetValueEx(key, name, 0, value_type, value)
                else:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
        self._windows_previous.clear()
        self._windows_notify()
        self.active = False

    def restore(self):
        if not self.active and not self._mac_previous and not self._windows_previous:
            return
        try:
            if sys.platform == "darwin":
                self._restore_mac()
            elif os.name == "nt":
                self._restore_windows()
            print("[+] Previous system proxy settings restored")
        except Exception as exc:
            print(f"[!] Failed to restore previous system proxy settings: {exc}")

class MapServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith('/timestamp'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            try:
                with TIMESTAMP_FILE.open('r', encoding='utf-8') as f:
                    ts = f.read().strip()
            except Exception:
                ts = "0"
            self.wfile.write(ts.encode())
            return

        if self.path in ('/', '/live_maps_locations.html'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            try:
                with MAP_FILE.open('rb') as f:
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.wfile.write(b'''<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{margin:0;background:#07111f;color:#fff;font-family:Inter,Segoe UI,sans-serif;display:grid;place-items:center;min-height:100vh}
.waiting{text-align:center;max-width:480px;padding:42px;border:1px solid #24344d;border-radius:24px;background:#0c1a2c;box-shadow:0 24px 60px #0008}
.pulse{width:14px;height:14px;margin:0 auto 20px;border-radius:50%;background:#54e4a6;box-shadow:0 0 0 0 #54e4a688;animation:pulse 1.6s infinite}
h1{margin:0 0 8px;font-size:28px}p{margin:0;color:#9fb2cc;line-height:1.55}.setup{margin-top:22px;padding:16px;text-align:left;background:#ffffff09;border:1px solid #ffffff14;border-radius:14px}.setup b{color:#fff}.setup a{display:inline-block;margin-top:11px;padding:10px 14px;color:#07111f;background:#54e4a6;border-radius:9px;text-decoration:none;font-weight:800}@keyframes pulse{70%{box-shadow:0 0 0 16px #54e4a600}}
</style></head><body><div class="waiting"><div class="pulse"></div><h1>Map radar is live</h1><p>Waiting for the first location...</p><div class="setup"><p><b>First time on Firefox?</b><br>Install the mitmproxy certificate, trust it for identifying websites, then reload GeoGuessr.</p><a href="http://mitm.it">Open certificate setup</a></div></div></body></html>''')
            return

        self.send_error(404)

def start_map_server(port=8765):
    global _server_started
    if _server_started:
        return
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', port), MapServerHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[+] Map server running at http://127.0.0.1:{port}/")
        _server_started = True
    except OSError as e:
        port_in_use = (
            "Address already in use" in str(e)
            or getattr(e, "errno", None) in {48, 98, 10048}
            or getattr(e, "winerror", None) == 10048
        )
        if port_in_use:
            print(f"[+] Map server already on port {port}")
            _server_started = True
        else:
            raise


TARGET_HOST = "maps.googleapis.com"
TARGET_PATH = "/$rpc/google.internal.maps.mapsjs.v1.MapsJsInternalService/GetMetadata"
TARGET_ALLOW_PATTERN = r"^maps\.googleapis\.com:443$"

COUNTRY_CODES = {
    "AF": "Afghanistan", "AX": "Åland Islands", "AL": "Albania", "DZ": "Algeria",
    "AS": "American Samoa", "AD": "Andorra", "AO": "Angola", "AI": "Anguilla",
    "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina",
    "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria",
    "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh",
    "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize",
    "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia",
    "BQ": "Bonaire, Sint Eustatius and Saba", "BA": "Bosnia and Herzegovina",
    "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil",
    "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam",
    "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "CV": "Cabo Verde",
    "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "KY": "Cayman Islands",
    "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China",
    "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands", "CO": "Colombia",
    "KM": "Comoros", "CD": "Congo (Democratic Republic)", "CG": "Congo",
    "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Côte d'Ivoire", "HR": "Croatia",
    "CU": "Cuba", "CW": "Curaçao", "CY": "Cyprus", "CZ": "Czechia",
    "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica",
    "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt",
    "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea",
    "EE": "Estonia", "SZ": "Eswatini", "ET": "Ethiopia",
    "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands", "FJ": "Fiji",
    "FI": "Finland", "FR": "France", "GF": "French Guiana",
    "PF": "French Polynesia", "TF": "French Southern Territories", "GA": "Gabon",
    "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana",
    "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada",
    "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala", "GG": "Guernsey",
    "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti",
    "HM": "Heard Island and McDonald Islands", "VA": "Holy See", "HN": "Honduras",
    "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India",
    "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland",
    "IM": "Isle of Man", "IL": "Israel", "IT": "Italy", "JM": "Jamaica",
    "JP": "Japan", "JE": "Jersey", "JO": "Jordan", "KZ": "Kazakhstan",
    "KE": "Kenya", "KI": "Kiribati", "KP": "North Korea", "KR": "South Korea",
    "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Lao People's Democratic Republic",
    "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
    "MO": "Macao", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia",
    "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands",
    "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte",
    "MX": "Mexico", "FM": "Micronesia (Federated States of)", "MD": "Moldova",
    "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro", "MS": "Montserrat",
    "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia",
    "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "NC": "New Caledonia",
    "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria",
    "NU": "Niue", "NF": "Norfolk Island", "MK": "North Macedonia",
    "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman",
    "PK": "Pakistan", "PW": "Palau", "PS": "Palestine, State of",
    "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru",
    "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland", "PT": "Portugal",
    "PR": "Puerto Rico", "QA": "Qatar", "RE": "Réunion", "RO": "Romania",
    "RU": "Russian Federation", "RW": "Rwanda", "BL": "Saint Barthélemy",
    "SH": "Saint Helena, Ascension and Tristan da Cunha",
    "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
    "MF": "Saint Martin (French part)", "PM": "Saint Pierre and Miquelon",
    "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino",
    "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal",
    "RS": "Serbia", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
    "SX": "Sint Maarten (Dutch part)", "SK": "Slovakia", "SI": "Slovenia",
    "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
    "GS": "South Georgia and the South Sandwich Islands", "SS": "South Sudan",
    "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname",
    "SJ": "Svalbard and Jan Mayen", "SE": "Sweden", "CH": "Switzerland",
    "SY": "Syrian Arab Republic", "TW": "Taiwan (Province of China)",
    "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand",
    "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga",
    "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Türkiye",
    "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu",
    "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates",
    "GB": "United Kingdom", "US": "United States",
    "UM": "United States Minor Outlying Islands", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela",
    "VN": "Viet Nam", "VG": "Virgin Islands (British)",
    "VI": "Virgin Islands (U.S.)", "WF": "Wallis and Futuna",
    "EH": "Western Sahara", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe"
}

CONTINENTS = {
    "AF": "Africa", "AX": "Europe", "AL": "Europe", "DZ": "Africa",
    "AS": "Oceania", "AD": "Europe", "AO": "Africa", "AI": "North America",
    "AQ": "Antarctica", "AG": "North America", "AR": "South America",
    "AM": "Asia", "AW": "North America", "AU": "Oceania", "AT": "Europe",
    "AZ": "Asia", "BS": "North America", "BH": "Asia", "BD": "Asia",
    "BB": "North America", "BY": "Europe", "BE": "Europe", "BZ": "North America",
    "BJ": "Africa", "BM": "North America", "BT": "Asia", "BO": "South America",
    "BQ": "North America", "BA": "Europe", "BW": "Africa", "BV": "Antarctica",
    "BR": "South America", "IO": "Asia", "BN": "Asia", "BG": "Europe",
    "BF": "Africa", "BI": "Africa", "CV": "Africa", "KH": "Asia",
    "CM": "Africa", "CA": "North America", "KY": "North America",
    "CF": "Africa", "TD": "Africa", "CL": "South America", "CN": "Asia",
    "CX": "Asia", "CC": "Asia", "CO": "South America", "KM": "Africa",
    "CD": "Africa", "CG": "Africa", "CK": "Oceania", "CR": "North America",
    "CI": "Africa", "HR": "Europe", "CU": "North America", "CW": "North America",
    "CY": "Asia", "CZ": "Europe", "DK": "Europe", "DJ": "Africa",
    "DM": "North America", "DO": "North America", "EC": "South America",
    "EG": "Africa", "SV": "North America", "GQ": "Africa", "ER": "Africa",
    "EE": "Europe", "SZ": "Africa", "ET": "Africa", "FK": "South America",
    "FO": "Europe", "FJ": "Oceania", "FI": "Europe", "FR": "Europe",
    "GF": "South America", "PF": "Oceania", "TF": "Antarctica", "GA": "Africa",
    "GM": "Africa", "GE": "Asia", "DE": "Europe", "GH": "Africa",
    "GI": "Europe", "GR": "Europe", "GL": "North America", "GD": "North America",
    "GP": "North America", "GU": "Oceania", "GT": "North America",
    "GG": "Europe", "GN": "Africa", "GW": "Africa", "GY": "South America",
    "HT": "North America", "HM": "Antarctica", "VA": "Europe", "HN": "North America",
    "HK": "Asia", "HU": "Europe", "IS": "Europe", "IN": "Asia",
    "ID": "Asia", "IR": "Asia", "IQ": "Asia", "IE": "Europe",
    "IM": "Europe", "IL": "Asia", "IT": "Europe", "JM": "North America",
    "JP": "Asia", "JE": "Europe", "JO": "Asia", "KZ": "Asia",
    "KE": "Africa", "KI": "Oceania", "KP": "Asia", "KR": "Asia",
    "KW": "Asia", "KG": "Asia", "LA": "Asia", "LV": "Europe",
    "LB": "Asia", "LS": "Africa", "LR": "Africa", "LY": "Africa",
    "LI": "Europe", "LT": "Europe", "LU": "Europe", "MO": "Asia",
    "MG": "Africa", "MW": "Africa", "MY": "Asia", "MV": "Asia",
    "ML": "Africa", "MT": "Europe", "MH": "Oceania", "MQ": "North America",
    "MR": "Africa", "MU": "Africa", "YT": "Africa", "MX": "North America",
    "FM": "Oceania", "MD": "Europe", "MC": "Europe", "MN": "Asia",
    "ME": "Europe", "MS": "North America", "MA": "Africa", "MZ": "Africa",
    "MM": "Asia", "NA": "Africa", "NR": "Oceania", "NP": "Asia",
    "NL": "Europe", "NC": "Oceania", "NZ": "Oceania", "NI": "North America",
    "NE": "Africa", "NG": "Africa", "NU": "Oceania", "NF": "Oceania",
    "MK": "Europe", "MP": "Oceania", "NO": "Europe", "OM": "Asia",
    "PK": "Asia", "PW": "Oceania", "PS": "Asia", "PA": "North America",
    "PG": "Oceania", "PY": "South America", "PE": "South America",
    "PH": "Asia", "PN": "Oceania", "PL": "Europe", "PT": "Europe",
    "PR": "North America", "QA": "Asia", "RE": "Africa", "RO": "Europe",
    "RU": "Europe", "RW": "Africa", "BL": "North America", "SH": "Africa",
    "KN": "North America", "LC": "North America", "MF": "North America",
    "PM": "North America", "VC": "North America", "WS": "Oceania",
    "SM": "Europe", "ST": "Africa", "SA": "Asia", "SN": "Africa",
    "RS": "Europe", "SC": "Africa", "SL": "Africa", "SG": "Asia",
    "SX": "North America", "SK": "Europe", "SI": "Europe", "SB": "Oceania",
    "SO": "Africa", "ZA": "Africa", "GS": "Antarctica", "SS": "Africa",
    "ES": "Europe", "LK": "Asia", "SD": "Africa", "SR": "South America",
    "SJ": "Europe", "SE": "Europe", "CH": "Europe", "SY": "Asia",
    "TW": "Asia", "TJ": "Asia", "TZ": "Africa", "TH": "Asia",
    "TL": "Asia", "TG": "Africa", "TK": "Oceania", "TO": "Oceania",
    "TT": "North America", "TN": "Africa", "TR": "Asia", "TM": "Asia",
    "TC": "North America", "TV": "Oceania", "UG": "Africa", "UA": "Europe",
    "AE": "Asia", "GB": "Europe", "US": "North America", "UM": "Oceania",
    "UY": "South America", "UZ": "Asia", "VU": "Oceania", "VE": "South America",
    "VN": "Asia", "VG": "North America", "VI": "North America",
    "WF": "Oceania", "EH": "Africa", "YE": "Asia", "ZM": "Africa", "ZW": "Africa"
}

COUNTRY_CENTERS = {
    "AF": (33.0, 65.0), "AX": (60.116667, 19.9), "AL": (41.0, 20.0),
    "DZ": (28.0, 3.0), "AS": (-14.3333, -170.0), "AD": (42.5, 1.6),
    "AO": (-12.5, 18.5), "AI": (18.25, -63.1667), "AQ": (-90.0, 0.0),
    "AG": (17.05, -61.8), "AR": (-34.0, -64.0), "AM": (40.0, 45.0),
    "AW": (12.5, -69.9667), "AU": (-27.0, 133.0), "AT": (47.3333, 13.3333),
    "AZ": (40.5, 47.5), "BS": (24.25, -76.0), "BH": (26.0, 50.55),
    "BD": (24.0, 90.0), "BB": (13.1667, -59.5333), "BY": (53.0, 28.0),
    "BE": (50.8333, 4.0), "BZ": (17.25, -88.75), "BJ": (9.5, 2.25),
    "BM": (32.3333, -64.75), "BT": (27.5, 90.5), "BO": (-17.0, -65.0),
    "BQ": (12.183333, -68.233333), "BA": (44.0, 18.0), "BW": (-22.0, 24.0),
    "BV": (-54.4333, 3.4), "BR": (-10.0, -55.0), "IO": (-6.0, 71.5),
    "BN": (4.5, 114.6667), "BG": (43.0, 25.0), "BF": (13.0, -2.0),
    "BI": (-3.5, 30.0), "CV": (16.0, -24.0), "KH": (13.0, 105.0),
    "CM": (6.0, 12.0), "CA": (60.0, -95.0), "KY": (19.5, -80.5),
    "CF": (7.0, 21.0), "TD": (15.0, 19.0), "CL": (-30.0, -71.0),
    "CN": (35.0, 105.0), "CX": (-10.5, 105.6667), "CC": (-12.5, 96.8333),
    "CO": (4.0, -72.0), "KM": (-12.1667, 44.25), "CD": (0.0, 25.0),
    "CG": (-1.0, 15.0), "CK": (-21.2333, -159.7667), "CR": (10.0, -84.0),
    "CI": (8.0, -5.0), "HR": (45.1667, 15.5), "CU": (21.5, -80.0),
    "CW": (12.166667, -68.966667), "CY": (35.0, 33.0), "CZ": (49.75, 15.5),
    "DK": (56.0, 10.0), "DJ": (11.5, 43.0), "DM": (15.4167, -61.3333),
    "DO": (19.0, -70.6667), "EC": (-2.0, -77.5), "EG": (27.0, 30.0),
    "SV": (13.8333, -88.9167), "GQ": (2.0, 10.0), "ER": (15.0, 39.0),
    "EE": (59.0, 26.0), "SZ": (26.5, 31.5), "ET": (8.0, 38.0),
    "FK": (-51.75, -59.0), "FO": (62.0, -7.0), "FJ": (-18.0, 175.0),
    "FI": (64.0, 26.0), "FR": (46.0, 2.0), "GF": (4.0, -53.0),
    "PF": (-15.0, -140.0), "TF": (-43.0, 67.0), "GA": (-1.0, 11.75),
    "GM": (13.4667, -16.5667), "GE": (42.0, 43.5), "DE": (51.0, 9.0),
    "GH": (8.0, -2.0), "GI": (36.1833, -5.3667), "GR": (39.0, 22.0),
    "GL": (72.0, -40.0), "GD": (12.1167, -61.6667), "GP": (16.25, -61.5833),
    "GU": (13.4667, 144.7833), "GT": (15.5, -90.25), "GG": (49.5, -2.56),
    "GN": (11.0, -10.0), "GW": (12.0, -15.0), "GY": (5.0, -59.0),
    "HT": (19.0, -72.4167), "HM": (-53.1, 72.5167), "VA": (41.9, 12.45),
    "HN": (15.0, -86.5), "HK": (22.25, 114.1667), "HU": (47.0, 20.0),
    "IS": (65.0, -18.0), "IN": (20.0, 77.0), "ID": (-5.0, 120.0),
    "IR": (32.0, 53.0), "IQ": (33.0, 44.0), "IE": (53.0, -8.0),
    "IM": (54.23, -4.55), "IL": (31.5, 34.75), "IT": (42.8333, 12.8333),
    "JM": (18.25, -77.5), "JP": (36.0, 138.0), "JE": (49.21, -2.13),
    "JO": (31.0, 36.0), "KZ": (48.0, 68.0), "KE": (1.0, 38.0),
    "KI": (1.4167, 173.0), "KP": (40.0, 127.0), "KR": (37.0, 127.5),
    "KW": (29.3375, 47.6581), "KG": (41.0, 75.0), "LA": (18.0, 105.0),
    "LV": (57.0, 25.0), "LB": (33.8333, 35.8333), "LS": (-29.5, 28.5),
    "LR": (6.5, -9.5), "LY": (25.0, 17.0), "LI": (47.1667, 9.5333),
    "LT": (56.0, 24.0), "LU": (49.75, 6.1667), "MO": (22.1667, 113.55),
    "MG": (-20.0, 47.0), "MW": (-13.5, 34.0), "MY": (2.5, 112.5),
    "MV": (3.25, 73.0), "ML": (17.0, -4.0), "MT": (35.8333, 14.5833),
    "MH": (9.0, 168.0), "MQ": (14.6667, -61.0), "MR": (20.0, -12.0),
    "MU": (-20.2833, 57.55), "YT": (-12.8333, 45.1667), "MX": (23.0, -102.0),
    "FM": (6.9167, 158.25), "MD": (47.0, 29.0), "MC": (43.7333, 7.4),
    "MN": (46.0, 105.0), "ME": (42.5, 19.3), "MS": (16.75, -62.2),
    "MA": (32.0, -5.0), "MZ": (-18.25, 35.0), "MM": (22.0, 98.0),
    "NA": (-22.0, 17.0), "NR": (-0.5333, 166.9167), "NP": (28.0, 84.0),
    "NL": (52.5, 5.75), "NC": (-21.5, 165.5), "NZ": (-41.0, 174.0),
    "NI": (13.0, -85.0), "NE": (16.0, 8.0), "NG": (10.0, 8.0),
    "NU": (-19.0333, -169.8667), "NF": (-29.0333, 167.95), "MK": (41.8333, 22.0),
    "MP": (15.2, 145.75), "NO": (62.0, 10.0), "OM": (21.0, 57.0),
    "PK": (30.0, 70.0), "PW": (7.5, 134.5), "PS": (31.9, 35.2),
    "PA": (9.0, -80.0), "PG": (-6.0, 147.0), "PY": (-23.0, -58.0),
    "PE": (-10.0, -76.0), "PH": (13.0, 122.0), "PN": (-25.0, -130.0),
    "PL": (52.0, 20.0), "PT": (39.5, -8.0), "PR": (18.25, -66.5),
    "QA": (25.5, 51.25), "RE": (-21.1, 55.6), "RO": (46.0, 25.0),
    "RU": (60.0, 100.0), "RW": (-2.0, 30.0), "BL": (17.9, -62.85),
    "SH": (-15.95, -5.7), "KN": (17.3333, -62.75), "LC": (13.8833, -61.1333),
    "MF": (18.0833, -63.05), "PM": (47.0, -56.3333), "VC": (13.25, -61.2),
    "WS": (-13.5833, -172.3333), "SM": (43.9333, 12.4167), "ST": (1.0, 7.0),
    "SA": (25.0, 45.0), "SN": (14.0, -14.0), "RS": (44.0, 21.0),
    "SC": (-4.5833, 55.6667), "SL": (8.5, -11.5), "SG": (1.3667, 103.8),
    "SX": (18.0333, -63.0667), "SK": (48.6667, 19.5), "SI": (46.0, 15.0),
    "SB": (-8.0, 159.0), "SO": (10.0, 49.0), "ZA": (-29.0, 24.0),
    "GS": (-54.5, -37.0), "SS": (7.0, 30.0), "ES": (40.0, -4.0),
    "LK": (7.0, 81.0), "SD": (15.0, 30.0), "SR": (4.0, -56.0),
    "SJ": (78.0, 20.0), "SE": (62.0, 15.0), "CH": (46.8333, 8.3333),
    "SY": (35.0, 38.0), "TW": (23.5, 121.0), "TJ": (39.0, 71.0),
    "TZ": (-6.0, 35.0), "TH": (15.0, 100.0), "TL": (-8.8333, 125.9167),
    "TG": (8.0, 1.1667), "TK": (-9.0, -172.0), "TO": (-20.0, -175.0),
    "TT": (11.0, -61.0), "TN": (34.0, 9.0), "TR": (39.0, 35.0),
    "TM": (40.0, 60.0), "TC": (21.75, -71.5833), "TV": (-8.0, 178.0),
    "UG": (1.0, 32.0), "UA": (49.0, 32.0), "AE": (24.0, 54.0),
    "GB": (54.0, -2.0), "US": (38.0, -97.0), "UM": (19.2823, 166.647),
    "UY": (-33.0, -56.0), "UZ": (41.0, 64.0), "VU": (-16.0, 167.0),
    "VE": (8.0, -66.0), "VN": (16.0, 107.0), "VG": (18.5, -64.5),
    "VI": (18.3333, -64.8333), "WF": (-13.3, -176.2), "EH": (24.5, -13.0),
    "YE": (15.0, 48.0), "ZM": (-15.0, 30.0), "ZW": (-20.0, 30.0)
}


def get_country_zoom(country_code: str) -> int:
    continental_scale = {"RU", "CA"}
    very_large = {"US", "CN", "BR", "AU", "IN", "AR", "KZ", "DZ", "MX", "ID"}
    large = {
        "SA", "IR", "MN", "PE", "TD", "NE", "AO", "ML", "ZA", "CO",
        "BO", "MR", "EG", "ET", "NG", "VE", "PK", "TR", "CL", "UA",
    }
    compact = {
        "AD", "AI", "AG", "AW", "BH", "BB", "BM", "BQ", "CV", "CW",
        "DM", "FO", "GI", "GD", "GG", "HK", "IM", "JE", "KI", "LI",
        "LU", "MO", "MT", "MC", "NR", "PW", "PR", "KN", "LC", "MF",
        "SM", "SG", "SX", "TO", "TT", "TV", "VA", "VG", "VI",
    }
    if country_code in continental_scale:
        return 3
    if country_code in very_large:
        return 4
    if country_code in large:
        return 5
    if country_code in compact:
        return 8
    return 6


def country_flag(country_code: str) -> str:
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(char)) for char in country_code.upper())

def get_cardinal_direction(lat: float, lng: float, country_code: str) -> str:
    if country_code not in COUNTRY_CENTERS:
        return "Unknown"
    center_lat, center_lng = COUNTRY_CENTERS[country_code]
    dlat = lat - center_lat
    dlng = lng - center_lng

    if abs(dlat) < 1.0 and abs(dlng) < 1.0:
        return "Center"

    vert = "N" if dlat > 0.5 else "S" if dlat < -0.5 else ""
    horiz = "E" if dlng > 0.5 else "W" if dlng < -0.5 else ""

    if vert and horiz:
        return vert + horiz
    return vert or horiz or "Center"


def extract_location_data(text):
    data = {
        "country_code": None, "country_name": None, "continent": None,
        "direction": None, "locality": None, "administrative_area": None,
        "street_name": None, "coordinates": None, "feature_name": None,
    }

    country_match = re.search(r'"([A-Z]{2})"', text)
    if country_match:
        code = country_match.group(1)
        data["country_code"] = code
        data["country_name"] = COUNTRY_CODES.get(code, code)
        data["continent"] = CONTINENTS.get(code, "Unknown")

    coord_matches = re.findall(r'\[null,null,(-?\d+\.\d+),(-?\d+\.\d+)\]', text)
    if coord_matches:
        lat, lng = coord_matches[0]
        data["coordinates"] = {"latitude": float(lat), "longitude": float(lng)}
        if data["country_code"]:
            data["direction"] = get_cardinal_direction(float(lat), float(lng), code)

    name_matches = re.findall(r'\["([^"]+)","(el|el-Latn|en|[^"]+)"\]', text)
    for name, lang in name_matches:
        if lang == "el":
            data["feature_name"] = name
        elif lang == "el-Latn":
            data["street_name"] = name
        elif lang == "en" and not data.get("locality"):
            data["locality"] = name

    address_match = re.search(r'\["([^"]+,\s*[^"]+)","en"\]', text)
    if address_match:
        parts = address_match.group(1).split(", ")
        if len(parts) >= 2:
            data["locality"] = parts[0]
            data["administrative_area"] = parts[1]

    return data


class MapsInterceptor:
    def __init__(self):
        self.latest_location = None
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.map_file = MAP_FILE
        self.first_open = True
        self.last_city_key = None
        self.proxy_manager = SystemProxyManager()
        start_map_server()

    def running(self):
        proxy_port = DEFAULT_PROXY_PORT
        try:
            from mitmproxy import ctx
            proxy_port = int(getattr(ctx.options, "listen_port", proxy_port) or proxy_port)
        except Exception:
            pass
        self.proxy_manager.enable("127.0.0.1", proxy_port)

    def done(self):
        self.proxy_manager.restore()

    def request(self, flow: http.HTTPFlow) -> None:
        if TARGET_HOST in flow.request.pretty_host and TARGET_PATH in flow.request.path:
            print("\n" + "="*80)
            print(f"[+] MAPS METADATA REQUEST")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"URL: {flow.request.pretty_url}")
            print("="*80)

    def update_live_map(self):
        if not self.latest_location or not self.latest_location.get("coordinates"):
            return

        lat = self.latest_location["coordinates"]["latitude"]
        lng = self.latest_location["coordinates"]["longitude"]

        code = self.latest_location.get("country_code") or "??"
        country = self.latest_location.get("country_name") or "Unknown country"
        continent = self.latest_location.get("continent") or "Unknown continent"
        locality = (
            self.latest_location.get("locality")
            or self.latest_location.get("feature_name")
            or "Unknown location"
        )
        region = self.latest_location.get("administrative_area") or "Region unavailable"
        feature = (
            self.latest_location.get("feature_name")
            or self.latest_location.get("street_name")
            or "Feature unavailable"
        )
        direction = self.latest_location.get("direction") or "—"
        center_lat, center_lng = COUNTRY_CENTERS.get(code, (lat, lng))
        country_zoom = get_country_zoom(code)
        region_zoom = min(10, max(7, country_zoom + 2))
        detail_zoom = 14

        safe = {
            "code": html.escape(code),
            "country": html.escape(country),
            "continent": html.escape(continent),
            "locality": html.escape(locality),
            "region": html.escape(region),
            "feature": html.escape(feature),
            "direction": html.escape(direction),
            "flag": country_flag(code),
        }

        m = folium.Map(
            location=[center_lat, center_lng],
            zoom_start=country_zoom,
            tiles=None,
            zoom_control=False,
            control_scale=True,
            prefer_canvas=True,
            world_copy_jump=True,
            zoom_snap=0.5,
            min_zoom=2,
        )
        city_tiles = folium.TileLayer(
            tiles=(
                "https://server.arcgisonline.com/ArcGIS/rest/services/"
                "World_Street_Map/MapServer/tile/{z}/{y}/{x}"
            ),
            attr=(
                "Tiles &copy; Esri &mdash; Source: Esri, DeLorme, NAVTEQ, "
                "USGS, Intermap, iPC, NRCAN, Esri Japan, METI, Esri China "
                "(Hong Kong), Esri (Thailand), TomTom"
            ),
            name="City finder",
            control=False,
            show=True,
            max_zoom=19,
        ).add_to(m)
        road_tiles = folium.TileLayer(
            tiles=(
                "https://{s}.basemaps.cartocdn.com/rastertiles/"
                "voyager/{z}/{x}/{y}{r}.png"
            ),
            attr="&copy; OpenStreetMap contributors &copy; CARTO",
            name="Road map",
            control=False,
            show=False,
            max_zoom=20,
            subdomains="abcd",
        ).add_to(m)
        detail_tiles = folium.TileLayer(
            tiles="OpenStreetMap",
            name="Detailed",
            control=False,
            show=False,
        ).add_to(m)
        terrain_tiles = folium.TileLayer(
            tiles=(
                "https://server.arcgisonline.com/ArcGIS/rest/services/"
                "World_Topo_Map/MapServer/tile/{z}/{y}/{x}"
            ),
            attr="Tiles &copy; Esri and contributors",
            name="Terrain",
            control=False,
            show=False,
            max_zoom=19,
        ).add_to(m)
        satellite_tiles = folium.TileLayer(
            tiles=(
                "https://server.arcgisonline.com/ArcGIS/rest/services/"
                "World_Imagery/MapServer/tile/{z}/{y}/{x}"
            ),
            attr="Tiles &copy; Esri and contributors",
            name="Satellite",
            control=False,
            show=False,
            max_zoom=19,
        ).add_to(m)
        satellite_labels = folium.TileLayer(
            tiles=(
                "https://services.arcgisonline.com/ArcGIS/rest/services/Reference/"
                "World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}"
            ),
            attr="Labels &copy; Esri and contributors",
            name="Satellite labels",
            overlay=True,
            control=False,
            show=False,
            max_zoom=19,
            opacity=0.95,
        ).add_to(m)
        night_tiles = folium.TileLayer(
            tiles=(
                "https://{s}.basemaps.cartocdn.com/dark_all/"
                "{z}/{x}/{y}{r}.png"
            ),
            attr="&copy; OpenStreetMap contributors &copy; CARTO",
            name="Night",
            control=False,
            show=False,
            max_zoom=20,
            subdomains="abcd",
        ).add_to(m)

        popup_html = f"""
        <div style="font-family:Inter,Segoe UI,sans-serif;min-width:260px;padding:4px;color:#10243f">
            <div style="font-size:11px;font-weight:800;letter-spacing:.13em;text-transform:uppercase;color:#55708f;margin-bottom:7px">Exact location</div>
            <div style="font-size:20px;font-weight:800;margin-bottom:10px">{safe['locality']}</div>
            <div style="line-height:1.65;color:#435a73">
                <b style="color:#10243f">{safe['country']}</b> · {safe['region']}<br>
                {safe['feature']}<br>
                <span style="font-family:ui-monospace,SFMono-Regular,monospace">{lat:.6f}, {lng:.6f}</span>
            </div>
        </div>
        """

        marker_icon = folium.DivIcon(
            html='''<div class="radar-marker"><span></span></div>''',
            icon_size=(36, 36),
            icon_anchor=(18, 18),
        )
        folium.Marker(
            [lat, lng],
            popup=folium.Popup(popup_html, max_width=340),
            tooltip=f"{safe['locality']} · {safe['country']}",
            icon=marker_icon,
        ).add_to(m)
        folium.Marker(
            [lat, lng],
            icon=folium.DivIcon(
                html=(
                    f'''<div class="target-label"><b>{safe['locality']}</b>'''
                    f'''<span>{safe['region']}</span></div>'''
                ),
                icon_size=(180, 48),
                icon_anchor=(-18, 24),
            ),
            interactive=False,
        ).add_to(m)
        folium.Circle(
            [lat, lng],
            radius=3000,
            color="#635bff",
            weight=2,
            fill=True,
            fill_color="#635bff",
            fill_opacity=0.11,
        ).add_to(m)
        if (center_lat, center_lng) != (lat, lng):
            country_icon = folium.DivIcon(
                html=f'''<div class="country-anchor"><span>{safe['flag']}</span><b>{safe['code']}</b></div>''',
                icon_size=(64, 32),
                icon_anchor=(32, 16),
            )
            folium.Marker(
                [center_lat, center_lng],
                icon=country_icon,
                tooltip=f"Approximate center of {safe['country']}",
            ).add_to(m)
            folium.PolyLine(
                [[center_lat, center_lng], [lat, lng]],
                color="#635bff",
                weight=2,
                opacity=0.38,
                dash_array="5 9",
                tooltip=f"{safe['direction']} of country center",
            ).add_to(m)

        Fullscreen(
            position="bottomright",
            title="Full screen",
            title_cancel="Exit full screen",
            force_separate_button=True,
        ).add_to(m)

        map_name = m.get_name()
        tile_names = {
            "city": city_tiles.get_name(),
            "roads": road_tiles.get_name(),
            "detail": detail_tiles.get_name(),
            "terrain": terrain_tiles.get_name(),
            "satellite": satellite_tiles.get_name(),
            "satellite_labels": satellite_labels.get_name(),
            "night": night_tiles.get_name(),
        }
        now_label = datetime.now().strftime("%H:%M:%S")
        ui_html = f"""
        <style>
            :root {{
                --ink:#10223b; --muted:#65758b; --accent:#5b5cf0;
                --accent2:#00b894; --panel:rgba(255,255,255,.94);
                --night:rgba(7,17,31,.92); --hairline:rgba(16,34,59,.11);
            }}
            html,body,#map {{font-family:Inter,"SF Pro Display","Segoe UI",system-ui,sans-serif!important}}
            .leaflet-container {{background:#dbe7f4}}
            .leaflet-control-attribution {{opacity:.52}}
            .leaflet-control-scale {{margin-left:14px!important;margin-bottom:14px!important}}
            .leaflet-control-scale-line {{
                border-color:var(--ink)!important;color:var(--ink)!important;
                background:#ffffffd6!important;border-radius:0 0 5px 5px;
                font-weight:750!important;backdrop-filter:blur(10px);
            }}
            .leaflet-bottom.leaflet-right {{bottom:74px;right:10px}}
            .leaflet-bar {{border:0!important;border-radius:14px!important;overflow:hidden;box-shadow:0 10px 30px #10223b2d!important}}
            .leaflet-bar a {{color:var(--ink)!important;border-color:#e5eaf1!important;width:34px!important;height:34px!important;line-height:34px!important}}
            .radar-marker {{
                position:relative;width:44px;height:44px;border-radius:50%;display:grid;place-items:center;
                background:rgba(91,92,240,.14);border:1px solid rgba(91,92,240,.24);
                box-shadow:0 0 0 0 rgba(91,92,240,.42);animation:radar 2.4s ease-out infinite;
            }}
            .radar-marker span {{
                position:relative;width:15px;height:15px;border-radius:50%;background:linear-gradient(135deg,#7879ff,#4b4cd7);
                border:4px solid white;box-shadow:0 6px 18px rgba(54,46,160,.5);z-index:2;
            }}
            .radar-marker:before,.radar-marker:after {{content:"";position:absolute;background:rgba(91,92,240,.5);border-radius:2px}}
            .radar-marker:before {{width:58px;height:1px;left:-8px;top:21px}}
            .radar-marker:after {{width:1px;height:58px;left:21px;top:-8px}}
            @keyframes radar {{0%{{box-shadow:0 0 0 0 rgba(91,92,240,.42)}}75%,100%{{box-shadow:0 0 0 28px rgba(91,92,240,0)}}}}
            @media (prefers-reduced-motion:reduce) {{.radar-marker{{animation:none}}}}
            .country-anchor {{
                width:58px;height:28px;display:flex;align-items:center;justify-content:center;gap:6px;
                color:var(--ink);background:#fffffff2;border:1px solid #fff;
                border-radius:999px;box-shadow:0 8px 22px #10223b35;
                font:850 11px/1 ui-monospace,SFMono-Regular,monospace;letter-spacing:.08em;
            }}
            .country-anchor span {{font-size:16px;line-height:1}}
            .target-label {{
                width:max-content;max-width:190px;padding:8px 11px;color:var(--ink);
                background:#fffffff2;border:1px solid #fff;border-radius:11px;
                box-shadow:0 9px 26px #10223b35;white-space:nowrap;opacity:0;
                transform:translateY(4px);transition:opacity .2s ease,transform .2s ease;
            }}
            .target-label.visible {{opacity:1;transform:translateY(0)}}
            .target-label b {{display:block;overflow:hidden;text-overflow:ellipsis;font-size:13px;line-height:1.15}}
            .target-label span {{display:block;margin-top:3px;overflow:hidden;text-overflow:ellipsis;color:#63758b;font-size:10px;line-height:1.1}}
            .map-tools {{
                position:fixed;z-index:1002;top:14px;right:14px;display:flex;align-items:center;gap:8px;
                padding:7px;color:white;background:var(--night);border:1px solid rgba(255,255,255,.13);
                border-radius:15px;box-shadow:0 12px 34px rgba(6,17,32,.28);backdrop-filter:blur(18px);
            }}
            .map-style-control {{display:flex;align-items:center;gap:7px}}
            .map-style-control label {{padding-left:4px;font-size:9px;font-weight:850;letter-spacing:.12em;text-transform:uppercase;color:#a8b9cc}}
            .map-style-control select {{
                min-width:154px;padding:9px 31px 9px 11px;color:#fff;background:#ffffff12;
                border:1px solid #ffffff1f;border-radius:10px;font:750 12px/1 system-ui;
                outline:none;cursor:pointer;color-scheme:dark;
            }}
            .map-style-control select:focus {{border-color:#8687ff;box-shadow:0 0 0 3px #5b5cf03b}}
            .compass {{
                position:fixed;z-index:1001;top:75px;right:15px;width:43px;height:43px;
                display:grid;place-items:center;color:var(--ink);background:#fffffff0;border:1px solid #fff;
                border-radius:50%;box-shadow:0 8px 24px #10223b2b;font:850 10px/1 system-ui;
            }}
            .compass:before {{content:"";position:absolute;top:7px;border-left:5px solid transparent;border-right:5px solid transparent;border-bottom:9px solid #e64a64}}
            .compass span {{margin-top:12px}}
            .country-card {{
                position:fixed;z-index:1001;top:14px;left:14px;width:min(350px,calc(100vw - 28px));
                box-sizing:border-box;padding:21px;color:var(--ink);background:var(--panel);
                border:1px solid rgba(255,255,255,.88);border-radius:20px;
                box-shadow:0 18px 52px rgba(16,34,59,.2);backdrop-filter:blur(22px) saturate(1.15);
                transition:width .24s ease,padding .24s ease;
            }}
            .panel-toggle {{
                position:absolute;top:13px;right:13px;width:30px;height:30px;border:1px solid #dfe5ed;
                border-radius:9px;color:#54677d;background:#f4f7fb;font-size:18px;line-height:1;cursor:pointer;transition:.18s;
            }}
            .panel-toggle:hover {{color:var(--accent);background:#ececff;border-color:#d7d7ff}}
            .eyebrow {{font-size:10px;font-weight:850;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}}
            .country-line {{display:flex;align-items:center;gap:12px;margin:8px 38px 3px 0}}
            .flag {{font-size:37px;filter:drop-shadow(0 5px 8px #10223b25)}}
            .country-name {{font-size:clamp(25px,3vw,34px);line-height:1.03;font-weight:850;letter-spacing:-.04em}}
            .iso {{display:inline-flex;margin-top:7px;padding:5px 8px;border-radius:7px;background:#eeeeff;color:#4d4ed4;font:800 10px/1 ui-monospace,monospace;letter-spacing:.11em}}
            .trail {{display:flex;flex-wrap:wrap;gap:6px;margin:17px 0 15px;color:var(--muted);font-size:12px}}
            .trail b {{color:var(--ink)}} .chev {{opacity:.45}}
            .facts {{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:15px}}
            .fact {{padding:10px 11px;background:#f4f7fb;border:1px solid #e7ecf2;border-radius:11px}}
            .fact-label {{font-size:9px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:#8190a3}}
            .fact-value {{margin-top:4px;font-size:12px;font-weight:750;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
            .view-switch {{display:grid;grid-template-columns:repeat(3,1fr);gap:5px;padding:5px;background:#e9eef5;border-radius:13px}}
            .view-btn {{border:0;border-radius:9px;padding:10px 6px;background:transparent;color:#586b80;font-size:11px;font-weight:800;cursor:pointer;transition:.18s}}
            .view-btn:hover {{color:var(--ink)}}
            .view-btn.active {{background:#fff;color:var(--accent);box-shadow:0 3px 12px #172c491b}}
            .update-row {{display:flex;align-items:center;justify-content:space-between;margin-top:12px;color:#8795a7;font-size:9px;font-weight:750;letter-spacing:.08em;text-transform:uppercase}}
            .live-state {{display:flex;align-items:center;gap:6px;color:#34856c}}
            .live-dot {{width:7px;height:7px;border-radius:50%;background:#36d399;box-shadow:0 0 0 4px #36d3991f}}
            .country-card.collapsed {{width:245px;padding:15px 46px 15px 15px}}
            .country-card.collapsed .eyebrow,.country-card.collapsed .trail,.country-card.collapsed .facts,.country-card.collapsed .view-switch,.country-card.collapsed .iso,.country-card.collapsed .update-row {{display:none}}
            .country-card.collapsed .country-line {{margin:0;gap:9px}}
            .country-card.collapsed .flag {{font-size:26px}}
            .country-card.collapsed .country-name {{font-size:20px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px}}
            .coords {{
                position:fixed;z-index:1000;left:50%;bottom:13px;transform:translateX(-50%);
                display:flex;align-items:center;gap:10px;padding:8px 9px 8px 13px;color:white;
                background:var(--night);border:1px solid rgba(255,255,255,.12);border-radius:13px;
                box-shadow:0 10px 32px rgba(6,17,32,.26);backdrop-filter:blur(16px);
                font:700 11px/1 ui-monospace,SFMono-Regular,monospace;
            }}
            .copy-btn {{border:0;border-radius:8px;padding:7px 10px;background:#ffffff15;color:white;font:750 10px/1 system-ui;cursor:pointer}}
            .copy-btn:hover {{background:#ffffff28}}
            .map-hint {{position:fixed;z-index:999;right:13px;bottom:16px;color:#526579;background:#ffffffd9;padding:7px 9px;border-radius:9px;font-size:9px;font-weight:750;backdrop-filter:blur(10px)}}
            @media (max-width:1100px) and (min-width:521px) {{
                .map-tools{{top:9px;right:9px;padding:6px}}
                .map-style-control label{{display:none}} .map-style-control select{{min-width:142px;padding:8px 28px 8px 10px}}
                .compass{{top:66px;right:10px}}
                .country-card{{top:9px;left:9px;width:294px;padding:17px;border-radius:18px}}
                .panel-toggle{{top:10px;right:10px}}
                .country-name{{font-size:27px;max-width:195px}} .flag{{font-size:32px}}
                .trail{{margin:13px 0}} .facts{{display:none}}
                .view-btn{{padding:9px 4px;font-size:10px}}
                .coords{{left:calc(50vw + 145px);bottom:10px;max-width:calc(100vw - 338px);overflow:hidden}}
                .coords span{{overflow:hidden;text-overflow:ellipsis}} .map-hint{{display:none}}
                .leaflet-bottom.leaflet-right{{bottom:58px;right:7px}}
            }}
            @media (max-width:520px) {{
                .map-tools{{top:7px;right:7px;padding:5px}}
                .map-style-control label{{display:none}} .map-style-control select{{min-width:129px;padding:8px 25px 8px 9px;font-size:11px}}
                .compass{{display:none}}
                .country-card{{top:56px;left:7px;width:calc(100vw - 14px);padding:15px}}
                .country-name{{font-size:24px;max-width:calc(100vw - 150px)}} .flag{{font-size:29px}} .facts{{display:none}} .trail{{margin:11px 0}}
                .coords{{bottom:8px;max-width:calc(100vw - 95px);white-space:nowrap}} .map-hint{{display:none}}
                .leaflet-bottom.leaflet-right{{bottom:57px;right:6px}}
            }}
        </style>
        <div class="map-tools">
            <div class="map-style-control">
                <label for="mapStyle">Map style</label>
                <select id="mapStyle" aria-label="Map style">
                    <option value="city">City finder</option>
                    <option value="roads">Road map</option>
                    <option value="detail">Detailed</option>
                    <option value="terrain">Terrain</option>
                    <option value="satellite">Satellite + labels</option>
                    <option value="night">Night map</option>
                </select>
            </div>
        </div>
        <div class="compass" aria-label="North"><span>N</span></div>
        <section class="country-card" aria-label="Current country and location">
            <button id="panelToggle" class="panel-toggle" type="button" aria-expanded="true" title="Collapse panel">&minus;</button>
            <div class="eyebrow">You are in</div>
            <div class="country-line"><span class="flag">{safe['flag']}</span><div><div class="country-name">{safe['country']}</div><span class="iso">{safe['code']}</span></div></div>
            <div class="trail"><span>{safe['continent']}</span><span class="chev">›</span><b>{safe['region']}</b><span class="chev">›</span><b>{safe['locality']}</b></div>
            <div class="facts">
                <div class="fact"><div class="fact-label">Position</div><div class="fact-value">{safe['direction']} of center</div></div>
                <div class="fact"><div class="fact-label">Nearest feature</div><div class="fact-value" title="{safe['feature']}">{safe['feature']}</div></div>
            </div>
            <div class="view-switch" role="group" aria-label="Map zoom">
                <button id="countryView" class="view-btn active" type="button" aria-pressed="true">Country</button>
                <button id="areaView" class="view-btn" type="button" aria-pressed="false">Cities</button>
                <button id="detailView" class="view-btn" type="button" aria-pressed="false">Exact</button>
            </div>
            <div class="update-row"><span class="live-state"><span class="live-dot"></span>Live</span><span>Updated {now_label}</span></div>
        </section>
        <div class="coords"><span>{lat:.6f}, {lng:.6f}</span><button id="copyCoords" class="copy-btn" type="button">Copy</button></div>
        <div class="map-hint">1 country · 2 cities · 3 exact · M style · H panel</div>
        """
        m.get_root().html.add_child(folium.Element(ui_html))

        control_script = f"""
        window.addEventListener('load', function() {{
            var map = {map_name};
            var countryButton = document.getElementById('countryView');
            var areaButton = document.getElementById('areaView');
            var detailButton = document.getElementById('detailView');
            var countryCard = document.querySelector('.country-card');
            var panelToggle = document.getElementById('panelToggle');
            var mapStyle = document.getElementById('mapStyle');
            var baseLayers = {{
                city: {tile_names['city']},
                roads: {tile_names['roads']},
                detail: {tile_names['detail']},
                terrain: {tile_names['terrain']},
                satellite: {tile_names['satellite']},
                night: {tile_names['night']}
            }};
            var satelliteLabels = {tile_names['satellite_labels']};
            L.control.zoom({{position:'bottomright'}}).addTo(map);
            function setMapStyle(style, remember) {{
                if (!baseLayers[style]) style = 'city';
                Object.keys(baseLayers).forEach(function(key) {{
                    if (map.hasLayer(baseLayers[key])) map.removeLayer(baseLayers[key]);
                }});
                if (map.hasLayer(satelliteLabels)) map.removeLayer(satelliteLabels);
                map.addLayer(baseLayers[style]);
                if (style === 'satellite') map.addLayer(satelliteLabels);
                mapStyle.value = style;
                if (remember) {{
                    try {{ localStorage.setItem('mapHelperStyle', style); }} catch (error) {{}}
                }}
            }}
            var savedStyle = 'city';
            try {{ savedStyle = localStorage.getItem('mapHelperStyle') || 'city'; }} catch (error) {{}}
            setMapStyle(savedStyle, false);
            mapStyle.addEventListener('change', function() {{ setMapStyle(this.value, true); }});
            function activate(button) {{
                [countryButton, areaButton, detailButton].forEach(function(item) {{
                    item.classList.remove('active');
                    item.setAttribute('aria-pressed', 'false');
                }});
                button.classList.add('active');
                button.setAttribute('aria-pressed', 'true');
            }}
            function updateZoomUI() {{
                var zoom = map.getZoom();
                if (zoom >= {detail_zoom - 1}) activate(detailButton);
                else if (zoom >= {region_zoom - 0.5}) activate(areaButton);
                else activate(countryButton);
                document.querySelectorAll('.target-label').forEach(function(label) {{
                    label.classList.toggle('visible', zoom >= {region_zoom - 0.5});
                }});
            }}
            function panelOffset() {{
                if (window.innerWidth <= 520) return 0;
                return Math.min((countryCard.offsetWidth / 2) + 12, 190);
            }}
            function focusMap(target, zoom, button) {{
                var offset = panelOffset();
                if (offset) {{
                    map.once('moveend', function() {{ map.panBy([-offset, 0], {{animate:true, duration:.24}}); }});
                }}
                map.flyTo(target, zoom, {{duration:.72}});
                activate(button);
            }}
            function showCountry() {{ focusMap([{center_lat:.7f},{center_lng:.7f}],{country_zoom},countryButton); }}
            function showArea() {{ focusMap([{lat:.7f},{lng:.7f}],{region_zoom},areaButton); }}
            function showDetail() {{ focusMap([{lat:.7f},{lng:.7f}],{detail_zoom},detailButton); }}
            function setPanelCollapsed(collapsed, remember) {{
                var oldOffset = panelOffset();
                countryCard.classList.toggle('collapsed', collapsed);
                panelToggle.innerHTML = collapsed ? '&plus;' : '&minus;';
                panelToggle.title = collapsed ? 'Expand panel' : 'Collapse panel';
                panelToggle.setAttribute('aria-expanded', String(!collapsed));
                if (remember) {{
                    try {{ localStorage.setItem('mapHelperPanelCollapsed', collapsed ? '1' : '0'); }} catch (error) {{}}
                }}
                setTimeout(function() {{
                    var newOffset = panelOffset();
                    map.panBy([oldOffset - newOffset, 0], {{animate:true, duration:.22}});
                }}, 260);
            }}
            function togglePanel() {{ setPanelCollapsed(!countryCard.classList.contains('collapsed'), true); }}
            countryButton.addEventListener('click', showCountry);
            areaButton.addEventListener('click', showArea);
            detailButton.addEventListener('click', showDetail);
            panelToggle.addEventListener('click', togglePanel);
            map.on('zoomend', updateZoomUI);
            document.addEventListener('keydown', function(event) {{
                if (event.target && /input|textarea|select/i.test(event.target.tagName)) return;
                if (event.key === '1' || event.key.toLowerCase() === 'c') showCountry();
                if (event.key === '2' || event.key.toLowerCase() === 'a') showArea();
                if (event.key === '3' || event.key.toLowerCase() === 'l') showDetail();
                if (event.key.toLowerCase() === 'm') {{
                    var styles = ['city','roads','detail','terrain','satellite','night'];
                    var next = styles[(styles.indexOf(mapStyle.value) + 1) % styles.length];
                    setMapStyle(next, true);
                }}
                if (event.key.toLowerCase() === 'h') togglePanel();
            }});
            document.getElementById('copyCoords').addEventListener('click', function() {{
                var button = this;
                navigator.clipboard.writeText('{lat:.7f}, {lng:.7f}').then(function() {{
                    button.textContent='Copied'; setTimeout(function(){{button.textContent='Copy'}},1200);
                }});
            }});
            document.title = {json.dumps(country + ' · Map Helper')};
            setTimeout(function() {{
                var collapsed = false;
                try {{ collapsed = localStorage.getItem('mapHelperPanelCollapsed') === '1'; }} catch (error) {{}}
                if (collapsed) {{
                    countryCard.classList.add('collapsed');
                    panelToggle.innerHTML = '&plus;';
                    panelToggle.title = 'Expand panel';
                    panelToggle.setAttribute('aria-expanded', 'false');
                }}
                var offset = panelOffset();
                if (offset) map.panBy([-offset, 0], {{animate:false}});
                updateZoomUI();
            }}, 0);
        }});
        """
        m.get_root().script.add_child(folium.Element(control_script))

        refresh_script = (
            '<script>\n'
            '    (function() {\n'
            '        var pageTime = Date.now();\n'
            '        function check() {\n'
            '            fetch("/timestamp?t=" + Date.now(), {cache: "no-store"})\n'
            '                .then(function(r) { return r.text(); })\n'
            '                .then(function(t) {\n'
            '                    var serverTime = parseInt(t, 10) || 0;\n'
            '                    if (serverTime > pageTime + 500) {\n'
            '                        window.location.reload(true);\n'
            '                    }\n'
            '                })\n'
            '                .catch(function(e) { console.error("Poll error:", e); });\n'
            '        }\n'
            '        check();\n'
            '        setInterval(check, 1200);\n'
            '    })();\n'
            '</script>'
        )
        m.get_root().html.add_child(folium.Element(refresh_script))

        m.save(self.map_file)
        
        try:
            with TIMESTAMP_FILE.open('w', encoding='utf-8') as f:
                f.write(str(int(time.time() * 1000)))
        except Exception as e:
            print(f"[!] Failed to write timestamp: {e}")

        if self.first_open:
            if OPEN_BROWSER_ON_FIRST_LOCATION:
                print(f"\n[🗺️  Opening live map (single tab)]")
                webbrowser.open("http://127.0.0.1:8765/", new=2)
            else:
                print(f"\n[🗺️  Live map ready: http://127.0.0.1:8765/]")
                print("   Browser auto-open is off, so your current window keeps focus.")
            self.first_open = False
        else:
            print(f"\n[🗺️  New city detected → existing map tab will refresh in place]")

    def response(self, flow: http.HTTPFlow) -> None:
        if TARGET_HOST in flow.request.pretty_host and TARGET_PATH in flow.request.path:
            print("\n" + "="*80)
            print(f"[+] MAPS METADATA RESPONSE")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Status: {flow.response.status_code}")

            if flow.response.content:
                try:
                    text = flow.response.content.decode('utf-8', errors='ignore')
                    location = extract_location_data(text)

                    print("\n--- LOCATION DETAILS ---")
                    if location.get("country_name"):
                        print(f"Country   : {location['country_name']} ({location['country_code']})")
                        print(f"Continent : {location['continent']}")
                        if location.get("direction"):
                            print(f"Direction : {location['direction']}")

                    if location.get("locality"):
                        print(f"City      : {location['locality']}")
                    if location.get("administrative_area"):
                        print(f"Region    : {location['administrative_area']}")
                    if location.get("feature_name"):
                        print(f"Feature   : {location['feature_name']}")

                    if location.get("coordinates"):
                        lat = location["coordinates"]["latitude"]
                        lng = location["coordinates"]["longitude"]
                        print(f"Coords    : {lat:.7f}, {lng:.7f}")
                        print(f"Google Maps : https://www.google.com/maps?q={lat},{lng}")

                    if location.get("coordinates"):
                        city_name = location.get("locality") or location.get("feature_name") or "Unknown"
                        current_key = (location["country_code"], city_name)

                        if current_key != self.last_city_key:
                            self.latest_location = location.copy()
                            self.last_city_key = current_key
                            self.update_live_map()
                            print(f"   → NEW CITY → map updated + reload armed")
                        else:
                            print(f"   (same city)")

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    response_file = DATA_DIR / f"maps_response_{timestamp}.txt"
                    with response_file.open("w", encoding="utf-8") as f:
                        f.write(text)

                except Exception as e:
                    print(f"Error: {e}")

            print("="*80 + "\n")


def run_standalone():
    from mitmproxy.tools.main import mitmdump

    script_path = str(Path(__file__).resolve())
    print("\n[+] Starting GeoGuessr map helper")
    print(f"[+] Proxy: 127.0.0.1:{DEFAULT_PROXY_PORT}")
    print("[+] Map:   http://127.0.0.1:8765/")
    print("[+] Scope: maps.googleapis.com only; all other domains pass through untouched")
    print("[!] First Firefox run: open http://mitm.it and trust the mitmproxy CA for websites")
    print("[+] Press Ctrl+C to stop and restore your previous proxy settings.\n")
    mitmdump(
        args=[
            "--listen-host", "127.0.0.1",
            "--listen-port", str(DEFAULT_PROXY_PORT),
            "--allow-hosts", TARGET_ALLOW_PATTERN,
            "--set", "termlog_verbosity=info",
            "-s", script_path,
        ]
    )


if __name__ == "__main__":
    run_standalone()
else:
    addons = [MapsInterceptor()]
