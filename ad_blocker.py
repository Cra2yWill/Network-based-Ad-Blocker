from mitmproxy import http, ctx
from datetime import datetime
from pathlib import Path
from queue import Queue, Full
from urllib.parse import urlsplit
import requests
import re
import time
import json
import threading
import os

#Configuration
EASYLIST_URL = "https://easylist.to/easylist/easylist.txt"
UPDATE_INTERVAL = 24 * 60 * 60  # Update every 24 hours
LOG_FILE = Path(__file__).resolve().parent / "blocked_ads.jsonl"  # Log file path

DOMAIN_PATTERN = re.compile(
    r"^\|\|([a-zA-Z0-9.-]+)\^$"
)

#Function to use regular expression to match domains (simple URL patterns)
def get_domains(easylist_text):
    domains = set()

    for line in easylist_text.splitlines():
        match = DOMAIN_PATTERN.fullmatch(line.strip())

        if match:
            domain = match.group(1).lower().rstrip(".")
            domains.add(domain)

    return frozenset(domains)

#check the exact hostname and its parent domains
def is_blocked(hostname, blocked_domains):
    hostname = hostname.lower().rstrip(".")

    if not hostname:
        return False
    
    #Extact match: average O(1) time complexity
    if hostname in blocked_domains:
        return True
    
    #Check parent domains using hash lookups
    start = 0

    while True:
        dot = hostname.find(".", start)

        if dot == -1:
            return False
        
        start = dot + 1
        if hostname[start:] in blocked_domains:
            return True
        
class AdBlocker:
    def __init__(self):
        self.blocklist = frozenset()
        self.stop_event = threading.Event()

        #Avoid blocking request processing on disk writes
        self.log_queue = Queue(maxsize=10000)
        
        self.update_thread = None
        self.log_thread = None

    #Called when mitmproxy loads this addon
    def load(self, loader):
        self.log_thread = threading.Thread(
            target=self.log_worker,
            daemon=True
        )
        self.log_thread.start()
        self.update_thread = threading.Thread(
            target=self.update_blocklist,
            daemon=True
        )
        self.update_thread.start()

    #Download EasyList Periodically and update the blocklist
    def update_blocklist(self):
        while not self.stop_event.is_set():
            try:
                response = requests.get(
                    EASYLIST_URL, 
                    timeout=30
                )

                response.raise_for_status()
                new_blocklist = get_domains(response.text)

                if not new_blocklist:
                    raise ValueError("No supported domains found in EasyList")
                
                #Replace the immutable snapshot atomically
                self.blocklist = new_blocklist
                ctx.log.info(f"Loaded {len(new_blocklist)} blocked domains")

            except Exception as error:
                ctx.log.error(f"Blocklist update failed: {error}")

            self.stop_event.wait(UPDATE_INTERVAL)

    #Write logs outside the request-processing path
    def log_worker(self):
        while True:
            entry = self.log_queue.get()

            if entry is None:
                self.log_queue.task_done()
                break

            try:
                with LOG_FILE.open(
                    "a", encoding="utf-8"
                ) as file:
                    file.write(json.dumps(entry) + "\n")

            except OSError as error:
                ctx.log.error(f"Logging failed: {error}")

            finally:
                self.log_queue.task_done()

    #Inspect and optionally block an HTTP request
    def request(self, flow: http.HTTPFlow):
        hostname = flow.request.host.lower().rstrip(".")

        #Read one consistent snapshot
        current_blocklist = self.blocklist

        if not is_blocked(hostname, current_blocklist):
            return
        
        referer = flow.request.headers.get("Referer")
        website = referer or flow.request.pretty_host

        flow.response = http.Response.make(
            403, #Forbidden
            b"Blocked by Network Ad Blocker",
            {"Content-Type": "text/plain"}
        )

        now = datetime.now()

        log_entry = {
            "Website": website,
            "Ad URL": flow.request.pretty_url,
            "Date": now.strftime("%d-%m-%Y"),
            "Time": now.strftime("%H:%M:%S"),
        }

        try:
            self.log_queue.put_nowait(log_entry)
        except Full:
            ctx.log.warn("Log queue is full; dropping log entry")

    #Stop the update thread and flush queued logs
    def done(self):
        self.stop_event.set()

        if self.update_thread is not None:
            self.update_thread.join(timeout=2)

        if self.log_thread is not None:
            self.log_queue.put(None)
            self.log_queue.join()
            self.log_thread.join()

addons = [AdBlocker()]