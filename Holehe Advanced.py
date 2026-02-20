#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Autore: TheLeakSecurity AI (educational PoC)
"""

import argparse
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import random
import sys
import os
import logging

import requests
from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

colorama_init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("holehe_advanced")


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0_0) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

print_lock = threading.Lock()


def load_services(services_file: str):
    if not os.path.exists(services_file):
        logger.error(f"File dei servizi non trovato: {services_file}")
        sys.exit(1)

    try:
        with open(services_file, "r", encoding="utf-8") as f:
            services = json.load(f)
    except Exception as e:
        logger.error(f"Errore nel parsing di {services_file}: {e}")
        sys.exit(1)

    if not isinstance(services, list):
        logger.error("Il file dei servizi deve contenere una lista JSON.")
        sys.exit(1)

    return services


def prepare_request_data(service_conf: dict, email: str):
    """
    Prepara headers, body e altri parametri per la richiesta HTTP
    a partire dalla configurazione del servizio.

    :param service_conf: dizionario con configurazione del servizio
    :param email: email da testare
    :return: (url, method, headers, data, json_data, timeout)
    """
    url = service_conf.get("url")
    method = service_conf.get("method", "GET").upper()
    headers = service_conf.get("headers", {}) or {}
    timeout = service_conf.get("timeout", 10)

    if "User-Agent" not in headers:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    body_type = service_conf.get("body_type", "json")
    body_conf = service_conf.get("body", {}) or {}

    data = None
    json_data = None

    email_field = body_conf.get("email_field", "email")
    password_field = body_conf.get("password_field")
    password_value = body_conf.get("password_value", "Password123!")

    payload = {}
    payload[email_field] = email

    if password_field:
        payload[password_field] = password_value

    if body_type == "json":
        json_data = payload
    elif body_type == "form":
        data = payload

    return url, method, headers, data, json_data, timeout


def analyze_response(service_conf: dict, response: requests.Response):
    success_indicator = service_conf.get("success_indicator")
    not_found_indicator = service_conf.get("not_found_indicator")

    def check_indicator(indicator):
        if not indicator:
            return False

        i_type = indicator.get("type")
        field = indicator.get("field", "text")
        value = indicator.get("value")

        if i_type == "status_code":
            return response.status_code == int(value)
        elif i_type == "contains":
            if field == "text":
                return value.lower() in response.text.lower()
            elif field == "headers":
                return any(
                    value.lower() in str(v).lower()
                    for v in response.headers.values()
                )

        return False

    if check_indicator(success_indicator):
        return "exists"

    if check_indicator(not_found_indicator):
        return "not_found"

    return "unknown"


def check_service(service_conf: dict, email: str, proxies=None, verify_ssl=True):
    service_name = service_conf.get("name", "UnnamedService")

    try:
        url, method, headers, data, json_data, timeout = prepare_request_data(
            service_conf, email
        )

        if method == "GET":
            resp = requests.get(
                url,
                headers=headers,
                params=data,
                timeout=timeout,
                proxies=proxies,
                verify=verify_ssl
            )
        else:  
            resp = requests.post(
                url,
                headers=headers,
                data=data,
                json=json_data,
                timeout=timeout,
                proxies=proxies,
                verify=verify_ssl
            )

        status = analyze_response(service_conf, resp)

        result = {
            "service": service_name,
            "status": status,  
            "http_status": resp.status_code,
        }
        return result

    except requests.RequestException as e:
        logger.debug(f"[{service_name}] Errore di rete: {e}")
        return {
            "service": service_name,
            "status": "error",
            "error": str(e),
            "http_status": None,
        }
    except Exception as e:
        logger.debug(f"[{service_name}] Errore generico: {e}")
        return {
            "service": service_name,
            "status": "error",
            "error": str(e),
            "http_status": None,
        }


def run_checks(email: str,
               services: list,
               threads: int = 5,
               proxies=None,
               verify_ssl=True):
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_service, svc, email, proxies, verify_ssl): svc
            for svc in services
        }

        for future in as_completed(futures):
            res = future.result()
            results.append(res)

            # Output realtime
            with print_lock:
                status = res["status"]
                service = res["service"]

                if status == "exists":
                    print(f"{Fore.GREEN}[+] {service}: email presente")
                elif status == "not_found":
                    print(f"{Fore.RED}[-] {service}: email non trovata")
                elif status == "error":
                    print(f"{Fore.YELLOW}[!] {service}: errore - {res.get('error')}")
                else:
                    print(f"{Fore.CYAN}[?] {service}: stato sconosciuto")

    return results


def save_results_json(results, email, output_file):
    output_data = {
        "email": email,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        logger.info(f"Risultati salvati in {output_file}")
    except Exception as e:
        logger.error(f"Errore nel salvataggio dei risultati: {e}")


def print_summary_table(results):
    table = []
    for r in results:
        service = r["service"]
        status = r["status"]
        http_status = r.get("http_status", "")

        if status == "exists":
            status_colored = Fore.GREEN + "EXISTS"
        elif status == "not_found":
            status_colored = Fore.RED + "NOT FOUND"
        elif status == "error":
            status_colored = Fore.YELLOW + "ERROR"
        else:
            status_colored = Fore.CYAN + "UNKNOWN"

        table.append([service, status_colored, http_status])

    print("\n" + "=" * 60)
    print("RIEPILOGO RISULTATI")
    print("=" * 60)
    print(tabulate(table, headers=["Servizio", "Stato", "HTTP"], tablefmt="github"))


def parse_args():
    """
    Parsing degli argomenti da riga di comando.
    """
    parser = argparse.ArgumentParser(
        description="Tool tipo Holehe avanzato per verifica email (uso etico)."
    )
    parser.add_argument(
        "-e", "--email",
        required=True,
        help="Email da testare (solo account di tua proprietà / autorizzati)"
    )
    parser.add_argument(
        "-s", "--services",
        default="services.json",
        help="File JSON con configurazione dei servizi (default: services.json)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="Numero di thread per richieste parallele (default: 5)"
    )
    parser.add_argument(
        "-o", "--output",
        help="File JSON in cui salvare i risultati (opzionale)"
    )
    parser.add_argument(
        "--proxy",
        help="Proxy HTTP/S (es: http://127.0.0.1:8080) per debugging / anonimizzazione"
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disabilita verifica certificati SSL (sconsigliato, ma utile in alcuni lab)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Abilita logging verbose (debug)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    email = args.email.strip()
    logger.info(f"Email target: {email}")

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        logger.info(f"Uso proxy: {args.proxy}")

    verify_ssl = not args.no_verify_ssl

    services = load_services(args.services)
    logger.info(f"Servizi caricati: {len(services)}")

    print(Fore.YELLOW + "[!] ATTENZIONE: usa questo tool solo su account "
          "che possiedi o per cui hai autorizzazione esplicita.")

    results = run_checks(
        email=email,
        services=services,
        threads=args.threads,
        proxies=proxies,
        verify_ssl=verify_ssl
    )

    print_summary_table(results)

    if args.output:
        save_results_json(results, email, args.output)


if __name__ == "__main__":
    main()