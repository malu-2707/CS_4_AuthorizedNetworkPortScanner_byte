import socket
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


REPORT_DIR = Path("reports")


def validate_target(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def validate_port_range(start_port, end_port):
    if start_port < 1 or end_port > 65535:
        return False

    if start_port > end_port:
        return False

    return True


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            status = "open"
        else:
            status = "closed"

        return {
            "port": port,
            "protocol": "TCP",
            "status": status,
            "service": get_service_name(port) if status == "open" else "unknown"
        }

    except socket.timeout:
        return {
            "port": port,
            "protocol": "TCP",
            "status": "filtered",
            "service": "unknown"
        }

    except OSError:
        return {
            "port": port,
            "protocol": "TCP",
            "status": "filtered",
            "service": "unknown"
        }

    finally:
        sock.close()


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_ports(target, start_port, end_port, timeout, workers):
    results = []

    total_ports = end_port - start_port + 1
    completed_ports = 0

    print("\nStarting concurrent scan...")
    print(f"Target  : {target}")
    print(f"Ports   : {start_port}-{end_port}")
    print(f"Workers : {workers}")
    print("-" * 65)

    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(
                scan_port,
                target,
                port,
                timeout
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()

            results.append(result)

            completed_ports += 1

            if result["status"] == "open":
                print(
                    f"[OPEN]     Port: {result['port']:<5} "
                    f"Protocol: TCP   Service: {result['service']}"
                )

            progress = (completed_ports / total_ports) * 100

            print(
                f"\rProgress: {completed_ports}/{total_ports} "
                f"({progress:.0f}%)",
                end="",
                flush=True
            )

    print()

    results.sort(key=lambda result: result["port"])

    return results


def create_report_data(
    target,
    start_port,
    end_port,
    timeout,
    workers,
    results
):
    open_ports = sum(
        1 for result in results
        if result["status"] == "open"
    )

    closed_ports = sum(
        1 for result in results
        if result["status"] == "closed"
    )

    filtered_ports = sum(
        1 for result in results
        if result["status"] == "filtered"
    )

    return {
        "scan_timestamp": datetime.now().isoformat(),
        "target": target,
        "resolved_ip": socket.gethostbyname(target),
        "protocol": "TCP",
        "start_port": start_port,
        "end_port": end_port,
        "timeout_seconds": timeout,
        "workers": workers,
        "summary": {
            "total_ports": len(results),
            "open": open_ports,
            "closed": closed_ports,
            "filtered": filtered_ports
        },
        "results": results
    }


def save_csv(report_data):
    REPORT_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / f"port_scan_{timestamp}.csv"

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Target",
            "Port",
            "Protocol",
            "Status",
            "Service"
        ])

        for result in report_data["results"]:
            writer.writerow([
                report_data["scan_timestamp"],
                report_data["target"],
                result["port"],
                result["protocol"],
                result["status"],
                result["service"]
            ])

    return filename


def save_json(report_data):
    REPORT_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / f"port_scan_{timestamp}.json"

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report_data,
            file,
            indent=4
        )

    return filename


def display_summary(report_data):
    summary = report_data["summary"]

    print("\n" + "=" * 65)
    print("SCAN SUMMARY")
    print("=" * 65)

    print(f"Target          : {report_data['target']}")
    print(f"Resolved IP     : {report_data['resolved_ip']}")
    print(f"Protocol        : {report_data['protocol']}")

    print(
        f"Port Range      : "
        f"{report_data['start_port']}-"
        f"{report_data['end_port']}"
    )

    print(f"Workers         : {report_data['workers']}")
    print(f"Total Ports     : {summary['total_ports']}")
    print(f"Open Ports      : {summary['open']}")
    print(f"Closed Ports    : {summary['closed']}")
    print(f"Filtered Ports  : {summary['filtered']}")

    print(
        f"Scan Duration   : "
        f"{report_data['scan_duration_seconds']:.2f} seconds"
    )

    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="Authorized TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Authorized hostname or IP address"
    )

    parser.add_argument(
        "start_port",
        type=int,
        help="Starting port number"
    )

    parser.add_argument(
        "end_port",
        type=int,
        help="Ending port number"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent workers"
    )

    args = parser.parse_args()

    print("=" * 65)
    print("AUTHORIZED NETWORK PORT SCANNER")
    print("=" * 65)

    print("\nIMPORTANT:")
    print("Use this scanner only against systems you own")
    print("or systems for which you have explicit authorization.")

    if not validate_target(args.target):
        print("\nError: Invalid or unreachable target.")
        return

    if not validate_port_range(
        args.start_port,
        args.end_port
    ):
        print("\nError: Invalid port range.")
        print("Valid ports are between 1 and 65535.")
        return

    if args.timeout <= 0:
        print("\nError: Timeout must be greater than zero.")
        return

    if args.workers < 1 or args.workers > 100:
        print("\nError: Workers must be between 1 and 100.")
        return

    resolved_ip = socket.gethostbyname(args.target)

    print(f"\nTarget resolved to: {resolved_ip}")

    start_time = datetime.now()

    results = scan_ports(
        args.target,
        args.start_port,
        args.end_port,
        args.timeout,
        args.workers
    )

    end_time = datetime.now()

    report_data = create_report_data(
        args.target,
        args.start_port,
        args.end_port,
        args.timeout,
        args.workers,
        results
    )

    report_data["scan_duration_seconds"] = (
        end_time - start_time
    ).total_seconds()

    csv_file = save_csv(report_data)
    json_file = save_json(report_data)

    display_summary(report_data)

    print(f"\nCSV report  : {csv_file}")
    print(f"JSON report : {json_file}")

    print("\nScan completed successfully.")


if __name__ == "__main__":
    main()