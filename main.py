from scapy.all import ARP, Ether, srp, conf
import json
from pathlib import Path
import re
import threading
import time
import sys
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.spinner import Spinner
from rich.align import Align


REFERENCE_PATH = Path("reference.json")
WATCHLIST_PATH = Path("watchlist.json")


def load_reference(path: Path = REFERENCE_PATH) -> dict:
    """Load the OUI → vendor/country mapping from reference.json."""
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # pragma: no cover - defensive
        return {}


def load_watchlist(path: Path = WATCHLIST_PATH) -> dict:
    """Load the watchlist of unknown devices."""
    if not path.exists():
        return {}
    
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {}


def save_to_watchlist(ip: str, mac: str, path: Path = WATCHLIST_PATH) -> None:
    """Add an unknown device to the watchlist (only if not already present)."""
    watchlist = load_watchlist(path)
    
    # Only add if not already in watchlist
    if mac not in watchlist:
        watchlist[mac] = {
            "ip": ip,
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(watchlist, f, indent=2, sort_keys=True, ensure_ascii=False)
        except Exception as e:
            pass  # Silently fail if we can't write


def lookup_mac(mac: str, reference: dict, custom_devices: dict = None) -> tuple[bool, str, bool]:
    """
    Cross-reference a MAC address against the reference mapping and custom devices.

    - Remove all non-hex characters, uppercase.
    - Take the first 6 characters as the OUI key.
    - Return (is_known, info_string, is_unknown_device).
    """
    # Check custom devices first if provided
    if custom_devices:
        # Check if MAC exists in custom devices (could be key or in a device dict)
        for key, value in custom_devices.items():
            if isinstance(value, dict):
                if value.get("mac", "").upper() == mac.upper() or key.upper() == mac.upper():
                    return True, value.get("name", "Known Device"), False
            elif key.upper() == mac.upper():
                return True, "Known Device", False
    
    # Keep only hex digits
    normalized = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(normalized) < 6:
        return False, f"unknown {mac}", True

    oui = normalized[:6]
    entry = reference.get(oui)
    if not entry:
        return False, f"unknown {mac}", True

    vendor = entry.get("vendor", "").strip()
    country = entry.get("country", "").strip()
    if country:
        info = f"{vendor} ({country})"
    else:
        info = vendor or f"known {mac}"
    return True, info, False


def scan_ip_range(ip_range: str):
    """
    Scan an IP range and return a list of (ip, mac) tuples.

    Example ip_range values:
      - '192.168.1.0/24'
      - '192.168.1.1-192.168.1.50'
    """
    # Reduce Scapy's verbosity
    conf.verb = 0

    # Prepare ARP request to broadcast MAC
    arp_req = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req

    answered, _ = srp(packet, timeout=2, retry=1)

    devices = []
    for _, recv in answered:
        devices.append((recv.psrc, recv.hwsrc))

    return devices


def build_table(devices: list, reference: dict, custom_devices: dict = None, current_time: float = None) -> Table:
    """Build a Rich table from the device list with Status column."""
    if current_time is None:
        current_time = time.time()
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address")
    table.add_column("Info")
    table.add_column("Status", justify="center")

    for device_data in devices:
        # Handle both old format (ip, mac) and new format (ip, mac, last_seen)
        if len(device_data) == 3:
            ip, mac, last_seen = device_data
        else:
            ip, mac = device_data
            last_seen = current_time  # If no timestamp, assume active
        
        is_known, info, is_unknown = lookup_mac(mac, reference, custom_devices)
        
        # Check if device is stale (not seen in last 60 seconds)
        time_since_seen = current_time - last_seen
        if time_since_seen > 60:
            status = "[red]STALE[/red]"
        else:
            status = "[green]ACTIVE[/green]"
        
        if is_unknown:
            # Unknown device - add to watchlist and show in red
            save_to_watchlist(ip, mac)
            table.add_row(
                ip,
                f"[red]{mac}[/red]",
                f"[red]{info}[/red]",
                status,
            )
        else:
            table.add_row(ip, mac, info, status)
    
    return table


def continuous_scan(ip_range: str, reference: dict, custom_devices: dict, stop_event: threading.Event, devices_dict: dict, lock: threading.Lock):
    """Continuously scan the IP range every 20 seconds."""
    while not stop_event.is_set():
        try:
            scanned_devices = scan_ip_range(ip_range)
            current_time = time.time()
            with lock:
                # Update devices_dict with new scan results, including timestamp
                for ip, mac in scanned_devices:
                    devices_dict[mac] = (ip, mac, current_time)
        except Exception:
            pass
        
        # Wait 20 seconds or until stop event
        stop_event.wait(20)


def monitor_keyboard(stop_event: threading.Event):
    """Monitor keyboard for Ctrl+E (ASCII 5) to stop scanning."""
    try:
        import termios
        import tty
        import select
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setcbreak(fd)  # Use cbreak instead of raw to allow Ctrl+C
            while not stop_event.is_set():
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)
                    if char == '\x05':  # Ctrl+E
                        stop_event.set()
                        break
                time.sleep(0.05)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    except (ImportError, OSError, AttributeError):
        # Fallback for Windows or if termios not available
        while not stop_event.is_set():
            time.sleep(0.1)


def main():
    console = Console()

    console.print("IP Range → MAC Address scanner (Scapy)")
    console.print("Examples: 192.168.1.0/24  or  192.168.1.10-192.168.1.20")
    console.print("Press Ctrl+C to exit.\n")

    # Ask for custom JSON file
    custom_file = input("Enter path to custom device JSON file (or 'N'/'n' to use reference.json): ").strip()
    custom_devices = None
    
    if custom_file and custom_file.lower() != 'n':
        custom_path = Path(custom_file)
        if custom_path.exists():
            try:
                with custom_path.open("r", encoding="utf-8") as f:
                    custom_devices = json.load(f)
                console.print(f"[green]Loaded custom device list from {custom_file}[/green]\n")
            except Exception as e:
                console.print(f"[yellow]Failed to load custom file, using reference.json: {e}[/yellow]\n")
                custom_devices = None
        else:
            console.print(f"[yellow]Custom file not found, using reference.json[/yellow]\n")
            custom_devices = None
    
    reference = load_reference()

    try:
        while True:
            ip_range = input("Enter IP range to scan: ").strip()
            if not ip_range:
                console.print("No range entered, exiting.")
                break

            console.print(f"\n[bold]Starting continuous scan of {ip_range}[/bold]")
            console.print("[dim]Press Ctrl+E to stop scanning and enter a new range[/dim]\n")

            # Shared state for devices
            devices_dict = {}
            lock = threading.Lock()
            stop_event = threading.Event()

            # Start continuous scanning thread
            scan_thread = threading.Thread(
                target=continuous_scan,
                args=(ip_range, reference, custom_devices, stop_event, devices_dict, lock),
                daemon=True
            )
            scan_thread.start()

            # Start keyboard monitoring thread
            keyboard_thread = threading.Thread(
                target=monitor_keyboard,
                args=(stop_event,),
                daemon=True
            )
            keyboard_thread.start()

            # Initial scan
            with console.status("[bold green]Scanning network...", spinner="material"):
                initial_devices = scan_ip_range(ip_range)
                current_time = time.time()
                for ip, mac in initial_devices:
                    devices_dict[mac] = (ip, mac, current_time)

            # Display table with Live updates
            last_count = 0
            with Live(console=console, refresh_per_second=2) as live:
                while not stop_event.is_set():
                    current_time = time.time()
                    with lock:
                        current_devices = list(devices_dict.values())
                    
                    if current_devices:
                        table = build_table(current_devices, reference, custom_devices, current_time)
                        
                        # Create layout with table and spinner in bottom right
                        layout = Layout()
                        layout.split_column(
                            Layout(table, name="table"),
                            Layout(name="footer", size=1)
                        )
                        layout["footer"].update(
                            Align.right(
                                Spinner("boxBounce2", text="Scanning...", style="bold green"),
                                vertical="middle"
                            )
                        )
                        
                        panel = Panel(
                            layout,
                            title=f"[bold cyan]Scanning {ip_range}[/bold cyan] | Devices: {len(current_devices)}",
                            border_style="blue"
                        )
                        live.update(panel)
                        
                        if len(current_devices) != last_count:
                            last_count = len(current_devices)
                    else:
                        # No devices yet - show spinner
                        layout = Layout()
                        layout.split_column(
                            Layout("[yellow]Scanning... No devices found yet[/yellow]", name="content"),
                            Layout(name="footer", size=1)
                        )
                        layout["footer"].update(
                            Align.right(
                                Spinner("boxBounce2", text="Scanning...", style="bold green"),
                                vertical="middle"
                            )
                        )
                        panel = Panel(
                            layout,
                            title=f"[bold cyan]Scanning {ip_range}[/bold cyan]",
                            border_style="blue"
                        )
                        live.update(panel)
                    
                    time.sleep(0.5)  # Update display every 0.5 seconds

            console.print("\n[bold yellow]Scan stopped. Press Ctrl+C to exit or enter a new IP range.[/bold yellow]\n")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user. Exiting.[/yellow]")


if __name__ == "__main__":
    main()