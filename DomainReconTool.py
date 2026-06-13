import socket
import sys
import whois
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

class DomainReconTool:
    def __init__(self):
        self.domain = ""

    def print_banner(self):
        """Displays a clean Kali Linux style header panel."""
        banner_text = Text()
        banner_text.append("🌐 DOMAIN INTELLIGENCE & RECONNAISSANCE TOOL v2.0.0\n", style="bold green")
        banner_text.append("═════════════════════════════════════════════════════════\n", style="bright_black")
        banner_text.append("Extracting: WHOIS Registry Data  |  DNS Architecture  |  IP Routing", style="cyan dim")
        
        panel = Panel(
            banner_text,
            title="[bold red]🔍 TARGET ACQUISITION SYSTEM[/bold red]",
            border_style="green",
            expand=False,
            padding=(1, 4)
        )
        console.print(panel)

    def get_whois_data(self):
        """Fetches domain registrar details, creation dates, and ownership records."""
        console.print("\n[bold yellow][*][/bold yellow] Querying Global WHOIS Databases...")
        try:
            w = whois.whois(self.domain)
            
            table = Table(title="📋 REGISTRATION & WHOIS DETAILS", title_style="bold white", show_header=True, header_style="bold magenta")
            table.add_column("Property Field", style="cyan", justify="left")
            table.add_column("Registered Information Data", style="white", justify="left")
            
            table.add_row("Registrar Name", str(w.registrar))
            table.add_row("Creation Date", str(w.creation_date))
            table.add_row("Expiration Date", str(w.expiration_date))
            table.add_row("Updated Date", str(w.updated_date))
            table.add_row("Registrant Country", str(w.country))
            
            # Format nameservers nicely whether they come back as a list or string
            ns_data = w.name_servers
            if isinstance(ns_data, list):
                ns_str = ", ".join(str(ns) for ns in ns_data)
            else:
                ns_str = str(ns_data)
            table.add_row("Name Servers", ns_str)
            
            console.print(table)
        except Exception as e:
            console.print(f"[bold red][-] Failed to pull WHOIS records:[/bold red] {e}")

    def get_dns_records(self):
        """Resolves critical structural infrastructure DNS records."""
        console.print("\n[bold yellow][*][/bold yellow] Resolving Domain Name System (DNS) Matrix...")
        
        record_types = {
            'A': 'IPv4 Mapping Address',
            'AAAA': 'IPv6 Mapping Address',
            'MX': 'Mail Exchange Servers',
            'TXT': 'Text Verification Records (SPF/DKIM)',
            'NS': 'Authoritative Name Servers'
        }

        table = Table(title="📡 DOMAIN SYSTEM RECORD MATRIX", title_style="bold white", show_header=True, header_style="bold cyan")
        table.add_column("Type", style="magenta", justify="center")
        table.add_column("Network Purpose", style="dim white", justify="left")
        table.add_column("Resolved Value / Destination", style="green", justify="left")

        for r_type, description in record_types.items():
            try:
                answers = dns.resolver.resolve(self.domain, r_type)
                for rdata in answers:
                    table.add_row(r_type, description, str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                table.add_row(r_type, description, "[dim red]No Record Found[/dim red]")
            except Exception:
                table.add_row(r_type, description, "[dim yellow]Query Timeout[/dim yellow]")

        console.print(table)

    def resolve_hosting_ip(self):
        """Converts domain name to its direct primary target host IP."""
        console.print("\n[bold yellow][*][/bold yellow] Tracing Core Host IP Server Resolution...")
        try:
            target_ip = socket.gethostbyname(self.domain)
            console.print(Panel(f"[bold white]Target Domain Mapping Direct Endpoint:[/bold white]\n[bold green]🎯 {target_ip}[/bold green]", border_style="blue", expand=False))
        except socket.gaierror:
            console.print("[bold red][-] Error: Could not resolve core server routing IP address.[/bold red]")

    def run(self):
        self.print_banner()
        
        console.print("\n[bold yellow]►[/bold yellow] Enter Target Domain Name:")
        self.domain = input(" 🌐 Domain (e.g., google.com): ").strip().lower()
        
        if not self.domain:
            console.print("[bold red][-] Error: Input field cannot be left blank.[/bold red]")
            sys.exit(1)
            
        # Clean potential URL noise like http:// or www.
        self.domain = self.domain.replace("https://", "").replace("http://", "").replace("www.", "")
        
        # Execute Pipeline Tasks
        self.resolve_hosting_ip()
        self.get_whois_data()
        self.get_dns_records()
        
        console.print("\n[bold green][✓][/bold green] Open-Source Reconnaissance pipeline completed for target system.\n")

if __name__ == "__main__":
    try:
        tool = DomainReconTool()  # Fixed typo here
        tool.run()
    except KeyboardInterrupt:
        console.print("\n\n[bold red][!] Interrupted by user execution signal. Exiting...[/bold red]")
        sys.exit(0)
