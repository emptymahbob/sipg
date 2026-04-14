"""
Command-line interface for SIPG.
"""

import sys
from typing import Optional, List

import click
from rich.console import Console
from rich.panel import Panel

from .core import ShodanIPGrabber, ShodanAPIError
from .config import Config

console = Console()


def _parse_fields(fields: Optional[str]) -> Optional[List[str]]:
    """Parse comma-separated --fields input into a clean list."""
    if not fields:
        return None
    parsed = [field.strip() for field in fields.split(",") if field.strip()]
    return parsed or None


# Banner
BANNER = r"""
[red]  ______           [/red][yellow]_______ [/yellow][red] _______         [/red][yellow]______     [/yellow]
[red] /      \         [/red][yellow]/      /[/yellow][red] /       \       [/red][yellow]/      \    [/yellow]
[red]/$$$$$$$ |        [/red][yellow]$$$$$$/[/yellow][red] $$$$$$$  |      [/red][yellow]/$$$$$$  |   [/yellow]
[red]$$ \__$$/        [/red][yellow]   $$ | [/yellow][red] $$ |__$$ |      [/red][yellow]$$ | _$$/    [/yellow]
[red]$$      \        [/red][yellow]   $$ | [/yellow][red] $$    $$/       [/red][yellow]$$ |/    |   [/yellow]
[red] $$$$$$  |        [/red][yellow]  $$ | [/yellow][red] $$$$$$$/        [/red][yellow]$$ |$$$$ |   [/yellow]
[red]/  \__$$ |__     [/red][yellow]  _$$ |_ [/yellow][red]$$ |            [/red][yellow]$$ \__$$ |__ [/yellow]
[red]$$    $$//  |  [/red][yellow]   / $$   [/yellow][red]|$$ |            [/red][yellow]$$    $$//  |[/yellow]
[red] $$$$$$/ $$/    [/red][yellow]  $$$$$$/ [/yellow][red]$$/              [/red][yellow]$$$$$$/ $$/[/yellow]
"""


def print_banner():
    """Print the SIPG banner."""
    console.print(Panel(BANNER, title="SIPG v2.1.2", subtitle="Made by @emptymahbob"))


@click.group()
@click.version_option(version="2.1.2", prog_name="SIPG")
def cli():
    """SIPG - Shodan IP Grabber

    A professional command-line tool for searching IP addresses using Shodan API.

    \b
    Main Commands:
      search     Search for IP addresses and host data
      collect    Collect ips/domains/subdomains
      fields     Show supported --fields values
      configure  Configure your Shodan API key
      info       Show API key information and usage
      examples   Show example search queries
      clear      Clear the stored API key

    \b
    Search Examples:
      sipg search 'ssl:"Uber Technologies Inc"'
      sipg search http.server:Apache --details
      sipg search 'country:"United States"' -o results.txt
      sipg search 'port:80' --start-page 2 --end-page 5

    \b
    Search Options:
      -o, --output FILE     Save results to file
      -m, --max-results N   Limit number of results
      -d, --delay SECONDS   Delay between requests (default: 1.0s)
      --details             Show full JSON host records
      --table               Display expanded formatted table
      --start-page N        Start from page N (default: 1)
      --end-page N          End at page N (inclusive)

    \b
    For detailed help on any command, use: sipg <command> --help
    """
    pass


@cli.command()
@click.option("--api-key", prompt=True, hide_input=True, help="Your Shodan API key")
def configure(api_key: str):
    """Configure your Shodan API key."""
    try:
        config = Config()
        config.set_api_key(api_key)

        # Test the API key
        grabber = ShodanIPGrabber(config)
        api_info = grabber.get_api_info()

        console.print("[green]✓ API key configured successfully![/green]")
        console.print(f"[blue]Plan:[/blue] {api_info.get('plan', 'Unknown')}")
        console.print(f"[blue]Credits:[/blue] {api_info.get('credits', 'Unknown')}")
        console.print(
            f"[blue]Scan credits:[/blue] {api_info.get('scan_credits', 'Unknown')}"
        )

    except ShodanAPIError as e:
        console.print(f"[red]✗ Failed to configure API key: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Unexpected error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("query", type=str, required=False)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Save results to file. If not specified, results are printed to the console. Only IPs are saved for simple output, or detailed JSON for --details.",
)
@click.option(
    "-m",
    "--max-results",
    type=int,
    help="Maximum number of results to return. Default: all available results.",
)
@click.option(
    "-d",
    "--delay",
    type=float,
    default=1.0,
    show_default=True,
    help="Extra pause (seconds) after each result page when paginating (in addition to API spacing).",
)
@click.option(
    "--api-min-interval",
    type=float,
    default=None,
    help="Minimum seconds between every api.shodan.io call (default 1.0, or SIPG_API_MIN_INTERVAL env). 0 disables.",
)
@click.option(
    "-D",
    "--details",
    is_flag=True,
    help="Show detailed results with additional information (organization, location, hostnames, etc).",
)
@click.option(
    "-T",
    "--table",
    is_flag=True,
    help="Display results in a formatted table (implies --details).",
)
@click.option(
    "-p",
    "--start-page",
    type=int,
    default=1,
    show_default=True,
    help="Start fetching results from this page (1-based).",
)
@click.option(
    "-P",
    "--end-page",
    type=int,
    help="End fetching results at this page (inclusive). If not set, fetches up to the last available page or max-results.",
)
@click.option(
    "-M",
    "--mode",
    type=click.Choice(["api", "free"]),
    default="free",
    show_default=True,
    help="Search mode.",
)
@click.option(
    "-c",
    "--collect",
    type=click.Choice(["ips", "domains", "subdomains", "all"]),
    default="ips",
    show_default=True,
    help="What to collect from results.",
)
@click.option(
    "-f",
    "--filter",
    "query_filter",
    type=str,
    help='Beginner mode: wraps input as <filter>:"<value>". Example: --filter ssl',
)
@click.option(
    "-s",
    "--silent",
    is_flag=True,
    help="Print raw values only (no group headers; minimal summary).",
)
@click.option(
    "-O",
    "--output-format",
    type=click.Choice(["txt", "json", "csv"]),
    default="txt",
    show_default=True,
    help="Output format when using --output.",
)
@click.option(
    "-F",
    "--fields",
    type=str,
    help="Comma-separated fields for table/csv schemas. Example: ip,port,org,asn",
)
def search(
    query: Optional[str],
    output: Optional[str],
    max_results: Optional[int],
    delay: float,
    api_min_interval: Optional[float],
    details: bool,
    table: bool,
    start_page: int,
    end_page: Optional[int],
    mode: str,
    collect: str,
    query_filter: Optional[str],
    silent: bool,
    output_format: str,
    fields: Optional[str],
):
    """Search for IP addresses using Shodan.

    QUERY: The search query to use (e.g., ssl:"Uber Technologies Inc")

    \b
    OUTPUT OPTIONS:
      - By default, prints results to the console
      - Use -o/--output to save results to a file
      - Use --max-results to limit the number of results
      - Use --start-page/--end-page to fetch specific page ranges (each page = 100 results)
      - Use --delay to avoid hitting Shodan rate limits (default: 1.0s)
      - Use --details for full information, or --table for a formatted table

    \b
    FILE OUTPUT:
      - Simple mode: Saves only IP addresses (one per line)
      - Details mode: Saves full JSON data with all metadata
      - Table mode: Same as details mode but displays in console as table

    \b
    PAGE RANGES:
      - Each page contains up to 100 results from Shodan
      - Use --start-page to begin from a specific page (default: 1)
      - Use --end-page to stop at a specific page (inclusive)
      - Example: --start-page 5 --end-page 10 gets results 401-1000

    \b
    EXAMPLES:
      # Basic search
      sipg search 'ssl:"Uber Technologies Inc"'

      # Limit results and save to file
      sipg search 'http.server:Apache' --max-results 200 -o apache.txt

      # Get detailed results from specific pages
      sipg search 'country:"United States"' --details --start-page 2 --end-page 5

      # Save detailed results to file
      sipg search 'port:80' --details -o port80.json --start-page 5 --end-page 10

      # Display in table format
      sipg search 'product:"nginx"' --table --max-results 50
    """
    try:
        # Allow piped input similar to: echo "nvidia.com" | sipg search --filter ssl --silent
        if query is None and not sys.stdin.isatty():
            query = sys.stdin.read().strip()

        if not query:
            raise click.UsageError(
                "Missing query. Provide QUERY argument or pipe input to stdin."
            )

        if query_filter:
            escaped_query = query.replace('"', '\\"')
            query = f'{query_filter}:"{escaped_query}"'
        selected_fields = _parse_fields(fields)

        grabber = ShodanIPGrabber(api_min_interval=api_min_interval)

        # ipfinder-like behavior: free ips stream immediately, plain output.
        if mode == "free" and collect == "ips":
            ips: List[str] = []
            for ip in grabber.iter_ips_free_deep(
                query=query,
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
            ):
                ips.append(ip)
                console.print(ip)
            if output:
                grabber.save_results_to_file(ips, output)
            if not silent:
                console.print(
                    f"\n[green]Search completed! Found {len(ips)} IP(s).[/green]"
                )
            return

        # Non-API collection paths do not provide full detailed host records.
        if mode == "free" or collect != "ips":
            if details or table:
                console.print(
                    "[yellow]--details/--table are only available in API mode. Ignoring these flags.[/yellow]"
                )

            assets = grabber.search_assets(
                query=query,
                mode=mode,
                collect=collect,
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
            )

            group_labels = {
                "ips": "IPs",
                "domains": "Domains",
                "subdomains": "Subdomains",
            }
            counts: List[str] = []
            for group_name in ["ips", "domains", "subdomains"]:
                values = assets.get(group_name, [])
                if not values:
                    continue
                counts.append(f"{len(values)} {group_labels[group_name]}")
                if silent:
                    for value in values:
                        console.print(value)
                else:
                    console.print(
                        f"\n[cyan]{group_labels[group_name]} ({len(values)}):[/cyan]"
                    )
                    for value in values:
                        console.print(value)

            if output:
                grabber.save_assets_to_file(
                    assets, output, output_format, fields=selected_fields
                )

            summary = ", ".join(counts) if counts else "0 values"
            console.print(f"\n[green]Search completed! Collected: {summary}.[/green]")
            return

        if details or table:
            results = list(
                grabber.search_with_details(
                    query, max_results, delay, start_page, end_page
                )
            )
            if table:
                grabber.display_results_table(results, fields=selected_fields)
            else:
                for i, result in enumerate(results, 1):
                    console.print(f"\n[cyan]Result {i}:[/cyan]")
                    console.print_json(data=result)
            if output:
                export_format = (
                    output_format if output_format in ("txt", "json", "csv") else "json"
                )
                grabber.save_detailed_results_to_file(
                    results, output, export_format, fields=selected_fields
                )
            console.print(
                f"\n[green]Search completed! Found {len(results)} result(s).[/green]"
            )
        else:
            assets = grabber.search_assets(
                query=query,
                mode=mode,
                collect="ips",
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
            )
            results = assets.get("ips", [])
            if silent:
                for ip in results:
                    console.print(ip)
            else:
                if results:
                    console.print(f"\n[cyan]IPs ({len(results)}):[/cyan]")
                for ip in results:
                    console.print(ip)
            if output:
                grabber.save_results_to_file(results, output)
            console.print(
                f"\n[green]Search completed! Found {len(results)} IP(s).[/green]"
            )
    except ShodanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Search interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("query", type=str, required=False)
@click.option(
    "-o", "--output", type=click.Path(), required=True, help="Output file path."
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["txt", "json", "csv"]),
    default="txt",
    show_default=True,
    help="Output format.",
)
@click.option(
    "-M",
    "--mode",
    type=click.Choice(["api", "free"]),
    default="free",
    show_default=True,
    help="Collection mode.",
)
@click.option(
    "-c",
    "--collect",
    type=click.Choice(["ips", "domains", "subdomains", "all"]),
    default="all",
    show_default=True,
    help="Asset types to collect.",
)
@click.option(
    "-m",
    "--max-results",
    type=int,
    help="Maximum number of values to return per asset type.",
)
@click.option(
    "-d",
    "--delay",
    type=float,
    default=1.0,
    show_default=True,
    help="Extra pause (seconds) after each page when paginating in API mode.",
)
@click.option(
    "--api-min-interval",
    type=float,
    default=None,
    help="Minimum seconds between api.shodan.io calls (default 1.0 or SIPG_API_MIN_INTERVAL).",
)
@click.option(
    "-p",
    "--start-page",
    type=int,
    default=1,
    show_default=True,
    help="Start page in API mode.",
)
@click.option("-P", "--end-page", type=int, help="End page in API mode.")
@click.option(
    "-f", "--filter", "query_filter", type=str, help="Beginner mode filter wrapper."
)
@click.option("-s", "--silent", is_flag=True, help="Print raw values only.")
@click.option(
    "-F",
    "--fields",
    type=str,
    help="Comma-separated fields for CSV schema. collect supports: type,value",
)
def collect(
    query: Optional[str],
    output: str,
    output_format: str,
    mode: str,
    collect: str,
    max_results: Optional[int],
    delay: float,
    api_min_interval: Optional[float],
    start_page: int,
    end_page: Optional[int],
    query_filter: Optional[str],
    silent: bool,
    fields: Optional[str],
):
    """Collect assets (IPs/domains/subdomains) with export formats."""
    try:
        if query is None and not sys.stdin.isatty():
            query = sys.stdin.read().strip()
        if not query:
            raise click.UsageError(
                "Missing query. Provide QUERY argument or pipe input to stdin."
            )
        if query_filter:
            escaped_query = query.replace('"', '\\"')
            query = f'{query_filter}:"{escaped_query}"'
        selected_fields = _parse_fields(fields)

        grabber = ShodanIPGrabber(api_min_interval=api_min_interval)
        if mode == "free" and collect == "ips":
            ips: List[str] = []
            for ip in grabber.iter_ips_free_deep(
                query=query,
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
            ):
                ips.append(ip)
                console.print(ip)
            grabber.save_results_to_file(ips, output)
            if not silent:
                console.print(
                    f"\n[green]Collection completed! Found {len(ips)} IP(s).[/green]"
                )
            return

        assets = grabber.search_assets(
            query=query,
            mode=mode,
            collect=collect,
            max_results=max_results,
            delay=delay,
            start_page=start_page,
            end_page=end_page,
        )

        group_labels = {
            "ips": "IPs",
            "domains": "Domains",
            "subdomains": "Subdomains",
        }
        counts: List[str] = []
        for group_name in ["ips", "domains", "subdomains"]:
            values = assets.get(group_name, [])
            if not values:
                continue
            counts.append(f"{len(values)} {group_labels[group_name]}")
            if silent:
                for value in values:
                    console.print(value)
            else:
                console.print(
                    f"\n[cyan]{group_labels[group_name]} ({len(values)}):[/cyan]"
                )
                for value in values:
                    console.print(value)

        grabber.save_assets_to_file(
            assets, output, output_format, fields=selected_fields
        )
        summary = ", ".join(counts) if counts else "0 values"
        console.print(f"\n[green]Collection completed! Collected: {summary}.[/green]")
    except ShodanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Collection interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output field metadata as JSON for scripts/automation.",
)
def fields(as_json: bool):
    """Show available field names for --fields options."""
    detail_fields = [
        ("ip / ip_str", "IPv4 address returned by Shodan", "ip,port,org,asn"),
        ("port", "Detected service port", "ip,port,transport"),
        ("transport", "Protocol transport (tcp/udp)", "ip,port,transport"),
        ("org", "Owning organization", "ip,org,asn,isp"),
        ("asn", "Autonomous System Number", "ip,asn,org"),
        ("isp", "Internet service provider", "ip,isp,org"),
        ("city", "City from geolocation", "ip,city,country"),
        ("country", "Country name from geolocation", "ip,city,country"),
        ("location", "Combined city + country", "ip,location"),
        ("hostnames", "Resolved hostnames", "ip,hostnames,domains"),
        ("domains", "Associated domains", "ip,domains,hostnames"),
        ("product", "Detected product/service", "ip,port,product"),
        ("os", "Detected operating system", "ip,os,product"),
        ("timestamp", "Shodan observation timestamp", "ip,timestamp,port"),
        ("vulns", "CVE list (joined)", "ip,vulns"),
        ("vuln_count", "Number of vulnerabilities", "ip,vuln_count,org"),
    ]

    if as_json:
        payload = {
            "search": {
                "description": "Fields supported by search --fields (table and detailed csv)",
                "fields": [
                    {"name": name, "description": description, "example": example}
                    for name, description, example in detail_fields
                ],
            },
            "collect": {
                "description": "Fields supported by collect --fields (csv only)",
                "fields": [
                    {
                        "name": "type",
                        "description": "Asset category: ips/domains/subdomains",
                        "example": "type,value",
                    },
                    {
                        "name": "value",
                        "description": "Asset value",
                        "example": "type,value",
                    },
                ],
            },
        }
        console.print_json(data=payload)
        return

    console.print("[blue]search --fields (for --table and detailed CSV):[/blue]")
    for name, description, example in detail_fields:
        console.print(
            f"  [green]{name}[/green] - {description} [dim](ex: --fields {example})[/dim]"
        )

    console.print("\n[blue]collect --fields (CSV only):[/blue]")
    console.print("  [green]type[/green] - Asset category: ips/domains/subdomains")
    console.print("  [green]value[/green] - Asset value")
    console.print(
        "  [dim]Example: sipg collect 'ssl:\"nvidia\"' -o out.csv --format csv --fields type,value[/dim]"
    )


@cli.command()
def info():
    """Show information about your Shodan API key."""
    try:
        grabber = ShodanIPGrabber()
        api_info = grabber.get_api_info()

        console.print("[blue]Shodan API Information:[/blue]")
        console.print(f"  [green]Plan:[/green] {api_info.get('plan', 'Unknown')}")
        console.print(f"  [green]Credits:[/green] {api_info.get('credits', 'Unknown')}")
        console.print(
            f"  [green]Scan credits:[/green] {api_info.get('scan_credits', 'Unknown')}"
        )
        console.print(
            f"  [green]Query credits:[/green] {api_info.get('query_credits', 'Unknown')}"
        )
        console.print(
            f"  [green]Monitored IPs:[/green] {api_info.get('monitored_ips', 'Unknown')}"
        )

    except ShodanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def examples():
    """Show example search queries."""
    examples_data = [
        {
            "description": "Find IPs with SSL certificates from Uber Technologies",
            "query": "'ssl:\"Uber Technologies Inc\"'",
        },
        {"description": "Find IPs with HTTP status 200", "query": "http.status:200"},
        {
            "description": "Find IPs with specific SSL certificate subject",
            "query": "'ssl.cert.subject.CN:\"*.uber.com\"'",
        },
        {"description": "Find IPs with Apache server", "query": "http.server:Apache"},
        {
            "description": "Find IPs in specific country",
            "query": "'country:\"United States\"'",
        },
        {"description": "Find IPs with specific port open", "query": "port:80"},
        {
            "description": "Find IPs with specific product",
            "query": "'product:\"nginx\"'",
        },
        {
            "description": "Find IPs with specific organization",
            "query": "'org:\"Amazon\"'",
        },
    ]

    console.print("[blue]Example Search Queries:[/blue]\n")

    for i, example in enumerate(examples_data, 1):
        console.print(f"[cyan]{i}.[/cyan] [green]{example['description']}[/green]")
        console.print(f"   [yellow]sipg search {example['query']}[/yellow]\n")


@cli.command()
def clear():
    """Clear the stored API key."""
    try:
        config = Config()
        config.clear_api_key()
        console.print("[green]✓ API key cleared successfully![/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to clear API key: {e}[/red]")
        sys.exit(1)


# Short command aliases for easier usage
cli.add_command(search, "s")
cli.add_command(collect, "c")
cli.add_command(configure, "cfg")
cli.add_command(info, "i")
cli.add_command(examples, "ex")
cli.add_command(clear, "cl")
cli.add_command(fields, "fs")


def main():
    """Main entry point for the CLI."""
    if len(sys.argv) == 1:
        print_banner()
        console.print("\n[blue]Use 'sipg --help' to see available commands.[/blue]")
        return

    cli()


if __name__ == "__main__":
    main()
