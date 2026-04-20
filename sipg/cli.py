"""
Command-line interface for SIPG (Shodan IP Grabber).
"""

import sys
from pathlib import Path
from typing import Optional, List

import click
from rich.align import Align
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


def _parse_collect(collect_raw: str) -> str:
    """Normalize --collect input and allow comma-separated values."""
    allowed = {"ips", "domains", "subdomains", "all"}
    parsed = [item.strip().lower() for item in collect_raw.split(",") if item.strip()]
    if not parsed:
        raise click.UsageError(
            "Invalid --collect value. Use ips, domains, subdomains, all, or comma-separated values."
        )
    invalid = [item for item in parsed if item not in allowed]
    if invalid:
        raise click.UsageError(
            f"Invalid --collect value(s): {', '.join(invalid)}. "
            "Allowed: ips, domains, subdomains, all."
        )
    if "all" in parsed:
        return "all"
    unique = set(parsed)
    if unique == {"ips"}:
        return "ips"
    if unique == {"domains"}:
        return "domains"
    if unique == {"subdomains"}:
        return "subdomains"
    return ",".join(sorted(unique))


def _resolve_output_format(
    output_path: Optional[str], explicit_format: Optional[str]
) -> str:
    """Resolve export format from --output-format or output file extension."""
    if explicit_format:
        return explicit_format
    if not output_path:
        return "txt"
    suffix = Path(output_path).suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".csv":
        return "csv"
    return "txt"


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
    """Print the SIPG (Shodan IP Grabber) banner."""
    body = BANNER
    console.print(
        Panel(
            Align.center(body),
            title="SIPG v2.1.5",
            subtitle="Shodan IP Grabber · Made by @emptymahbob",
            expand=True,
        )
    )


@click.group()
@click.version_option(version="2.1.5", prog_name="SIPG (Shodan IP Grabber)")
def cli():
    """SIPG — Shodan IP Grabber

    A professional command-line tool for searching IP addresses using Shodan API.

    \b
    Main Commands:
      search     Search and collect IPs/domains/subdomains
      fields     Show supported --fields values
      configure  Configure your Shodan API key
      info       Show API key information and usage
      examples   Show example search queries
      clear      Clear the stored API key

    \b
    Search Examples:
      sipg search 'ssl:"Uber Technologies Inc"'
      sipg search 'ssl:"nvidia"' --collect all --mode free
      sipg search http.server:Apache --details
      sipg search 'country:"United States"' -o results.txt
      sipg search 'port:80' --start-page 2 --end-page 5

    \b
    Search Options (full):
      -o, --output FILE         Save results to file (otherwise print)
      -m, --max-results N       Limit number of results
      -d, --delay SECONDS       Delay between requests (default: 1.0s)
      -I, --api-min-interval N  Minimum API call spacing
      -D, --details, --detail   Show full JSON host records
      -T, --table, --tables     Display expanded formatted table
      -p, --start-page N        Start from page N (default: 1)
      -P, --end-page N          End at page N (inclusive)
      -M, --mode [auto|api|free]  auto=api if key saved else free; api|free to force
      -c, --collect TEXT        ips/domains/subdomains/all or comma-separated
      -f, --filter TEXT         Wrap value as filter:"value"
      -s, --silent              Print raw values only
      -O, --output-format TYPE  Optional export format override
      -F, --fields LIST         Comma-separated export/table fields

    \b
    For detailed help on any command, use: sipg <command> --help
    """
    pass


@cli.command()
@click.option("-k", "--api-key", prompt=True, hide_input=True, help="Your Shodan API key")
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
    "-I",
    "--api-min-interval",
    type=float,
    default=None,
    help="Minimum seconds between every api.shodan.io call (default 1.0, or SIPG_API_MIN_INTERVAL env). 0 disables.",
)
@click.option(
    "-D",
    "--detail",
    "--details",
    "details",
    is_flag=True,
    help="Show detailed results with additional information (organization, location, hostnames, etc).",
)
@click.option(
    "-T",
    "--tables",
    "--table",
    "table",
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
    type=click.Choice(["auto", "api", "free"]),
    default="auto",
    show_default=True,
    help="auto=api if an API key is saved, else free; api=REST Search; free=facet/no-key style.",
)
@click.option(
    "-c",
    "--collect",
    type=str,
    default="ips",
    show_default=True,
    help="What to collect (default: ips): ips, domains, subdomains, all, or comma-separated (example: domains,subdomains).",
)
@click.option(
    "--domain-suffix",
    type=str,
    default=None,
    help="With domains/subdomains collection or hostnames/domains columns: keep only FQDNs ending at a "
    "label boundary with this suffix (comma-separated for OR). Example: --domain-suffix mil keeps *.mil, "
    "not *.mil.ng.",
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
    default=None,
    help="Optional output format override. If omitted, format is auto-detected from -o file extension (.json/.csv, otherwise txt).",
)
@click.option(
    "-F",
    "--fields",
    type=str,
    help="Comma-separated fields for table/csv schemas. Use `port` for search hits per host; "
    "`ports` for all ports via GET /shodan/host/{ip}. Example: ip,port,org",
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
    output_format: Optional[str],
    fields: Optional[str],
    domain_suffix: Optional[str],
):
    """Search and collect assets using Shodan.
    
    QUERY: The search query to use (e.g., ssl:"Uber Technologies Inc")

    \b
    OUTPUT BEHAVIOR:
      - No -o/--output: print results to console
      - With -o/--output: save results to file
      - Default collection is ips only
      - Use --collect to choose ips/domains/subdomains/all
      - Use --max-results to limit the number of results
      - Use --start-page/--end-page to fetch specific page ranges (each page = 100 results)
      - Use --delay to avoid hitting Shodan rate limits (default: 1.0s)
      - Use --details for full information, or --table for a formatted table

    \b
    FILE OUTPUT:
      - --collect ips/domains/subdomains/all + -O txt/json/csv
      - --details/--table in API mode can export rich JSON/CSV with --fields

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

      # Collect domains/subdomains too (single command workflow)
      sipg search 'ssl:"nvidia"' --collect all --mode free -o assets.json -O json
    """
    try:
        if not silent:
            print_banner()

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
        collect = _parse_collect(collect)
        resolved_output_format = _resolve_output_format(output, output_format)

        grabber = ShodanIPGrabber(api_min_interval=api_min_interval)
        ds_suffixes = grabber._normalize_domain_suffixes(domain_suffix)

        # Default: use API when a key exists; free only without a key unless user passes -M free
        if mode == "auto":
            mode = "api" if grabber.config.get_api_key() else "free"

        # --fields without --details/--table: user wants columnar output → enable table path
        if selected_fields and not details and not table and collect == "ips":
            table = True

        # Table view implies full host records (same as details for fetching)
        if table and not details:
            details = True

        # Rich output (--details, --table, --fields) needs Shodan host/search API, not free streaming.
        need_host_records = bool(details or table or selected_fields)
        if mode == "free" and collect == "ips" and need_host_records:
            if grabber.config.get_api_key():
                console.print(
                    "[cyan]Using -M api for rich host data "
                    "(--details / --table / --fields require full JSON from host/search; "
                    "free mode only streams plain IPs).[/cyan]"
                )
                mode = "api"
            else:
                console.print(
                    "[yellow]--details, --table, and --fields need a Shodan API key (host/search). "
                    "Run `sipg cfg`, then retry with e.g. `sipg s '<query>' -M api -D`. "
                    "Continuing with free IP list only (rich flags ignored).[/yellow]"
                )
                details = table = False
                selected_fields = None

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
                if resolved_output_format == "txt":
                    grabber.save_results_to_file(ips, output)
                else:
                    grabber.save_assets_to_file(
                        {"ips": ips, "domains": [], "subdomains": []},
                        output,
                        resolved_output_format,
                        fields=selected_fields,
                    )
            if not silent:
                console.print(
                    f"\n[green]Search completed! Found {len(ips)} IP(s).[/green]"
                )
            return

        # Non-API collection paths do not provide full detailed host records.
        if mode == "free" or collect != "ips":
            if details or table:
                console.print(
                    "[yellow]--details/--table are API detail views and require IP host records. "
                    "They are ignored in free mode or when --collect excludes ips. "
                    "Use -M api -c ips (or -c all) to use --details/--table.[/yellow]"
                )

            if ds_suffixes:
                c_parts = {p.strip().lower() for p in collect.split(",") if p.strip()}
                if "all" in c_parts or "domains" in c_parts or "subdomains" in c_parts:
                    lbl = ", ".join(f".{s}" for s in ds_suffixes)
                    console.print(
                        f"[dim]Domain filter: keeping only names ending with {lbl}[/dim]"
                    )
            assets = grabber.search_assets(
                query=query,
                mode=mode,
                collect=collect,
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
                domain_suffix=domain_suffix,
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
                    assets, output, resolved_output_format, fields=selected_fields
                )

            summary = ", ".join(counts) if counts else "0 values"
            console.print(f"\n[green]Search completed! Collected: {summary}.[/green]")
            return
        
        if details or table:
            try:
                results = list(
                    grabber.search_with_details(
                        query, max_results, delay, start_page, end_page
                    )
                )
            except ShodanAPIError as e:
                # api-info can work while host/search is forbidden (plan / key scope).
                if getattr(e, "status_code", None) not in (401, 403):
                    raise
                console.print(
                    f"[yellow]Shodan host/search denied (HTTP {e.status_code}). "
                    "Your key may reach api-info but not the Search API (/shodan/host/search) "
                    "on this plan — common for some dev or restricted keys. "
                    "Falling back to [bold]free mode[/bold]: plain IPs only "
                    "(no JSON, table, or --fields columns). "
                    "Upgrade at https://account.shodan.io/ or use without -D/-T/-F.[/yellow]"
                )
                if collect != "ips":
                    console.print(
                        "[red]Automatic fallback only supports --collect ips. "
                        "Retry with `-c ips` or omit -D/-T/-F for facet collection.[/red]"
                    )
                    sys.exit(1)
                ips_fb: List[str] = []
                for ip in grabber.iter_ips_free_deep(
                    query=query,
                    max_results=max_results,
                    delay=delay,
                    start_page=start_page,
                    end_page=end_page,
                ):
                    ips_fb.append(ip)
                    console.print(ip)
                if output:
                    if resolved_output_format == "txt":
                        grabber.save_results_to_file(ips_fb, output)
                    else:
                        grabber.save_assets_to_file(
                            {"ips": ips_fb, "domains": [], "subdomains": []},
                            output,
                            resolved_output_format,
                            fields=None,
                        )
                if not silent:
                    console.print(
                        f"\n[green]Search completed! Found {len(ips_fb)} IP(s) (free fallback).[/green]"
                    )
                return

            _nf = grabber._normalize_fields(selected_fields) or grabber.DEFAULT_TABLE_FIELDS
            if "ports" in _nf:
                console.print(
                    "[dim]Loading full host port lists (GET /shodan/host/{ip}, one request per unique IP)...[/dim]"
                )
            if ds_suffixes and (
                "hostnames" in _nf or "domains" in _nf
            ):
                lbl = ", ".join(f".{s}" for s in ds_suffixes)
                console.print(
                    f"[dim]Domain filter on columns: keeping only names ending with {lbl}[/dim]"
                )
            prepared, tab_cols = grabber.prepare_detail_tabular_results(
                results, selected_fields
            )

            if table:
                grabber.print_detail_table_rows(prepared, tab_cols, ds_suffixes)
            else:
                for i, result in enumerate(results, 1):
                    console.print(f"\n[cyan]Result {i}:[/cyan]")
                    console.print_json(data=result)
            if output:
                grabber.save_detailed_results_to_file(
                    results,
                    output,
                    resolved_output_format,
                    fields=selected_fields,
                    csv_rows=prepared if resolved_output_format == "csv" else None,
                    csv_columns=tab_cols if resolved_output_format == "csv" else None,
                    domain_suffix_filter=ds_suffixes,
                )
            shown = len(prepared) if table else len(results)
            console.print(f"\n[green]Search completed! Found {shown} result(s).[/green]")
        else:
            assets = grabber.search_assets(
                query=query,
                mode=mode,
                collect="ips",
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
                domain_suffix=domain_suffix,
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
                if resolved_output_format == "txt":
                    grabber.save_results_to_file(results, output)
                else:
                    grabber.save_assets_to_file(
                        {"ips": results, "domains": [], "subdomains": []},
                        output,
                        resolved_output_format,
                        fields=selected_fields,
                    )
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
@click.option(
    "-j",
    "--json",
    "as_json",
    is_flag=True,
    help="Output field metadata as JSON for scripts/automation.",
)
def fields(as_json: bool):
    """Show available field names for --fields options."""
    detail_fields = [
        ("ip / ip_str", "IPv4 address returned by Shodan", "ip,port,org,asn"),
        (
            "port",
            "Ports matching your search (merged per IP)",
            "sipg s '<q>' -T -F ip,port,org",
        ),
        (
            "ports",
            "All ports Shodan has for each host (GET /shodan/host/{ip}, one API call per unique IP)",
            "sipg s '<q>' -T -F ip,ports,org",
        ),
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
                "description": "Fields supported by search --fields",
                "fields": [
                    {"name": name, "description": description, "example": example}
                    for name, description, example in detail_fields
                ],
            },
            "asset_csv": {
                "description": "Fields supported by search --collect ... -O csv",
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

    console.print("\n[blue]search --collect ... -O csv fields:[/blue]")
    console.print("  [green]type[/green] - Asset category: ips/domains/subdomains")
    console.print("  [green]value[/green] - Asset value")
    console.print(
        "  [dim]Example: sipg search 'ssl:\"nvidia\"' --collect all -o out.csv -O csv --fields type,value[/dim]"
    )


@cli.command()
@click.option(
    "--probe",
    is_flag=True,
    help="Call GET /shodan/host/search once (uses 1 query credit) to verify Search API access for -D/-T/-F.",
)
def info(probe: bool):
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

        if probe:
            console.print(
                "\n[blue]Search API probe[/blue] [dim](GET /shodan/host/search, 1 query credit)[/dim]:"
            )
            try:
                grabber.probe_host_search_access()
                console.print(
                    "  [green]Search API:[/green] allowed — host/search returned 200 "
                    "[dim](-D / -T / -F can use full host data when this succeeds)[/dim]"
                )
            except ShodanAPIError as e:
                sc = getattr(e, "status_code", None)
                console.print(
                    f"  [yellow]Search API:[/yellow] not usable (HTTP {sc or 'error'})"
                )
                console.print(
                    "  [dim]api-info can still work while host/search is blocked on some plans (e.g. Academic). "
                    "SIPG will fall back to free IP streaming for rich flags.[/dim]"
                )
                console.print(f"  [dim]{e}[/dim]")
        
    except ShodanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def examples():
    """Show practical commands with common arguments."""
    examples_data = [
        ("Basic IP search", "sipg s 'ssl:\"Uber Technologies Inc\"'"),
        ("Details view (JSON in console)", "sipg s 'port:443' -D"),
        ("Table view (plural alias accepted)", "sipg s 'product:\"nginx\"' --tables"),
        ("Filter wrapper mode", "echo \"nvidia.com\" | sipg s -f ssl"),
        (
            "Free mode with domains/subdomains",
            "sipg s 'ssl:\"nvidia\"' -M free -c domains,subdomains",
        ),
        ("Silent raw output", "sipg s 'ssl:\"nvidia\"' -M free -s"),
        ("Limit + delay", "sipg s 'http.server:Apache' -m 200 -d 1.5"),
        ("Page range", "sipg s 'country:\"United States\"' -p 2 -P 5"),
        ("Auto format by extension (JSON)", "sipg s 'ssl:\"nvidia\"' -c all -o assets.json"),
        ("Auto format by extension (CSV)", "sipg s 'ssl:\"nvidia\"' -c all -o assets.csv -F type,value"),
        (
            "Override output format explicitly",
            "sipg s 'ssl:\"nvidia\"' -c all -o out.txt -O json",
        ),
        ("API rate spacing control", "sipg s 'port:80' -M api -I 1.2"),
    ]

    console.print("[blue]Command Examples (search-focused):[/blue]\n")
    for i, (desc, cmd) in enumerate(examples_data, 1):
        console.print(f"[cyan]{i}.[/cyan] [green]{desc}[/green]")
        console.print(f"   [yellow]{cmd}[/yellow]\n")

    console.print("[dim]Tip: run `sipg s --help` to see every available argument.[/dim]")


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
cli.add_command(configure, "cfg")
cli.add_command(info, "i")
cli.add_command(examples, "ex")
cli.add_command(clear, "cl")
cli.add_command(fields, "fs")


def main():
    """Main entry point for the CLI."""
    if len(sys.argv) == 1:
        print_banner()
        console.print(
            "\n[blue]Use 'sipg --help' for SIPG (Shodan IP Grabber) commands.[/blue]"
        )
        return
    
    cli()


if __name__ == "__main__":
    main() 
