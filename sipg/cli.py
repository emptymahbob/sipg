"""
Command-line interface for SIPG.
"""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from .core import ShodanIPGrabber, ShodanAPIError
from .config import Config

console = Console()

# Banner
BANNER = r"""
[red]  ______           [/red][yellow]_______ [/yellow][red] _______         [/red][yellow]______     [/yellow]
[red] /      \         [/red][yellow]/      /[/yellow][red] /       \       [/red][yellow]/      \    [/yellow]
[red]/$$$$$$$ |        [/red][yellow]$$$$$$/[/yellow][red] $$$$$$$  |      [/red][yellow]/$$$$$$  |   [/yellow]
[red]$$ \__$$/        [/red][yellow]   $$ | [/yellow][red]$$ |__$$ |      [/red][yellow]$$ | _$$/    [/yellow]
[red]$$      \        [/red][yellow]   $$ | [/yellow][red] $$    $$/       [/red][yellow]$$ |/    |   [/yellow]
[red] $$$$$$  |        [/red][yellow]  $$ | [/yellow][red] $$$$$$$/        [/red][yellow]$$ |$$$$ |   [/yellow]
[red]/  \__$$ |__     [/red][yellow]  _$$ |_ [/yellow][red]$$ |            [/red][yellow]$$ \__$$ |__ [/yellow]
[red]$$    $$//  |  [/red][yellow]   / $$   [/yellow][red]|$$ |            [/red][yellow]$$    $$//  |[/yellow]
[red] $$$$$$/ $$/    [/red][yellow]  $$$$$$/ [/yellow][red]$$/              [/red][yellow]$$$$$$/ $$/[/yellow]
"""


def print_banner():
    """Print the SIPG banner."""
    console.print(Panel(BANNER, title="SIPG v2.1.0", subtitle="Made by @emptymahbob"))


@click.group()
@click.version_option(version="2.1.0", prog_name="SIPG")
def cli():
    """SIPG - Shodan IP Grabber

    A professional command-line tool for searching IP addresses using Shodan API.

    Example:
      sipg search 'ssl:"Uber Technologies Inc"'
      sipg search http.server:Apache
      sipg search 'ssl.cert.subject.CN:"*.uber.com"'
    """
    pass


@cli.command()
@click.option('--api-key', prompt=True, hide_input=True, 
              help='Your Shodan API key')
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
        console.print(f"[blue]Scan credits:[/blue] {api_info.get('scan_credits', 'Unknown')}")
        
    except ShodanAPIError as e:
        console.print(f"[red]✗ Failed to configure API key: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Unexpected error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument('query', type=str)
@click.option('-o', '--output', type=click.Path(), help='Save results to file. If not specified, results are printed to the console. Only IPs are saved for simple output, or detailed JSON for --details.')
@click.option('-m', '--max-results', type=int, help='Maximum number of results to return. Default: all available results.')
@click.option('-d', '--delay', type=float, default=1.0, show_default=True, help='Delay (in seconds) between API requests to avoid rate limits.')
@click.option('--details', is_flag=True, help='Show detailed results with additional information (organization, location, hostnames, etc).')
@click.option('--table', is_flag=True, help='Display results in a formatted table (implies --details).')
@click.option('--start-page', type=int, default=1, show_default=True, help='Start fetching results from this page (1-based).')
@click.option('--end-page', type=int, help='End fetching results at this page (inclusive). If not set, fetches up to the last available page or max-results.')
def search(query: str, output: Optional[str], max_results: Optional[int], 
           delay: float, details: bool, table: bool, start_page: int, end_page: Optional[int]):
    """Search for IP addresses using Shodan.
    
    QUERY: The search query to use (e.g., ssl:"Uber Technologies Inc")

    \b
    Output:
      - By default, prints results to the console.
      - Use -o/--output to save results to a file (IPs only, or detailed JSON with --details).
      - Use --max-results to limit the number of results.
      - Use --start-page/--end-page to fetch results from a specific page range (each page = 100 results).
      - Use --delay to avoid hitting Shodan rate limits (default: 1.0s).
      - Use --details for full info, or --table for a formatted table.

    Examples:
      sipg search 'ssl:"Uber Technologies Inc"' --max-results 200
      sipg search 'http.server:Apache' --details --start-page 2 --end-page 5
      sipg search 'country:"United States"' -o us.txt --start-page 5 --end-page 10
    """
    try:
        grabber = ShodanIPGrabber()
        
        if details or table:
            results = list(grabber.search_with_details(query, max_results, delay, start_page, end_page))
            if table:
                grabber.display_results_table(results)
            else:
                for i, result in enumerate(results, 1):
                    console.print(f"\n[cyan]Result {i}:[/cyan]")
                    console.print(f"  [green]IP:[/green] {result['ip']}")
                    console.print(f"  [green]Port:[/green] {result.get('port', 'N/A')}")
                    console.print(f"  [green]Organization:[/green] {result.get('org', 'N/A')}")
                    location = result.get('location', {})
                    if location:
                        console.print(f"  [green]Location:[/green] {location.get('city', 'N/A')}, {location.get('country_name', 'N/A')}")
                    hostnames = result.get('hostnames', [])
                    if hostnames:
                        console.print(f"  [green]Hostnames:[/green] {', '.join(hostnames)}")
                    domains = result.get('domains', [])
                    if domains:
                        console.print(f"  [green]Domains:[/green] {', '.join(domains)}")
            if output:
                ips = [result['ip'] for result in results]
                grabber.save_results_to_file(ips, output)
        else:
            results = list(grabber.search_ips(query, max_results, delay, start_page, end_page))
            for i, ip in enumerate(results, 1):
                console.print(f"{i}. https://{ip}")
            if output:
                grabber.save_results_to_file(results, output)
        console.print(f"\n[green]Search completed! Found {len(results)} results.[/green]")
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
def info():
    """Show information about your Shodan API key."""
    try:
        grabber = ShodanIPGrabber()
        api_info = grabber.get_api_info()
        
        console.print("[blue]Shodan API Information:[/blue]")
        console.print(f"  [green]Plan:[/green] {api_info.get('plan', 'Unknown')}")
        console.print(f"  [green]Credits:[/green] {api_info.get('credits', 'Unknown')}")
        console.print(f"  [green]Scan credits:[/green] {api_info.get('scan_credits', 'Unknown')}")
        console.print(f"  [green]Query credits:[/green] {api_info.get('query_credits', 'Unknown')}")
        console.print(f"  [green]Monitored IPs:[/green] {api_info.get('monitored_ips', 'Unknown')}")
        
    except ShodanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def examples():
    """Show example search queries."""
    examples_data = [
        {
            "description": "Find IPs with SSL certificates from Uber Technologies",
            "query": "'ssl:\"Uber Technologies Inc\"'"
        },
        {
            "description": "Find IPs with HTTP status 200",
            "query": "http.status:200"
        },
        {
            "description": "Find IPs with specific SSL certificate subject",
            "query": "'ssl.cert.subject.CN:\"*.uber.com\"'"
        },
        {
            "description": "Find IPs with Apache server",
            "query": "http.server:Apache"
        },
        {
            "description": "Find IPs in specific country",
            "query": "'country:\"United States\"'"
        },
        {
            "description": "Find IPs with specific port open",
            "query": "port:80"
        },
        {
            "description": "Find IPs with specific product",
            "query": "'product:\"nginx\"'"
        },
        {
            "description": "Find IPs with specific organization",
            "query": "'org:\"Amazon\"'"
        }
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


def main():
    """Main entry point for the CLI."""
    if len(sys.argv) == 1:
        print_banner()
        console.print("\n[blue]Use 'sipg --help' to see available commands.[/blue]")
        return
    
    cli()


if __name__ == '__main__':
    main() 