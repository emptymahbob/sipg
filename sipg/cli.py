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
    console.print(Panel(BANNER, title="SIPG v2.0.0", subtitle="Made by @emptymahbob"))


@click.group()
@click.version_option(version="2.0.0", prog_name="SIPG")
def cli():
    """SIPG - Shodan IP Grabber
    
    A professional command-line tool for searching IP addresses using Shodan API.
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
@click.argument('query')
@click.option('-o', '--output', type=click.Path(), help='Save results to file')
@click.option('-m', '--max-results', type=int, help='Maximum number of results to return')
@click.option('-d', '--delay', type=float, default=1.0, help='Delay between API requests (seconds)')
@click.option('--details', is_flag=True, help='Show detailed results with additional information')
@click.option('--table', is_flag=True, help='Display results in a formatted table')
def search(query: str, output: Optional[str], max_results: Optional[int], 
           delay: float, details: bool, table: bool):
    """Search for IP addresses using Shodan.
    
    QUERY: The search query to use (e.g., 'ssl:"Uber Technologies Inc"')
    """
    try:
        grabber = ShodanIPGrabber()
        
        if details or table:
            # Get detailed results
            results = list(grabber.search_with_details(query, max_results, delay))
            
            if table:
                grabber.display_results_table(results)
            else:
                # Display detailed results
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
            
            # Save IPs to file if requested
            if output:
                ips = [result['ip'] for result in results]
                grabber.save_results_to_file(ips, output)
        else:
            # Get simple IP results
            results = list(grabber.search_ips(query, max_results, delay))
            
            # Display results
            for i, ip in enumerate(results, 1):
                console.print(f"{i}. https://{ip}")
            
            # Save to file if requested
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
            "query": 'ssl:"Uber Technologies Inc"'
        },
        {
            "description": "Find IPs with HTTP status 200",
            "query": 'http.status:200'
        },
        {
            "description": "Find IPs with specific SSL certificate subject",
            "query": 'ssl.cert.subject.CN:"*.uber.com"'
        },
        {
            "description": "Find IPs with Apache server",
            "query": 'http.server:Apache'
        },
        {
            "description": "Find IPs in specific country",
            "query": 'country:"United States"'
        },
        {
            "description": "Find IPs with specific port open",
            "query": 'port:80'
        },
        {
            "description": "Find IPs with specific product",
            "query": 'product:"nginx"'
        },
        {
            "description": "Find IPs with specific organization",
            "query": 'org:"Amazon"'
        }
    ]
    
    console.print("[blue]Example Search Queries:[/blue]\n")
    
    for i, example in enumerate(examples_data, 1):
        console.print(f"[cyan]{i}.[/cyan] [green]{example['description']}[/green]")
        console.print(f"   [yellow]sipg search \"{example['query']}\"[/yellow]\n")


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