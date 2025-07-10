"""
Core functionality for SIPG.
"""

import time
import ipaddress
from typing import List, Optional, Iterator, Dict, Any
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .config import Config


class ShodanAPIError(Exception):
    """Exception raised for Shodan API errors."""
    pass


class ShodanIPGrabber:
    """Main class for Shodan IP grabbing functionality."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the Shodan IP Grabber.
        
        Args:
            config: Configuration object. If None, creates a new one.
        """
        self.config = config or Config()
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SIPG/2.1.0 (https://github.com/emptymahbob/sipg)'
        })
    
    def _make_request(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make a request to the Shodan API.
        
        Args:
            url: API endpoint URL.
            params: Query parameters.
            
        Returns:
            JSON response from the API.
            
        Raises:
            ShodanAPIError: If the API request fails.
        """
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ShodanAPIError(f"API request failed: {e}")
        except ValueError as e:
            raise ShodanAPIError(f"Invalid JSON response: {e}")
    
    def search_ips(self, query: str, max_results: Optional[int] = None, 
                   delay: float = 1.0, start_page: int = 1, end_page: Optional[int] = None) -> Iterator[str]:
        """Search for IP addresses using Shodan.
        
        Args:
            query: Search query string.
            max_results: Maximum number of results to return. If None, returns all.
            delay: Delay between API requests in seconds.
            start_page: The first page to fetch (1-based).
            end_page: The last page to fetch (inclusive). If None, fetches up to the last available page.
            
        Yields:
            IP addresses found.
            
        Raises:
            ShodanAPIError: If the API request fails.
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError("No API key configured. Use 'sipg configure' to set your API key.")
        
        params = {
            'key': api_key,
            'query': query,
            'page': 1
        }
        
        try:
            initial_response = self._make_request(
                'https://api.shodan.io/shodan/host/search', 
                params
            )
            total_results = initial_response.get('total', 0)
            
            if total_results == 0:
                self.console.print("[yellow]No results found for the given query.[/yellow]")
                return
            
            self.console.print(f"[green]Found {total_results} total results[/green]")
            
            results_per_page = 100
            total_pages = (total_results + results_per_page - 1) // results_per_page
            
            if max_results:
                total_pages = min(total_pages, (max_results + results_per_page - 1) // results_per_page)
            
            # Apply custom page range
            first_page = max(1, start_page)
            last_page = min(end_page if end_page else total_pages, total_pages)
            if first_page > last_page:
                return
            
            ip_count = 0
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task(f"Searching IPs...", total=last_page - first_page + 1)
                
                for page in range(first_page, last_page + 1):
                    progress.update(task, description=f"Searching page {page}/{last_page}")
                    params['page'] = page
                    response = self._make_request(
                        'https://api.shodan.io/shodan/host/search',
                        params
                    )
                    matches = response.get('matches', [])
                    for match in matches:
                        ip = match.get('ip_str')
                        if ip and self._is_valid_ipv4(ip):
                            ip_count += 1
                            yield ip
                            if max_results and ip_count >= max_results:
                                return
                    progress.advance(task)
                    if page < last_page:
                        time.sleep(delay)
        except ShodanAPIError:
            raise
        except Exception as e:
            raise ShodanAPIError(f"Unexpected error: {e}")
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Check if an IP address is a valid IPv4 address.
        
        Args:
            ip: IP address string.
            
        Returns:
            True if valid IPv4, False otherwise.
        """
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False
    
    def search_with_details(self, query: str, max_results: Optional[int] = None,
                           delay: float = 1.0, start_page: int = 1, end_page: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Search for IP addresses with additional details.
        
        Args:
            query: Search query string.
            max_results: Maximum number of results to return.
            delay: Delay between API requests in seconds.
            start_page: The first page to fetch (1-based).
            end_page: The last page to fetch (inclusive). If None, fetches up to the last available page.
            
        Yields:
            Dictionary containing IP and additional details.
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError("No API key configured. Use 'sipg configure' to set your API key.")
        
        params = {
            'key': api_key,
            'query': query,
            'page': 1
        }
        
        try:
            initial_response = self._make_request(
                'https://api.shodan.io/shodan/host/search',
                params
            )
            total_results = initial_response.get('total', 0)
            
            if total_results == 0:
                self.console.print("[yellow]No results found for the given query.[/yellow]")
                return
            
            self.console.print(f"[green]Found {total_results} total results[/green]")
            
            results_per_page = 100
            total_pages = (total_results + results_per_page - 1) // results_per_page
            
            if max_results:
                total_pages = min(total_pages, (max_results + results_per_page - 1) // results_per_page)
            
            # Apply custom page range
            first_page = max(1, start_page)
            last_page = min(end_page if end_page else total_pages, total_pages)
            if first_page > last_page:
                return
            
            result_count = 0
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task(f"Searching details...", total=last_page - first_page + 1)
                
                for page in range(first_page, last_page + 1):
                    progress.update(task, description=f"Searching page {page}/{last_page}")
                    params['page'] = page
                    response = self._make_request(
                        'https://api.shodan.io/shodan/host/search',
                        params
                    )
                    matches = response.get('matches', [])
                    for match in matches:
                        ip = match.get('ip_str')
                        if ip and self._is_valid_ipv4(ip):
                            result_count += 1
                            yield match
                            if max_results and result_count >= max_results:
                                return
                    progress.advance(task)
                    if page < last_page:
                        time.sleep(delay)
        except ShodanAPIError:
            raise
        except Exception as e:
            raise ShodanAPIError(f"Unexpected error: {e}")
    
    def display_results_table(self, results: List[Dict[str, Any]]) -> None:
        """Display results in a formatted table.
        
        Args:
            results: List of result dictionaries.
        """
        if not results:
            self.console.print("[yellow]No results to display.[/yellow]")
            return
        
        table = Table(title="Shodan Search Results")
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Port", style="magenta")
        table.add_column("Organization", style="green")
        table.add_column("Location", style="yellow")
        table.add_column("Hostnames", style="blue")
        
        for result in results:
            location = result.get('location', {})
            location_str = f"{location.get('city', 'N/A')}, {location.get('country_name', 'N/A')}"
            
            hostnames = ', '.join(result.get('hostnames', [])[:2])  # Show first 2 hostnames
            if len(result.get('hostnames', [])) > 2:
                hostnames += f" (+{len(result.get('hostnames', [])) - 2} more)"
            
            table.add_row(
                result['ip'],
                str(result.get('port', 'N/A')),
                result.get('org', 'N/A'),
                location_str,
                hostnames or 'N/A'
            )
        
        self.console.print(table)
    
    def save_results_to_file(self, results: List[str], filename: str) -> None:
        """Save results to a file.
        
        Args:
            results: List of IP addresses.
            filename: Output filename.
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for ip in results:
                    f.write(f"https://{ip}\n")
            self.console.print(f"[green]Results saved to {filename}[/green]")
        except IOError as e:
            self.console.print(f"[red]Failed to save results: {e}[/red]")
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get information about the current API key.
        
        Returns:
            Dictionary containing API information.
            
        Raises:
            ShodanAPIError: If the API request fails.
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError("No API key configured.")
        
        params = {'key': api_key}
        return self._make_request('https://api.shodan.io/api-info', params) 