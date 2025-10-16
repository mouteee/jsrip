#!/usr/bin/env python3
"""
jsrip - JavaScript Ripper and Analyzer
A tool for crawling sites, downloading JavaScript, and analyzing for secrets & endpoints.
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

from core.analyzer import JSAnalyzer
from core.crawler import PlaywrightCrawler
from utils.reporter import ReportGenerator
from utils.logger import setup_logger


DEFAULT_OUTPUT_BASENAME = "./jsrip_output"


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="jsrip - Download and analyze JavaScript files from URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick start (auto-named output folder)
  python3 jsrip.py -u https://example.com

  # Analyze multiple targets from a file
  python3 jsrip.py -l urls.txt --format md json html

  # Deeper crawl with a named output folder
  python3 jsrip.py -u https://example.com --max-depth 3 -o ./runs/example_1
""",
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--url", help="Single URL to analyze")
    input_group.add_argument("-l", "--list", help="File with URLs (one per line)")

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_BASENAME,
        help=f"Output directory (default: {DEFAULT_OUTPUT_BASENAME}*auto_timestamp*)",
    )
    parser.add_argument(
        "-f",
        "--format",
        nargs="+",
        choices=["json", "pdf", "md", "html", "csv"],
        default=["json", "md"],
        help="Report format(s) (default: json md)",
    )

    # Crawler options
    # Requires Python 3.9+ for BooleanOptionalAction
    parser.add_argument(
        "--headless",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Run browser headless (default: True). Use --no-headless to show browser.",
    )
    parser.add_argument(
        "--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)"
    )
    parser.add_argument(
        "--max-pages", type=int, default=500, help="Maximum pages to crawl (default: 500)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Page load timeout in seconds (default: 30)",
    )

    # Analysis options
    parser.add_argument(
        "--no-beautify",
        action="store_true",
        help="Don't beautify JavaScript before analysis",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=3.5,
        help="Minimum entropy for secret detection (default: 3.5) [info only]",
    )
    parser.add_argument(
        "--min-secret-length",
        type=int,
        default=8,
        help="Minimum secret length (default: 8) [info only]",
    )

    # Additional options
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--headers", help="JSON file with custom HTTP headers")
    parser.add_argument("--cookies", help="JSON file with cookies")
    parser.add_argument(
        "--user-agent",
        default="jsrip/1.0 (JavaScript Analyzer)",
        help="Custom user agent string",
    )

    return parser.parse_args()


def load_urls(args):
    """Load URLs from file or single URL argument."""
    if args.url:
        return [args.url]

    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                urls = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
            return urls
        except FileNotFoundError:
            print(f"[!] Error: File not found: {args.list}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading URL list: {e}")
            sys.exit(1)

    return []


def load_json_file(filepath, file_type):
    """Load JSON file for headers or cookies."""
    if not filepath:
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Warning: {file_type} file not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Warning: Invalid JSON in {file_type} file: {e}")
        return None


def auto_output_dir(user_arg: str) -> Path:
    """Create a timestamped output dir if the user didn't supply a custom name."""
    if user_arg == DEFAULT_OUTPUT_BASENAME:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path(f"{DEFAULT_OUTPUT_BASENAME}_{timestamp}")
    else:
        out = Path(user_arg)
    out.mkdir(parents=True, exist_ok=True)
    return out


async def main():
    """Main execution function."""
    args = parse_arguments()

    # Output dir (timestamped by default)
    output_dir = auto_output_dir(args.output)

    # Logging
    logger = setup_logger(output_dir, verbose=args.verbose)
    logger.info("=" * 60)
    logger.info("jsrip - JavaScript Ripper and Analyzer")
    logger.info("=" * 60)

    # URLs
    urls = load_urls(args)
    logger.info(f"Loaded {len(urls)} URL(s) for analysis")

    # Headers / Cookies
    headers = load_json_file(args.headers, "headers")
    cookies = load_json_file(args.cookies, "cookies")

    # Config (passed to crawler; analyzer gets explicit kwargs)
    config = {
        "output_dir": output_dir,
        "user_agent": args.user_agent,
        "headers": headers,
        "cookies": cookies,
        "headless": args.headless,
        "max_depth": args.max_depth,
        "max_pages": args.max_pages,
        "timeout": args.timeout,
        "beautify": not args.no_beautify,
        "entropy_threshold": args.entropy_threshold,
        "min_secret_length": args.min_secret_length,
        "verbose": args.verbose,
    }

    # Results container
    scan_results = {
        "scan_info": {
            "start_time": datetime.now().isoformat(),
            "urls_count": len(urls),
            "urls": urls,
        },
        "statistics": {
            "js_files_downloaded": 0,
            "secrets_found": 0,
            "endpoints_discovered": 0,
            "unique_domains": set(),
        },
        "findings": {"secrets": [], "endpoints": [], "js_files": []},
    }

    try:
        # Stage 1: Crawl
        logger.info("\n[Stage 1/3] Crawling URLs and discovering JavaScript files...")
        crawler = PlaywrightCrawler(config, logger)
        js_files = await crawler.crawl_urls(urls)
        scan_results["statistics"]["js_files_downloaded"] = len(js_files)
        scan_results["findings"]["js_files"] = js_files
        logger.info(f"✓ Discovered {len(js_files)} JavaScript files")

        # Stage 2: Analyze
        logger.info("\n[Stage 2/3] Analyzing JavaScript files...")
        analyzer = JSAnalyzer(
            output_dir=output_dir,
            beautify=config["beautify"],
            verbose=config["verbose"],
        )
        analysis_results = analyzer.analyze_files(js_files)

        scan_results["statistics"]["secrets_found"] = len(
            analysis_results.get("secrets", [])
        )
        scan_results["statistics"]["endpoints_discovered"] = len(
            analysis_results.get("endpoints", [])
        )
        scan_results["findings"]["secrets"] = analysis_results.get("secrets", [])
        scan_results["findings"]["endpoints"] = analysis_results.get("endpoints", [])

        # Unique domains
        from urllib.parse import urlparse

        for js_file in js_files:
            domain = urlparse(js_file["url"]).netloc
            scan_results["statistics"]["unique_domains"].add(domain)

        logger.info(
            f"✓ Found {scan_results['statistics']['secrets_found']} potential secrets"
        )
        logger.info(
            f"✓ Discovered {scan_results['statistics']['endpoints_discovered']} endpoints"
        )

        # Stage 3: Reports
        logger.info("\n[Stage 3/3] Generating reports...")

        # JSON-serializable stats
        scan_results["statistics"]["unique_domains"] = list(
            scan_results["statistics"]["unique_domains"]
        )
        scan_results["scan_info"]["end_time"] = datetime.now().isoformat()

        # Duration
        start = datetime.fromisoformat(scan_results["scan_info"]["start_time"])
        end = datetime.fromisoformat(scan_results["scan_info"]["end_time"])
        scan_results["scan_info"]["duration"] = str(end - start)

        # Reports
        reporter = ReportGenerator(output_dir, logger)
        for fmt in args.format:
            reporter.generate_report(scan_results, fmt)

        logger.info(f"\n✓ Reports generated: {', '.join(args.format)}")
        logger.info(f"✓ All outputs saved to: {output_dir}")

        # Console summary (friendly)
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Targets:           {scan_results['scan_info']['urls_count']}")
        print(f"JS Files Found:    {scan_results['statistics']['js_files_downloaded']}")
        print(f"Secrets Found:     {scan_results['statistics']['secrets_found']}")
        print(f"Endpoints Found:   {scan_results['statistics']['endpoints_discovered']}")
        print(f"Duration:          {scan_results['scan_info']['duration']}")
        print(f"Output Directory:  {output_dir}")
        print("=" * 60)

    except ModuleNotFoundError as e:
        # Common first-run hiccup: Playwright not installed
        print(f"[!] Missing dependency: {e}")
        print(
            "    Tip: pip install -r requirements.txt && playwright install chromium"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logger.error("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n[!] Critical error: {e}")
        import traceback

        traceback.print_exc()
        print(f"\n[!] Something went wrong. Check logs in: {output_dir}/jsrip.log")
        sys.exit(1)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
