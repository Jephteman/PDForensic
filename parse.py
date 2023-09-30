from argparse import ArgumentParser, Namespace

def parse_args() -> Namespace:
    """
    This function parses command line arguments.
    """

    parser = ArgumentParser(
        description="This script parses and analyses PDF files for Forensic Investigations"
    )
    add_argument = parser.add_argument

    add_argument(
        "files",
        nargs="+",
        action="extend",
        help="Glob syntax, URL, '-' (stdin) to get PDF files data.",
    )
    add_argument(
        "-l",
        "--logs",
        type=int,
        default=51,
        help="Logs level (1 print all logs; 30 print warnings, error and critical)",
    )

    add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
        help="Show all details",
    )
    add_argument(
        "-c",
        "--no-csv",
        default=False,
        action="store_true",
        help="Deactivate CSV report",
    )
    add_argument(
        "-j",
        "--no-json",
        default=False,
        action="store_true",
        help="Deactivate JSON report",
    )
    add_argument(
        "-p",
        "--no-print",
        default=False,
        action="store_true",
        help="Deactivate printer",
    )

    group_data = parser.add_mutually_exclusive_group()
    group_data.add_argument(
        "-d",
        "--data",
        default=False,
        action="store_true",
        help="Process all data (tags, stream ect...)",
    )
    group_data.add_argument(
        "-t",
        "--tags",
        default=True,
        action="store_true",
        help="Process only tags.",
    )

    group_exclusive_filter = parser.add_mutually_exclusive_group()
    group_exclusive_filter.add_argument(
        "-f",
        "--no-filter",
        default=False,
        action="store_true",
        help="No filter, each object are processed",
    )

    group_filter = parser.add_argument_group(
        "Filter", description="Add custom elements to filter"
    )
    group_filter_add_argument = group_filter.add_argument
    group_filter_add_argument(
        "-s",
        "--strings",
        default=[],
        nargs="+",
        action="extend",
        help="Add string element to filter.",
    )
    group_filter_add_argument(
        "-r",
        "--regex",
        default=[],
        nargs="+",
        action="extend",
        help="Add regex element to filter.",
    )
    group_filter_add_argument(
        "-x",
        "--hexadecimal-data",
        "--hexa",
        default=[],
        nargs="+",
        action="extend",
        help="Add hexadecimal binary data element to filter.",
    )
    group_filter_add_argument(
        "-y",
        "--types",
        default=[],
        nargs="+",
        action="extend",
        help="Add a filter for PDF objects based on type name.",
    )
    group_filter_add_argument(
        "-i",
        "--ids",
        default=[],
        type=int,
        nargs="+",
        action="extend",
        help="Add a filter for PDF objects based on ID.",
    )

    return parser.parse_args()

