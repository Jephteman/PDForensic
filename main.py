from sys import stdout, stdin
from typing import Tuple, Iterable
from urllib.request import urlopen
from datetime import datetime
from _io import TextIOWrapper
from glob import iglob
from json import dump

from colorama import init as colorama_init , Fore

from pathlib import Path
from posix import listdir

from PDForensic import *
from PDForensic import (
    logger, logger_debug, 
    logger_critical,
    logger_warning
    )

from views import *
from parse import *

colorama_init(True)

def launch(
    code: int,
    file: str,
    arguments: Namespace,
    types: Iterable[type],
    report_file: TextIOWrapper = None ,
    verbose: bool= False
) -> Tuple[int, bool]:
    """
    This function starts PDF file analysis.
    """

    logger_debug("Processing file'" + str(file) + "'")
    forensic = type("PdfAnalysis", types, {"__init__": PDForensic.__init__})( # type: ignore
        file,
        arguments.data,
        arguments.tags,
        not arguments.no_filter,
        arguments.strings,
        arguments.hexadecimal_data,
        arguments.regex,
        arguments.types,
        arguments.ids,
    )
    for type_ in types:
        init = type_.__dict__.get("__init__")
        if init:
            init(forensic)

    forensic.parse()
    report = forensic.report()
    if verbose: 
        dump(report, stdout, indent=4)
        dump(report, report_file)
        report_file.write("\n")
        print()
    else :
        if forensic.get_malicious_score() > 50:
            print(f"{file}")
            print(f"\t {Fore.RED + str(report['malicious'])}")
        else:
            print(f"{file}")
            print(f"\t{Fore.GREEN + str(report['malicious'])}")

    return forensic.exit_code + code, True

def main() -> int:
    """
    This function starts this script from command line.
    """

    print(copyright)

    arguments = parse_args()

    logger.setLevel(arguments.logs)

    report = None
    if arguments.verbose:
        report = open(
            "PDForensic" + datetime.now().strftime("_%Y_%m_%d_%H_%M_%S") + ".json",
            "a",
        )

    types = []
    if arguments.verbose:
        if not arguments.no_csv:
            types.append(ToCSV)
        if not arguments.no_json:
            types.append(ToJSON)
        if not arguments.no_print:
            types.append(Printer)
    
    if not types:
        logger_warning("Nothing to do without print, CSV or JSON. Add print.")
        types.append(NoPrinter)
    types = tuple(types)

    exit_code = 0
    first_all = False

    for globsyntax in arguments.files:
        first = False
        logger_debug("Processing glob syntax '" + globsyntax + "'")

        if globsyntax == "-":
            exit_code, first = launch(
                exit_code, stdin.buffer, arguments, types, report_file=report , verbose=arguments.verbose # type: ignore
            )
            first_all = first
            continue
        elif ":" in globsyntax:
            exit_code, first = launch(
                exit_code, urlopen(globsyntax), arguments, types, report_file=report, verbose=arguments.verbose
            )
            first_all = first
            continue

        for file in iglob(globsyntax):
            if Path(file).is_dir():
                pdf_files = [i for i in listdir(file) if i.split('.')[-1] == "pdf"] 
                for pdf_file in pdf_files:
                    pdf_path = Path(file).joinpath(pdf_file)
                    exit_code, first = launch(
                        exit_code, str(pdf_path), arguments, types, report_file=report
                    )
            if Path(file).is_file:
                exit_code, first = launch(
                    exit_code, file, arguments, types, report_file=report
                )
                first_all = first

        if not first:
            logger_warning("There is no file matching: " + globsyntax)
            exit_code += 1

    if arguments.verbose:
        report.close()

    if not first_all:
        logger_critical("There is no file found.")
        exit_code += 2

    return exit_code % 127

if __name__ == '__main__':
    exit(main())
