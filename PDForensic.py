#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__version__ = "0.2.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This tool analyses PDF files for Forensic Investigations"
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/PDForensic"

copyright = """
PDForensic  Copyright (C) 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["PDForensic"]

from logging import StreamHandler, Formatter, Logger, getLogger
from typing import Dict, Union, Iterable
from sys import stderr, _getframe
from re import compile as regex, Match
from base64 import b16decode, b16encode
from collections.abc import Callable
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime
from math import ceil


from my_regex import * 
from utils import *
from parse import *


# https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf
# http://paulbourke.net/dataformats/postscript/psref.pdf
# https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Welch
# https://github.com/empira/PDFsharp/blob/master/src/PdfSharp/Pdf.Filters/LzwDecode.cs
# https://github.com/katjas/PDFrenderer/blob/master/src/com/sun/pdfview/decode/LZWDecode.java

# http://www-igm.univ-mlv.fr/~lecroq/cours/lzw.pdf
# https://www.normalesup.org/~simonet/teaching/caml-prepa/tp-caml-2001-07.pdf
# https://perso.limsi.fr/anne/coursAlgo/lzwAS.pdf

# https://github.com/hhrutter/lzw/blob/master/reader.go
# https://github.com/gettalong/hexapdf/blob/b9e194418b3b1bf89d6842e264dbff1c348c1332/lib/hexapdf/filter/lzw_decode.rb
# https://github.com/tecnickcom/tc-lib-pdf-filter/blob/c56027589f3e9456c469feaf3a7987cb796f9a44/src/Type/Lzw.php

lzwdecode = LzwDecode().decode


class PDForensic(ABC):

    """
    This class parses and analyses PDF files for Forensic Investigations.
    """

    malicious_scoring: Dict[str, int] = {
        "command": 100,
        "scripts": 100,
        "AA_script_starter": 75,
        "OpenAction_script_starter": 75,
        "stream_object": 50,
        "URI": 25,
        "form": 25,
        "send": 25,
        "embedded": 25,
        "GoTo": 15,
        "acroform": 15,
        "malicious_image": 10,
        "media": 10,
    }

    filters = {
        "LZWDecode": lzwdecode,
        "LZW": lzwdecode,
        "ASCII85Decode": a85decode,
        "A85": a85decode,
        "ASCIIHexDecode": hex_decode,
        "AHx": hex_decode,
        "FlateDecode": deflate,
        "Fl": deflate,
        "RunLengthDecode": runlength_decode,
        "R": runlength_decode,
    }

    def __init__(
        self,
        file: str,
        process_data: bool = False,
        process_tags: bool = True,
        filter_: bool = True,
        strings: Iterable[str] = [],
        hexa: Iterable[str] = [],
        regexs: Iterable[str] = [],
        types: Iterable[str] = [],
        ids: Iterable[int] = [],
    ):
        self.hexa = {b16decode(string.encode().upper()) for string in hexa}
        self.types = {string.strip().casefold() for string in types}
        self.regex = {regex(string.encode()) for string in regexs}
        self.strings = {string.encode() for string in strings}
        self.ids = {integer for integer in ids}

        self.custom_filter = (
            len(self.hexa)
            + len(self.regex)
            + len(self.strings)
            + len(self.types)
            + len(self.ids)
        )

        self.process_data = process_data
        self.process_tags = process_tags
        self.type_counter = Counter()
        self.use_filter = filter_
        self.current_id = 0
        self.exit_code = 0
        self.processed = 0
        self.file = file
        self.score = {}
        self._start = 0
        self.count = 0
        self._end = 0

        if not filter_ and (
            self.hexa or self.regex or self.strings or self.types
        ):
            logger_warning("Filters are not used but you add filter values.")

    def get_malicious_score(self) -> float:
        """
        This function calculates malicious score.
        """

        logger_debug("Getting malicious score for " + str(self.file))
        return (
            sum(self.score.values())
            * 100
            / sum(self.malicious_scoring.values())
        )

    def report(self) -> Dict[str, Union[str, int]]:
        """
        This function reports PDF analysis.
        """

        return {
            "tool": "PDForensic",
            "version": __version__,
            "file": str(self.file),
            "date": datetime.now().isoformat(),
            "malicious": {
                "score": str(ceil(self.get_malicious_score())) + "%",
                "types": list(self.score.keys()),
            },
            "objects": {
                "found": self.count,
                "processed": self.processed,
                "counter": {k: v for k, v in self.type_counter.most_common()},
            },
            "filters": {
                "ids": list(self.ids),
                "types": list(self.types),
                "strings": [x.decode() for x in self.strings],
                "regex": [x.pattern.decode() for x in self.regex],
                "raw data - hexadecimal": [
                    b16encode(x).decode() for x in self.hexa
                ],
            },
        } # type: ignore

    def read_file(self) -> bytes:
        """
        This function returns data readed from PDF file.
        """

        logger_debug("Getting data for " + str(self.file))

        if isinstance(self.file, str):
            try:
                with open(self.file, "rb") as file:
                    return file.read()
            except Exception as e:
                logger_error("Can't open " + self.file + " error: " + str(e))
                self.exit_code += 5
                return None # type: ignore
        else:
            return self.file.read()

    def parse(self) -> None:
        """
        This function parses PDF data.
        """

        data = self.read_file()

        logger_debug("Start data parsing for " + str(self.file))
        for match in pdf_parser.finditer(data):
            self._start = match.start()
            self._end = match.end()
            data = match.group()
            id_ = data.split(maxsplit=1)[0]
            self.current_id = int(id_) if id_.isdigit() else -1

            if match.lastgroup == "object":
                processed = self.get_data_process(match)
            else:
                processed = self.to_handle(match.lastgroup, match.group()) # type: ignore

            if self.current_id in self.ids:
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'id' filter."
                )
                if not processed:
                    self.to_handle("object", data)
                    self.to_handle(
                        "decoded_data",
                        self.pdf_unfilter(match.group(16), data),
                    )

            self.count += 1

    @staticmethod
    def deobfuscation(tags: bytes) -> bytes:
        r"""
        This function deobfuscates tags.

        >>> PDForensic.deobfuscation(r'#61(\142)#63'.encode())
        b'a(b)c'
        >>> PDForensic.deobfuscation(r')'.encode())
        [2016-06-22 17:58:15] ERROR    (40) {PDForensic - PDForensic.py:722} PDF syntax error
        >>>
        """

        for char in pdf_tags_char.finditer(tags):
            char = char.group()
            tags = tags.replace(char, chr(int(char[1:], 16)).encode())

        start_index: int = None # type: ignore
        precedent: int = None # type: ignore

        for i, char in enumerate(tags):
            if precedent:
                continue

            if char == 40:
                start_index = i
            elif char == 41:
                end_index = i
                if start_index is None:
                    logger_error("PDF syntax error")
                    continue
                pdf_string = tags[start_index:end_index]
                for char in pdf_string_char.finditer(pdf_string):
                    char = char.group()
                    pdf_string = pdf_string.replace(
                        char, chr(int(char[1:], 8)).encode()
                    )
                tags = tags[:start_index] + pdf_string + tags[end_index:]

            precedent = char # type: ignore

        return tags

    def pdf_unfilter(self, tags: bytes, full_data: bytes) -> bytes:
        """
        This function decodes and decompress PDF streams.
        """

        filters = pdf_filters.search(tags)

        if filters is None:
            return full_data

        data = full_data[full_data.index(tags) + len(tags) :]
        data = data.split(b"endstream")[0].split(b"stream")[1].strip()

        for filter_ in filters.group(1).decode().strip("[]").split("/"):
            callback = PDForensic.filters.get(filter_)
            if filter_:
                if callback:
                    data = callback(data)
                else:
                    break
        else:
            return data

        return full_data

    def get_data_process(self, match: Match) -> bool:
        """
        This function sends only data to process to filters.
        """

        full_data = match.group()
        logger_debug("Getting tags for object " + str(self.current_id))
        tags = match.group(16)

        tags = self.deobfuscation(tags)

        if self.process_data:
            processed = self.filter(full_data)
        else:
            processed = self.filter(tags)

        logger_debug("Start tags analysis for object " + str(self.current_id))
        for tag in tags_parser.finditer(tags):
            group = tag.lastgroup
            data = tag.group()
            type_ = ""
            suspicious = False

            if group == "type":
                type_ = data.split(b"/")[2].strip().decode()
                processed = self.type_filter(type_, full_data, processed)
                self.type_counter["type - " + type_] += 1
            elif group == "subtype":
                type_ = data.split(b"/")[2].strip().decode()
                processed = self.type_filter(type_, full_data, processed)
                self.type_counter["subtype - " + type_] += 1
            elif group == "stream_object":
                StreamObjectParser(
                    self, self.pdf_unfilter(tags, full_data)
                ).parse()
                suspicious = True
            elif group != "date":
                suspicious = True

            if suspicious:
                logger_info(
                    "Getting suspicious tag: '"
                    + group # type: ignore
                    + "' for object "
                    + str(self.current_id)
                )
                self.score[group] = self.malicious_scoring[group] # type: ignore

            if not self.custom_filter:
                self.to_handle(group, data, type_) # type: ignore

        return processed

    def type_filter(
        self, type_: str, data: bytes, processed: bool = None # type: ignore
    ) -> bool: # type: ignore
        """
        This function filters objects by type.
        """

        if type_.strip().casefold() in self.types:
            logger_info(
                "Object " + str(self.current_id) + " match the 'type' filter."
            )
            if not processed:
                self.to_handle("object", data, type_)
            return True

    def filter(self, data: bytes, decoded_data: bytes = None) -> bool: # type: ignore
        """
        This function filters objects.
        """

        if not self.use_filter:
            self.to_handle("object", data)
            return True

        for string in self.strings:
            if string in data:
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'string' filter."
                )
                self.to_handle("object", data)
                return True

        for raw in self.hexa:
            if raw in data:
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'hexadecimal' filter."
                )
                self.to_handle("object", data)
                return True

        for regex in self.regex:
            if regex.search(data):
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'regex' filter."
                )
                self.to_handle("object", data)
                return True

    def to_handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function calls inherited 'handle_object' methods.
        """

        self.processed += 1
        for class_ in self.__class__.__mro__:
            method = class_.__dict__.get("handle", lambda *x: None)
            if not getattr(method, "__isabstractmethod__", None):
                logger_debug(
                    "Object "
                    + str(self.current_id)
                    + " is processed by '"
                    + class_.__name__
                    + "'."
                )
                method(self, type_, data, typename)

    @abstractmethod
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        pass


def get_custom_logger(name: str = None) -> Logger: # type: ignore
    """
    This function create a custom logger.
    """

    logger = getLogger(name or _getframe().f_code.co_filename)
    logger.propagate = False

    if not logger.handlers:
        formatter = Formatter(
            fmt=(
                "%(asctime)s%(levelname)-9s(%(levelno)s) "
                "{%(name)s - %(filename)s:%(lineno)d} %(message)s"
            ),
            datefmt="[%Y-%m-%d %H:%M:%S] ",
        )
        stream = StreamHandler(stream=stderr)
        stream.setFormatter(formatter)

        logger.addHandler(stream)

    return logger

logger: Logger = get_custom_logger("PDForensic")
logger_debug: Callable = logger.debug
logger_info: Callable = logger.info
logger_warning: Callable = logger.warning
logger_error: Callable = logger.error
logger_critical: Callable = logger.critical
logger_log: Callable = logger.log
