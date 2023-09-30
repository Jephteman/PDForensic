from zlib import (
    decompress as zlib,
    decompressobj as zlib_object,
    error as zliberror,
)

from binascii import unhexlify
from contextlib import suppress

from io import BytesIO
from typing import Dict, Union, Tuple, Iterable, List

def hex_decode(data: bytes) -> bytes:
    r"""
    This function decodes hexadecimal encoding (ASCIIHexDecode filter).

    >>> hex_decode(b"05020a 0 a 02>")
    b'\x05\x02\n\n\x02'
    >>>
    """

    return unhexlify(b"".join(data.rstrip(b">").split()))


def deflate(data: bytes) -> bytes:
    r"""
    This function decodes zlib compressed streams (FlateDecode filter).

    >>> deflate(b'x\x9cK\xcb\xcf\x07\x00\x02\x82\x01E')
    b'foo'
    >>> deflate(b'x\x9cJ\xcb\xcf\x07\x00foo')
    b'foofoo'
    >>> deflate(b'foo')
    b'foo'
    >>>
    """

    with suppress(zliberror):
        return zlib(data)

    # data_length = len(data)
    zlib_instance = zlib_object()
    uncompressed = bytearray()
    for index, byte in enumerate(data):
        try:
            uncompressed.extend(
                zlib_instance.decompress(byte.to_bytes(1, "big"))
            )
        except:
            break

    if index < 3:
        return data

    return bytes(uncompressed) + data[index:]


# https://pdfbox.apache.org/docs/1.8.12/javadocs/org/apache/pdfbox/filter/RunLengthDecodeFilter.html
# https://gogit.univ-orleans.fr/lifo/no/openboard/blob/a53f41f71b8346e263e44e146d6e0853e20f4867/src/pdf-merger/RunLengthDecode.cpp


def runlength_decode(data: bytes) -> bytes:
    r"""
    This function decodes streams with filter RunLengthDecode.

    >>> runlength_decode(b'\x030123\xffa\x80')
    b'0123aa'
    >>> runlength_decode(b'\x000\xffa')
    b'0aa'
    >>>
    """

    uncompressed = bytearray()

    characters = BytesIO(data)
    character = characters.read(1)

    while character:
        character = int.from_bytes(characters, "big") # type: ignore
        if character < 128:
            uncompressed.extend(characters.read(character + 1))
        elif character > 128:
            uncompressed.extend(characters.read(1) * (257 - character))
        else:
            break
        character = characters.read(1)

    return bytes(uncompressed)


def a85decode(data: bytes) -> bytes:
    r"""
    This function decodes ascii 85.

    >>> a85decode(b'0AZauzaZbv~foobar')
    b'/\xde\x02D\x00\x00\x00\x00\xc9>'
    >>>
    """

    new_data = bytearray()
    position = block = 0
    for character in data:
        if 32 < character < 118:
            position += 1
            block = block * 85 + character - 33
            if position == 5:
                new_data.extend(block.to_bytes(4, "big"))
                position = block = 0
        elif character == 122:
            new_data.extend(b"\0" * 4)
        elif character == 126:
            if position:
                [block := block * 85 + 84 for _ in range(position, 5)]
                new_data.extend(block.to_bytes(4, "big")[: position - 1])
            break
    return bytes(new_data)


class LzwDecode:
    r"""
    This class decodes LZW compressed data.

    >>> decoder = LzwDecode()
    >>> decoder.decode(b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    b'-----A---B'
    >>> decoder.decode(b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    b'-----A---B'
    >>>
    """

    bits_number_table = {511: 10, 1023: 11, 2047: 12}

    def __init__(self):
        self.character = 0
        self.bits_number = 9
        self.byte = b"\0"
        self.bits_index = 8
        self.precedent_bytes: bytes = None # type: ignore
        self.file = BytesIO()
        self.uncompressed = bytearray()
        self.code = 0

    def decode(self, data: bytes) -> bytes:
        """
        This function decodes compressed data.
        """

        self.code = 0
        self.byte = b"\0"
        self.uncompressed.clear()
        position = self.file.tell()
        self.file.write(data)
        self.file.seek(position)

        while self.byte and self.code != 257:
            self.shift = 8 - self.bits_index
            self.code = 0
            bits = self.bits_number
            while self.byte and self.bits_number > self.shift:
                self.read_block()
            self.code = (self.code << self.bits_number) | (
                (self.character >> (self.shift - self.bits_number))
                & ((1 << self.bits_number) - 1)
            )
            self.bits_index += self.bits_number
            self.bits_number = bits
            self.do_code()

        return bytes(self.uncompressed)

    def read_block(self) -> None:
        """
        This function reads a LZW block.
        """

        self.code = (self.code << self.shift) | (
            self.character & ((1 << self.shift) - 1)
        )
        self.bits_number -= self.shift
        self.byte = self.file.read(1)
        self.character = int.from_bytes(self.byte, "big")
        self.bits_index = 0
        self.shift = 8 - self.bits_index

    def do_code(self) -> None:
        """
        This function makes actions for the specific code.
        """

        if self.code == 256:
            self.table = [x.to_bytes(1, "big") for x in range(256)]
            self.table.extend((None, None)) # type: ignore
            self.precedent_bytes = b""
            self.bits_number = 9
        elif not self.precedent_bytes:
            self.precedent_bytes = self.table[self.code]
            self.uncompressed.extend(self.precedent_bytes)
        elif self.code != 257:
            if self.code < len(self.table):
                x = self.table[self.code]
                self.uncompressed.extend(x)
                self.table.append(
                    self.precedent_bytes + x[0].to_bytes(1, "big")
                )
            else:
                self.table.append(
                    self.precedent_bytes
                    + self.precedent_bytes[0].to_bytes(1, "big")
                )
                x = self.table[self.code]
                self.uncompressed.extend(x)
            self.bits_number = LzwDecode.bits_number_table.get(
                len(self.table), self.bits_number
            )
            self.precedent_bytes = x


class StreamObjectParser:

    """
    This class implements a stream object parser.
    """

    def __init__(self, forensic, data: bytes):
        self.forensic = forensic
        self.data = data

    def get_id_positions(self) -> List[Tuple[int, int]]:
        """
        This function returns IDs and position for each object in the stream.
        """

        data = self.data
        id_position = data.split(b" ", maxsplit=2)

        if len(id_position) == 3:
            id_, position, data = id_position
        else:
            return [], self.data # type: ignore

        id_positions = []
        add = id_positions.append
        while id_.isdigit() and position.isdigit():
            add((int(id_), int(position)))

            id_position = data.split(b" ", maxsplit=2)

            if len(id_position) == 3:
                id_, position, data = id_position
            else:
                break

        data = b" ".join((id_, position, data))
        return id_positions, data # type: ignore

    def parse(self) -> None:
        """
        This function processes tags in stream object.
        """

        id_positions, data = self.get_id_positions()
        forensic = self.forensic
        process_data = forensic.get_data_process

        for id_, position in id_positions[::-1]: # type: ignore
            forensic.current_id = id_
            process_data(
                type("Match", (), {"group": lambda *x: data[position:]})
            )
            data = data[:position]

