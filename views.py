from PDForensic import PDForensic
from os.path import basename, splitext
from csv import writer
from json import dump




class ToCSV(PDForensic):

    """
    This class saves filtered objects into a CSV report.
    """

    def __init__(self):
        filename = self.csv_filename = (
            splitext(basename(self.file))[0] + ".csv"
            if isinstance(self.file, str)
            else "not_named.csv"
        )
        file = self.csv_file = open(filename, "a")
        self.csv_writer = writer(file)

    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function saves filtered objects into a CSV report.
        """

        if (not self.custom_filter and type_ == "object") or (
            type_ == "object"
            or type_ == "subtype"
            or type_ == "type"
            or type_ == "xref"
            or type_ == "startxref"
        ):
            self.csv_writer.writerow(
                [
                    str(self.current_id),
                    type_,
                    typename,
                    str(self._start),
                    str(self._end),
                ]
            )
        else:
            self.csv_writer.writerow(
                [
                    str(self.current_id),
                    type_,
                    str(data),
                    str(self._start),
                    str(self._end),
                ]
            )


class Printer(PDForensic):

    """
    This class prints filtered objects.
    """
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function prints filtered objects.
        """

        if (not self.custom_filter and type_ == "object") or (
            type_ == "subtype"
            or type_ == "type"
            or type_ == "xref"
            or type_ == "startxref"
        ):
            print(str(self.current_id).ljust(9), type_.ljust(25), typename)
        elif (
            type_ == "null"
            or type_ == "boolean"
            or type_ == "integer"
            or type_ == "number"
            or type_ == "ref"
            or type_ == "string"
            or type_ == "array"
        ):
            print(
                str(self.current_id).ljust(9),
                type_.ljust(25),
                repr(
                    data.split(b"endobj")[0]
                    .split(b"obj")[1]
                    .strip()
                    .decode("latin1")
                ),
            )
        else:
            print(
                str(self.current_id).ljust(9),
                type_.ljust(25),
                repr(data.decode("latin1")),
            )

class NoPrinter(PDForensic):
    """
    This class prints nothings
    """
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        pass
    
class ToJSON(PDForensic):

    """
    This class saves filtered objects into a JSON report.
    """

    def __init__(self):
        filename = self.json_filename = (
            splitext(basename(self.file))[0] + ".json"
            if isinstance(self.file, str)
            else "not_named.json"
        )
        self.json_file = open(filename, "a")

    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function saves filtered objects into a JSON report.
        """

        if (not self.custom_filter and type_ == "object") or (
            type_ == "object"
            or type_ == "subtype"
            or type_ == "type"
            or type_ == "xref"
            or type_ == "startxref"
        ):
            dump(
                {
                    "id": str(self.current_id),
                    "type": type_,
                    "data": typename,
                    "start": self._start,
                    "end": self._end,
                },
                self.json_file,
            )
        else:
            dump(
                {
                    "id": str(self.current_id),
                    "type": type_,
                    "data": data.decode("latin-1"),
                    "start": self._start,
                    "end": self._end,
                },
                self.json_file,
            )
            self.json_file.write("\n")

