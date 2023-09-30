from re import compile as regex, Pattern


pdf_parser: Pattern = regex(
    r"""(?xs)
(?P<null>
    \d+\s+\d+\s+obj\s+null\s+endobj
) |
(?P<boolean>
    \d+\s+\d+\s+obj\s+(true|false)\s+endobj
) |
(?P<integer>
    \d+\s+\d+\s+obj\s+-?\d+\s+endobj
) |
(?P<number>
    \d+\s+\d+\s+obj\s+-?\d+\.\d+\s+endobj
) |
(?P<ref>
    \d+\s+\d+\s+obj\s+\d+\s\d+\sR\s+endobj
) |
(?P<string>
    \d+\s+\d+\s+obj\s+\([\x00-\xff]+\)\s+endobj
) |
(?P<array>
    \d+\s+\d+\s+obj\s+\[\s*((-?\d+(\.\d+)?|R|\([\x00-\xff]+?\)|<+[\x00-\xff]+?>+|\[[\x00-\xff]*?\]|true|false|null|/\w+)\s+)*(-?\d+(\.\d+)?|R|\([\x00-\xff]+\)|<+[\x00-\xff]+?>+|\[[\x00-\xff]*?\]|true|false|null|/\w+)\s*\]\s+endobj
) |
(?P<object>
    (\d+\s+\d+\s+obj(\s+<+[\x00-\xff]+?>+))(\s*stream\s([\x00-\xff]*?)(\sendstream)\s+endobj\s|\s+endobj\s)
) |
(?P<root>
    <+((/ID\s*\[\s*(<[\da-fA-F]+>){1,2}\])|[^>]*?)*/Root((/ID\s*\[\s*(<[\da-fA-F]+>){1,2}\])|[^>]*?)*>+
) |
(?P<pdf_tag>
    %PDF(-\d+\.\d+)?\s
) |
(?P<eof_tag>
    %%EOF\s?
) |
(?P<binary_tag>
    %[\x00-\xff]{4}\s
) |
(?P<startxref>
    startxref\s+\d+\s+
) |
(?P<xref>
    xref[\n\r\w ]+?trailer\s+
) |
(?P<unknow_object>
    \d+\s+\d+\s+obj[\x00-\xff]+?endobj
) |
(?P<unknow_token>
    [^\x00\t\x0c\x20\r\n]+
)
""".encode()
)

tags_parser: Pattern = regex(
    r"""(?xi)
(?P<command>
    \s<+[\x00-\xff]+/Launch[\x00-\xff]+$                                             # Launch can launch a command
) |
(?P<AA_script_starter>
    \s<+[\x00-\xff]+/AA\s*<+[\x00-\xff]+$                                            # Start run automatically scripts
) |endstream\rendobj
(?P<OpenAction_script_starter>
    \s<+[\x00-\xff]+/OpenAction[\x00-\xff]+$                                         # Start run automatically scripts
) |
(?P<scripts>
    \s<+[\x00-\xff]+/JavaScript(\s*/JS(\([\x00-\xff]+\)[\x00-\xff]+)?)?[\x00-\xff]+$ # Javascript code
) |
(?P<stream_object>
    \s<+[\x00-\xff]+/ObjStm\s*(/|>)                                                  # Hide object in stream
) |
(?P<URI>
    \s<+[\x00-\xff]+/URI[\x00-\xff]+$                                                # Access resource by its URL
) |
(?P<form>
    \s<+[\x00-\xff]+/SubmitForm[\x00-\xff]+$                                         # Send data to server
) |
(?P<send>
    \s<+[\x00-\xff]+/GoTo(R|E)[\x00-\xff]+$                                          # Send data to server
) |
(?P<embedded>
    \s<+[\x00-\xff]+/EmbeddedFile[\x00-\xff]+$                                       # Access resource by its URL
) |
(?P<GoTo>
    \s<+[\x00-\xff]+/GoTo\s*/[\x00-\xff]+$                                           # Change the view to a specified destination
) |
(?P<acroform>
    \s<+[\x00-\xff]+/AcroForm[\w\s]*(/|>)
) |
(?P<malicious_image>
    \s<+[\x00-\xff]+/JBIG2Decode\s*(/|>)
) |
(?P<media>
    \s<+[\x00-\xff]+/RichMedia[\x00-\xff]+$                                          # RichMedia can be used to embed Flash in a PDF
) |
(?P<date>
    D:(\d{14})[-+Z]?(\d{2}'\d{2}')?
) |
(?P<type>
    /Type\s*/[\w\s]+
) |
(?P<subtype>
    /Subtype\s*/[\w\s]+
)
""".encode()
)

pdf_tags_char: Pattern = regex(r"#[0-9a-fA-F]{2}".encode())

pdf_string_char: Pattern = regex(r"\\[0-7]{1,3}".encode())

pdf_filters: Pattern = regex(r"/Filter\s*(/\w+|\[(/\w+\s*)+\])".encode())

pdf_streams: Pattern = regex(
    r"\s?stream\s[\x00-\xff]+\sendstream"
)

