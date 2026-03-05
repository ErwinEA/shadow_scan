import json
import re
from pathlib import Path

from PyPDF2 import PdfReader


PDF_PATH = "standards-oui.ieee.org.pdf"
OUTPUT_FILE = "reference.json"


def fetch_oui_text(pdf_path: Path | None = None) -> str:
    """
    Extract text from the local IEEE OUI PDF file.

    The PDF is expected to be the downloaded version of:
      https://standards-oui.ieee.org/oui/oui.txt
    saved as 'standards-oui.ieee.org.pdf' in the project directory.
    """
    if pdf_path is None:
        pdf_path = Path(PDF_PATH)

    if not pdf_path.exists():
        raise FileNotFoundError(
            f"PDF file not found at {pdf_path}. "
            "Make sure 'standards-oui.ieee.org.pdf' is in the project directory."
        )

    reader = PdfReader(str(pdf_path))
    chunks: list[str] = []
    for page in reader.pages:
        page_text = page.extract_text() or ""
        chunks.append(page_text)

    # Join pages with newlines to mimic the original text layout.
    return "\n".join(chunks)


def parse_oui_text(text: str) -> dict:
    """
    Parse the IEEE OUI text and return a dict:

    {
      "286FB9": {
        "vendor": "Nokia Shanghai Bell Co., Ltd.",
        "country": "CN"
      },
      ...
    }
    """
    lines = text.splitlines()
    data = {}
    i = 0

    while i < len(lines):
        line = lines[i]

        # We key off the "(base 16)" line; this has the canonical 6-hex OUI.
        if "(base 16)" in line:
            # Example:
            # 286FB9     (base 16)     Nokia Shanghai Bell Co., Ltd.
            parts = line.split("(base 16)")
            left = parts[0].strip()
            right = parts[1].strip() if len(parts) > 1 else ""

            # OUI is the first token on the left side.
            oui_token = left.split()[0]
            # Normalize: keep only hex digits, uppercase.
            oui_key = re.sub(r"[^0-9A-Fa-f]", "", oui_token).upper()

            vendor = right

            # Look ahead for the country code in the block following this line.
            # A block is terminated by a blank line.
            country = ""
            j = i + 1
            while j < len(lines) and lines[j].strip() != "":
                candidate = lines[j].strip()
                # Country is typically a 2-letter uppercase code like "CN", "US".
                if re.fullmatch(r"[A-Z]{2}", candidate):
                    country = candidate
                j += 1

            if oui_key:
                data[oui_key] = {
                    "vendor": vendor,
                    "country": country,
                }

            # Skip to the end of this block
            i = j
            continue

        i += 1

    return data


def save_reference_json(mapping: dict, output_path: Path) -> None:
    """Save the mapping to a JSON file with pretty formatting."""
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True, ensure_ascii=False)


def main():
    print(f"Reading OUI data from {PDF_PATH} ...")
    text = fetch_oui_text()
    print("Parsing OUI data ...")
    mapping = parse_oui_text(text)
    print(f"Parsed {len(mapping)} entries.")

    output_path = Path(OUTPUT_FILE)
    save_reference_json(mapping, output_path)
    print(f"Saved reference data to {output_path.resolve()}")


if __name__ == "__main__":
    main()