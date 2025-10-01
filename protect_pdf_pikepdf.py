#!/usr/bin/env python3
"""
protect_pdf_pikepdf.py
Protect a single PDF using pikepdf (qpdf under the hood).

Features:
- Set user (open) password and owner password
- Set permission flags (print/modify/copy/annotate)
- Optionally remove metadata (XMP & document info)
- Save to specified output path
"""

import argparse
from pathlib import Path
import sys
import pikepdf

def build_permissions(allow_print, allow_modify, allow_copy, allow_annotate):
    return pikepdf.Permissions(
        allow_print=allow_print,
        allow_modify=allow_modify,
        allow_copy=allow_copy,
        allow_annotate=allow_annotate
    )

def protect(input_path: Path, output_path: Path, user_password: str, owner_password: str,
            allow_print: bool, allow_modify: bool, allow_copy: bool, allow_annotate: bool,
            remove_metadata: bool, encryption_method: str):
    if encryption_method not in ("aes128", "aes256", "rc4"):
        raise ValueError("encryption_method must be 'aes128', 'aes256', or 'rc4'")
    perm = build_permissions(allow_print, allow_modify, allow_copy, allow_annotate)

    with pikepdf.open(input_path) as pdf:
        if remove_metadata:
            try:
                pdf.docinfo.clear()
            except Exception:
                pass
            try:
                pdf.open_metadata(set_pikepdf_version=False).clear()
            except Exception:
                pass

        if encryption_method == "aes256":
            encryption = pikepdf.Encryption(owner=owner_password or "", user=user_password or "",
                                            R=6)  # AES-256
        elif encryption_method == "aes128":
            encryption = pikepdf.Encryption(owner=owner_password or "", user=user_password or "",
                                            R=4)  # AES-128
        else:
            encryption = pikepdf.Encryption(owner=owner_password or "", user=user_password or "",
                                            R=3)  # RC4-128

        pdf.save(output_path, encryption=encryption, permissions=perm)
    print(f"Protected PDF saved to: {output_path}")

def parse_bool_flag(val: str):
    val = val.lower()
    if val in ("1", "true", "yes", "y"):
        return True
    if val in ("0", "false", "no", "n"):
        return False
    raise argparse.ArgumentTypeError("Boolean flag expected (true/false)")

def main():
    parser = argparse.ArgumentParser(description="Protect a PDF using pikepdf (qpdf backend).")
    parser.add_argument("-i", "--input", required=True, help="Input PDF path")
    parser.add_argument("-o", "--output", required=False, help="Output protected PDF path")
    parser.add_argument("-u", "--userpw", required=True, help="User (open) password")
    parser.add_argument("-w", "--ownerpw", required=False, default=None, help="Owner password (optional)")
    parser.add_argument("--allow-print", type=parse_bool_flag, default=False, help="Allow printing (true/false). Default false.")
    parser.add_argument("--allow-modify", type=parse_bool_flag, default=False, help="Allow modify (true/false). Default false.")
    parser.add_argument("--allow-copy", type=parse_bool_flag, default=False, help="Allow copy/extract (true/false). Default false.")
    parser.add_argument("--allow-annotate", type=parse_bool_flag, default=False, help="Allow annotate (true/false). Default false.")
    parser.add_argument("--remove-metadata", action="store_true", help="Remove metadata (XMP and docinfo)")
    parser.add_argument("--enc", choices=["aes128","aes256","rc4"], default="aes256", help="Encryption: aes256 (default), aes128, rc4")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print("Input PDF not found:", input_path, file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else input_path.with_name(input_path.stem + "_protected.pdf")
    output_path = output_path.expanduser().resolve()

    protect(
        input_path=input_path,
        output_path=output_path,
        user_password=args.userpw,
        owner_password=args.ownerpw,
        allow_print=args.allow_print,
        allow_modify=args.allow_modify,
        allow_copy=args.allow_copy,
        allow_annotate=args.allow_annotate,
        remove_metadata=args.remove_metadata,
        encryption_method=args.enc
    )

if __name__ == "__main__":
    main()
