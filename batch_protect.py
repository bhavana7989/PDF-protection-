#!/usr/bin/env python3
"""
batch_protect.py
Protect all PDFs in a given input directory and write outputs to an output directory.
Uses protect_pdf_pikepdf.py logic (we replicate a minimal version here for convenience).
"""

import argparse
from pathlib import Path
import getpass
from tqdm import tqdm
import subprocess
import sys

def main():
    p = argparse.ArgumentParser(description="Batch protect PDFs in a folder (uses pikepdf wrapper).")
    p.add_argument("-i", "--indir", required=True, help="Input directory containing PDFs")
    p.add_argument("-o", "--outdir", required=True, help="Output directory for protected PDFs")
    p.add_argument("-p", "--password", required=False, help="Password to use for all files (if omitted you'll be prompted)")
    p.add_argument("--owner", required=False, help="Owner password (optional)")
    p.add_argument("--enc", choices=["aes128","aes256","rc4"], default="aes256", help="Encryption method")
    p.add_argument("--remove-metadata", action="store_true", help="Remove metadata")
    args = p.parse_args()

    indir = Path(args.indir).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    if not args.password:
        pw = getpass.getpass("Enter password to use for all PDFs: ")
    else:
        pw = args.password

    pdf_files = sorted(indir.glob("*.pdf"))
    if not pdf_files:
        print("No PDF files found in:", indir)
        sys.exit(0)a

    for pdf in tqdm(pdf_files, desc="Protecting PDFs"):
        outpath = outdir / f"{pdf.stem}_protected.pdf"
        cmd = [
            sys.executable, str(Path(__file__).parent / "protect_pdf_pikepdf.py"),
            "-i", str(pdf), "-o", str(outpath), "-u", pw
        ]
        if args.owner:
            cmd += ["-w", args.owner]
        if args.remove_metadata:
            cmd += ["--remove-metadata"]
        if args.enc:
            cmd += ["--enc", args.enc]

        subprocess.run(cmd, check=True)

    print("Batch protection complete. Output folder:", outdir)

if __name__ == "__main__":
    main()
