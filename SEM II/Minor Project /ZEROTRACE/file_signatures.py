from PyPDF2 import PdfReader, PdfWriter
from docx import Document
import shutil

def add_pdf_signature(input_path, output_path, signature="zerotrace report - high"):
    reader = PdfReader(input_path)
    writer = PdfWriter()

    # Copy all pages as-is
    for page in reader.pages:
        writer.add_page(page)

    # Add or update metadata (non-visible)
    metadata = reader.metadata or {}
    metadata.update({"/ConfidentialSignature": signature})
    writer.add_metadata(metadata)

    with open(output_path, "wb") as f:
        writer.write(f)

    print(f"[+] Metadata signature added to PDF: {output_path}")



def add_docx_signature(input_path, output_path, signature="zerotrace report - high"):
    shutil.copy(input_path, output_path)  # Preserve exact file first
    doc = Document(output_path)
    doc.core_properties.subject = signature  # Metadata only
    doc.save(output_path)
    print(f"[+] Metadata signature added to DOCX: {output_path}")

add_docx_signature("project alpha details.docx", "project alpha conf.docx")

def embed_txt_signature(file_path, signature):
    # Convert signature to zero-width encoding
    zero_width_map = {'0': '\u200b', '1': '\u200c'}
    binary_sig = ''.join(format(ord(c), '08b') for c in signature)
    encoded_signature = ''.join(zero_width_map[b] for b in binary_sig)

    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(f"\n{encoded_signature}\n")
        print(f"Zero-width signature embedded into {file_path}")
    except Exception as e:
        print(f"Error embedding signature: {e}")


