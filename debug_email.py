# debug
# whats the MIME structure of .eml file, what parts exist? what get_body_text() is getting?

"""
Multipurpose Internet Mail Extensions - MIME
text/plain
text/html
multipart/mixed
application/pdf
application/zip
application/x-7z-compressed
"""


import sys
from email import policy
from email.parser import BytesParser


def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_email.py <email_file.eml>")
        sys.exit(1)

    filepath = sys.argv[1]
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    print("=" * 60)
    print(f"MIME STRUCTURE: {filepath}")
    print("=" * 60)
    print(f"Is multipart: {msg.is_multipart()}")
    print()

    if msg.is_multipart():
        for i, part in enumerate(msg.walk()):
            content_type = part.get_content_type()
            filename = part.get_filename()
            disposition = part.get_content_disposition()
            try:
                content = part.get_content()
                content_preview = str(content)[:200].replace("\n", " ")
            except Exception as e:
                content_preview = f"<could not decode: {e}>"

            print(f"[Part {i}]")
            print(f"  Content-Type:        {content_type}")
            print(f"  Content-Disposition: {disposition}")
            print(f"  Filename:            {filename}")
            print(f"  Content preview:     {content_preview}")
            print()
    else:
        content = msg.get_content()
        print("Single-part message content preview:")
        print(str(content)[:500])

    print("=" * 60)


if __name__ == "__main__":
    main()