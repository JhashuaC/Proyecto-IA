"""Parser de archivos .eml usando la libreria estandar."""

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
import re

from phishing_detector.domain.entities import AttachmentInfo, EmailAnalysisRequest


class HtmlLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.display_links = []
        self.forms = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag.lower() == "form":
            self.forms += 1

    def handle_data(self, data):
        self.display_links.extend(re.findall(r"https?://[^\s<>\"]+", data or ""))


def _payload_to_text(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")


def parse_eml(raw_bytes, source_name="correo.eml"):
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    plain_parts = []
    html_parts = []
    attachments = []

    for part in message.walk():
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(AttachmentInfo(
                filename=filename or "adjunto_sin_nombre",
                content_type=content_type,
                size=len(payload),
            ))
            continue
        if content_type == "text/plain":
            plain_parts.append(_payload_to_text(part))
        elif content_type == "text/html":
            html_parts.append(_payload_to_text(part))

    html_text = "\n".join(html_parts)
    parser = HtmlLinkParser()
    parser.feed(html_text)
    body = "\n".join(plain_parts).strip() or re.sub(r"<[^>]+>", " ", html_text)
    body = re.sub(r"\s+", " ", body).strip()
    inline_links = re.findall(r"https?://[^\s<>\"]+", body + " " + html_text)
    links = list(dict.fromkeys(parser.links + parser.display_links + inline_links))

    headers = {key.lower(): str(value) for key, value in message.items()}
    sender = parseaddr(str(message.get("From", "")))[1] or str(message.get("From", ""))
    reply_to = parseaddr(str(message.get("Reply-To", "")))[1] or str(message.get("Reply-To", ""))
    return_path = parseaddr(str(message.get("Return-Path", "")))[1] or str(message.get("Return-Path", ""))
    auth_results = str(message.get("Authentication-Results", ""))

    return EmailAnalysisRequest(
        subject=str(message.get("Subject", "")),
        body=body,
        url=links[0] if links else "",
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        authentication_results=auth_results,
        headers=headers,
        links=links,
        attachments=attachments,
        source_name=source_name,
    )

