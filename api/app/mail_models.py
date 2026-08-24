from typing import TypedDict

class AttachmentInfo(TypedDict):
    name: str
    type: str
    size: int

class MessageSummary(TypedDict):
    uid: int
    subject: str
    from_: str | None
    to: list[str]
    date: str | None
    seen: bool
    size: int

class ParsedMessage(TypedDict):
    summary: MessageSummary
    headers: dict[str, str]
    text_body: str | None
    html_body: str | None
    attachments: list[AttachmentInfo]
