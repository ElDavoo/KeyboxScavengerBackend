from __future__ import annotations

import re
import textwrap
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class XmlNormalizationError(ValueError):
    pass


KEY_MATERIAL_TAGS = {"Certificate", "PrivateKey"}
PEM_LINE_WIDTH = 64
BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
PRIVATE_KEY_HEADER_ALGORITHMS = {
    "-----BEGIN EC PRIVATE KEY-----": "ecdsa",
    "-----BEGIN RSA PRIVATE KEY-----": "rsa",
}


def normalize_xml_payload(xml_payload: bytes) -> bytes:
    try:
        root = ET.fromstring(xml_payload)
    except ET.ParseError as exc:
        raise XmlNormalizationError(str(exc)) from exc

    _normalize_node(root)
    for key in root.iter("Key"):
        _normalize_key_algorithm(key)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _normalize_node(node: ET.Element) -> None:
    if node.attrib:
        ordered_attributes = {
            key: value
            for key, value in sorted(node.attrib.items())
            if key.lower() != "deviceid"
        }
        node.attrib.clear()
        node.attrib.update(ordered_attributes)

    if node.text is not None:
        node.text = _normalize_text(node.tag, node.text)

    for child in list(node):
        if child.tag is ET.Comment:
            node.remove(child)
            continue

        _normalize_node(child)

        if child.tail is not None:
            stripped_tail = child.tail.strip()
            child.tail = stripped_tail if stripped_tail else None


def _normalize_text(tag: str, text: str) -> str | None:
    if tag in KEY_MATERIAL_TAGS:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(_rewrap_pem_lines(lines)) if lines else None

    stripped_text = text.strip()
    return stripped_text if stripped_text else None


def _rewrap_pem_lines(lines: list[str]) -> list[str]:
    """Re-wrap a PEM body at 64 columns so line breaks cannot make copies look distinct."""
    if len(lines) < 3 or not (lines[0].startswith("-----BEGIN") and lines[-1].startswith("-----END")):
        return lines

    body = "".join(lines[1:-1])
    if not BASE64_BODY_RE.match(body):
        # Leave malformed bodies alone; the validator's PEM sanitizer deals with them.
        return lines

    return [lines[0], *textwrap.wrap(body, PEM_LINE_WIDTH), lines[-1]]


def _normalize_key_algorithm(key: ET.Element) -> None:
    """Derive the algorithm attribute from the key material, ignoring whatever label it carried."""
    algorithm = _algorithm_from_leaf_certificate(key) or _algorithm_from_private_key(key)
    if algorithm is not None:
        key.set("algorithm", algorithm)


def _algorithm_from_leaf_certificate(key: ET.Element) -> str | None:
    certificate = key.find(".//Certificate")
    if certificate is None or not certificate.text:
        return None

    try:
        public_key = x509.load_pem_x509_certificate(certificate.text.encode()).public_key()
    except ValueError:
        return None

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecdsa"
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa"
    return None


def _algorithm_from_private_key(key: ET.Element) -> str | None:
    private_key = key.find("PrivateKey")
    if private_key is None or not private_key.text:
        return None

    return PRIVATE_KEY_HEADER_ALGORITHMS.get(private_key.text.splitlines()[0])
