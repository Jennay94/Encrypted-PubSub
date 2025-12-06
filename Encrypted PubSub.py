# encrypted_pubsub_chat.py
# Exercise 7: Encrypted PubSub chat in Flet
# Author: Jenifer Molnár
#
# Chat app where:
# - each user enters a passphrase (used as encryption key)
# - users select a topic from a dropdown
# - messages are encrypted before sending
# - only users with the correct passphrase can decrypt them
#
# Multiple app instances can be opened to simulate multiple users.

import flet as ft
import hashlib
import base64
import json
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken


# --- Helpers for encryption / decryption -------------------------------------


def derive_key(passphrase: str) -> bytes:
    """
    Derive a 32-byte key from the passphrase using SHA-256.
    The result is converted to urlsafe base64 so Fernet can use it.
    """
    # Basic key derivation (not for real production use, but OK for exercise)
    sha = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(sha)


def encrypt_message(passphrase: str, plaintext: str) -> str:
    """
    Encrypt the message text using the passphrase.
    Returns base64-encoded ciphertext (string).
    """
    key = derive_key(passphrase)
    f = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_message(passphrase: str, ciphertext: str) -> str | None:
    """
    Try to decrypt ciphertext with the given passphrase.
    Returns the plaintext if successful, None if the passphrase is wrong.
    """
    try:
        key = derive_key(passphrase)
        f = Fernet(key)
        plain = f.decrypt(ciphertext.encode("utf-8"))
        return plain.decode("utf-8")
    except (InvalidToken, ValueError):
        # Wrong passphrase or invalid data
        return None


# --- Main Flet app -----------------------------------------------------------


def main(page: ft.Page):
    page.title = "Encrypted PubSub Chat"
    page.vertical_alignment = "stretch"
    page.horizontal_alignment = "stretch"
    page.padding = 20

    # --- UI controls ---------------------------------------------------------

    # User name so we can see who sent the message
    name_field = ft.TextField(label="Your name", width=200, value="User")

    # Passphrase used to encrypt/decrypt messages
    passphrase_field = ft.TextField(
        label="Passphrase",
        password=True,
        can_reveal_password=True,
        width=220,
        hint_text="Enter shared secret",
    )

    # Topic selection for publish/subscribe
    topic_dropdown = ft.Dropdown(
        label="Topic",
        width=200,
        options=[
            ft.dropdown.Option("general"),
            ft.dropdown.Option("school"),
            ft.dropdown.Option("random"),
        ],
        value="general",
    )

    # Chat history – messages will be appended here
    messages_list = ft.ListView(
        expand=True,
        spacing=5,
        auto_scroll=True,
    )

    # Message input and send button
    message_input = ft.TextField(
        label="Message",
        expand=True,
        hint_text="Type your message here...",
    )
    send_button = ft.ElevatedButton("Send", icon=ft.Icons.SEND)

    # Status bar for small info messages
    status_text = ft.Text("", size=12, italic=True)

    # --- PubSub handler ------------------------------------------------------

    def handle_pubsub_message(msg: dict):
        """
        Called when a message is received via page.pubsub.
        'msg' is expected to be a dict with keys: topic, sender, ciphertext, timestamp.
        """
        # Ignore if topic does not match the selected one
        selected_topic = topic_dropdown.value
        if msg.get("topic") != selected_topic:
            return

        sender = msg.get("sender", "Unknown")
        timestamp = msg.get("timestamp", "")

        ciphertext = msg.get("ciphertext", "")
        passphrase = passphrase_field.value or ""

        # Try to decrypt with the current passphrase
        if passphrase.strip():
            plaintext = decrypt_message(passphrase, ciphertext)
        else:
            plaintext = None

        if plaintext is None:
            display_text = f"[{timestamp}] {sender}: <cannot decrypt - wrong passphrase?>"
        else:
            display_text = f"[{timestamp}] {sender}: {plaintext}"

        messages_list.controls.append(ft.Text(display_text))
        page.update()

    # Subscribe to PubSub channel (shared for all sessions)
    page.pubsub.subscribe(handle_pubsub_message)

    # --- Sending messages ----------------------------------------------------

    def send_message(e):
        """Encrypt message and broadcast it via PubSub."""
        sender_name = name_field.value.strip() or "User"
        topic = topic_dropdown.value
        passphrase = passphrase_field.value.strip()
        text = message_input.value.strip()

        if not text:
            status_text.value = "Please enter a message."
            page.update()
            return

        if not passphrase:
            status_text.value = "Please enter a passphrase before sending."
            page.update()
            return

        # Encrypt the message using the shared passphrase
        try:
            ciphertext = encrypt_message(passphrase, text)
        except Exception as ex:
            status_text.value = f"Encryption failed: {ex}"
            page.update()
            return

        # Prepare payload for PubSub – send encrypted text only
        payload = {
            "topic": topic,
            "sender": sender_name,
            "ciphertext": ciphertext,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }

        # Broadcast to all connected sessions
        page.pubsub.send_all(payload)

        # Clear input after sending
        message_input.value = ""
        status_text.value = ""
        page.update()

    send_button.on_click = send_message

    # Also send when user presses Enter in message field
    message_input.on_submit = send_message

    # --- Layout --------------------------------------------------------------

    page.add(
        ft.Column(
            [
                ft.Text("Encrypted PubSub Chat", size=24, weight="bold"),
                ft.Row(
                    [
                        name_field,
                        passphrase_field,
                        topic_dropdown,
                    ],
                    wrap=True,
                    spacing=10,
                ),
                ft.Container(
                    content=messages_list,
                    border=ft.border.all(1, ft.Colors.GREY),

                    border_radius=5,
                    padding=10,
                    expand=True,
                ),
                ft.Row(
                    [
                        message_input,
                        send_button,
                    ],
                    spacing=10,
                ),
                status_text,
            ],
            expand=True,
        )
    )


if __name__ == "__main__":
    # Run as a normal Flet app
    ft.app(target=main)
