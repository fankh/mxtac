from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class NotificationChannel(Base, TimestampMixin):
    """Notification channel configuration.

    Stores channel-specific settings as a JSON string in config_json.
    Schema per channel_type:
      email:   { smtp_host, smtp_port, from_address, to_addresses[], use_tls }
      slack:   { webhook_url, channel, username }
      webhook: { url, method, headers{}, auth_token }
      msteams: { webhook_url }
    """

    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    channel_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    # email | slack | webhook | msteams

    # Channel-specific configuration stored as a JSON string
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    min_severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="low", server_default="low"
    )
    # critical | high | medium | low

    def __repr__(self) -> str:
        return f"<NotificationChannel {self.id} name={self.name!r} type={self.channel_type}>"
