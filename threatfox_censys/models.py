from sqlalchemy import Boolean, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class IoC(Base):
    __tablename__ = "ioc"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc: Mapped[str] = mapped_column(String, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String, nullable=False)
    threat_type: Mapped[str] = mapped_column(String, nullable=False)
    submitted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    def __repr__(self):
        return (
            f"<IoC(ioc={self.ioc}, ioc_type={self.ioc_type},"
            f" submitted={self.submitted})>"
        )
