"""Transaction management utilities."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.exceptions import ValidationError

logger = logging.getLogger(__name__)


class TransactionManager:
    """Context manager for database transactions with automatic rollback."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._in_transaction = False

    async def __aenter__(self):
        """Start transaction context."""
        # Always manage the transaction to ensure commit
        self._in_transaction = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit transaction context with commit or rollback."""
        if not self._in_transaction:
            # Not our transaction to manage
            return False

        try:
            if exc_type is None:
                # No exception, commit
                await self.db.commit()
                logger.debug("Transaction committed successfully")
            else:
                # Exception occurred, rollback
                await self.db.rollback()
                logger.warning(f"Transaction rolled back due to {exc_type.__name__}: {exc_val}")
        except Exception as e:
            logger.error(f"Error during transaction cleanup: {e}")
            try:
                await self.db.rollback()
            except Exception:
                logger.error("Failed to rollback transaction during cleanup")

        return False  # Don't suppress exceptions

    async def commit(self):
        """Manually commit transaction."""
        if self._in_transaction:
            await self.db.commit()
            logger.debug("Transaction manually committed")

    async def rollback(self):
        """Manually rollback transaction."""
        if self._in_transaction:
            await self.db.rollback()
            logger.debug("Transaction manually rolled back")


@asynccontextmanager
async def transaction_scope(db: AsyncSession) -> AsyncGenerator[TransactionManager, None]:
    """
    Async context manager for database transactions.

    Usage:
        async with transaction_scope(db) as tx:
            # Do database operations
            user = await user_service.create_user(...)
            # Automatic commit on success, rollback on exception
    """
    tx_manager = TransactionManager(db)
    async with tx_manager:
        yield tx_manager


@asynccontextmanager
async def atomic_operation(db: AsyncSession) -> AsyncGenerator[AsyncSession, None]:
    """
    Simple atomic operation context manager.

    Usage:
        async with atomic_operation(db) as session:
            # Operations are automatically committed or rolled back
            user = User(...)
            session.add(user)
    """
    async with transaction_scope(db):
        yield db


class BatchTransactionManager:
    """Manager for batch operations with transaction batching."""

    def __init__(self, db: AsyncSession, batch_size: int = 100):
        self.db = db
        self.batch_size = batch_size
        self.operations_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None and self.operations_count > 0:
            await self.db.commit()
        else:
            await self.db.rollback()
        return False

    async def add_operation(self, operation_func, *args, **kwargs):
        """Add an operation to the batch."""
        try:
            await operation_func(*args, **kwargs)
            self.operations_count += 1

            # Commit batch if we hit the batch size
            if self.operations_count >= self.batch_size:
                await self.db.commit()
                self.operations_count = 0
                logger.debug(f"Batch committed at {self.batch_size} operations")

        except Exception as e:
            await self.db.rollback()
            self.operations_count = 0
            logger.error(f"Batch operation failed: {e}")
            raise


@asynccontextmanager
async def batch_operations(
    db: AsyncSession, batch_size: int = 100
) -> AsyncGenerator[BatchTransactionManager, None]:
    """
    Context manager for batch operations.

    Usage:
        async with batch_operations(db, batch_size=50) as batch:
            for data in large_dataset:
                await batch.add_operation(create_user, data)
    """
    batch_manager = BatchTransactionManager(db, batch_size)
    async with batch_manager:
        yield batch_manager


def validate_transaction_state(db: AsyncSession, required_state: bool = True):
    """
    Validate that the database is in the expected transaction state.

    Args:
        db: Database session
        required_state: True if transaction is required, False if not

    Raises:
        ValidationError: If transaction state doesn't match requirement
    """
    in_transaction = db.in_transaction()

    if required_state and not in_transaction:
        raise ValidationError("Operation requires an active transaction")
    elif not required_state and in_transaction:
        raise ValidationError("Operation cannot be performed within a transaction")


# Decorator for functions that require transactions
def requires_transaction(func):
    """Decorator to ensure function runs within a transaction."""
    import functools

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Find db session in arguments
        db = None
        for arg in args:
            if isinstance(arg, AsyncSession):
                db = arg
                break

        if not db:
            # Look in kwargs
            for value in kwargs.values():
                if isinstance(value, AsyncSession):
                    db = value
                    break

        if not db:
            raise ValidationError("No database session found in function arguments")

        validate_transaction_state(db, required_state=True)
        return await func(*args, **kwargs)

    return wrapper


# Decorator for functions that must not run in transactions
def requires_no_transaction(func):
    """Decorator to ensure function runs outside of a transaction."""
    import functools

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Find db session in arguments
        db = None
        for arg in args:
            if isinstance(arg, AsyncSession):
                db = arg
                break

        if not db:
            # Look in kwargs
            for value in kwargs.values():
                if isinstance(value, AsyncSession):
                    db = value
                    break

        if not db:
            raise ValidationError("No database session found in function arguments")

        validate_transaction_state(db, required_state=False)
        return await func(*args, **kwargs)

    return wrapper
