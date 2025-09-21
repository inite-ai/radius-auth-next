"""Organization management service."""


from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.membership import Membership, Role
from app.models.organization import Organization
from app.models.user import User
from app.utils.exceptions import NotFoundError, ValidationError


class OrganizationService:
    """Service for organization management operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_organization(
        self,
        name: str,
        slug: str,
        user_id: int,
        description: str | None = None,
        website: str | None = None,
        email: str | None = None,
        phone: str | None = None,
    ) -> Organization:
        """Create a new organization and assign owner role to user."""
        from app.utils.transaction_manager import atomic_operation

        async with atomic_operation(self.db):
            # Check if slug is already taken
            result = await self.db.execute(select(Organization).where(Organization.slug == slug))
            existing_org = result.scalar_one_or_none()

            if existing_org:
                raise ValidationError("Organization slug already exists")

            # Create organization
            organization = Organization(
                name=name,
                slug=slug,
                description=description,
                is_personal=False,
                plan="free",
                website=website,
                email=email,
                phone=phone,
            )

            self.db.add(organization)
            await self.db.flush()  # Get the ID

            # Create owner membership for user
            membership = Membership(
                user_id=user_id,
                organization_id=organization.id,
                role=Role.OWNER,
                is_active=True,
            )

            self.db.add(membership)
            # atomic_operation handles commit/rollback

        return organization

    async def get_organization_by_id(self, organization_id: int) -> Organization | None:
        """Get organization by ID."""

        result = await self.db.execute(
            select(Organization).where(
                Organization.id == organization_id,
                Organization.is_active,
            )
        )
        return result.scalar_one_or_none()

    async def get_user_organizations(
        self,
        user_id: int,
        page: int = 1,
        per_page: int = 20,
    ) -> tuple[list[tuple[Organization, Membership]], int]:
        """Get organizations user has access to."""

        skip = (page - 1) * per_page

        result = await self.db.execute(
            select(Organization, Membership)
            .join(Membership, Organization.id == Membership.organization_id)
            .where(
                Membership.user_id == user_id,
                Membership.is_active,
                Organization.is_active,
            )
            .offset(skip)
            .limit(per_page)
        )

        org_memberships = result.all()

        # Count total
        count_result = await self.db.execute(
            select(Organization, Membership)
            .join(Membership, Organization.id == Membership.organization_id)
            .where(
                Membership.user_id == user_id,
                Membership.is_active,
                Organization.is_active,
            )
        )
        total = len(count_result.all())

        return org_memberships, total

    async def get_user_role_in_organization(
        self,
        user_id: int,
        organization_id: int,
    ) -> Role | None:
        """Get user's role in organization."""

        result = await self.db.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.organization_id == organization_id,
                Membership.is_active,
            )
        )
        membership = result.scalar_one_or_none()
        return membership.role if membership else None

    async def update_organization(
        self,
        organization_id: int,
        **update_data,
    ) -> Organization:
        """Update organization."""

        organization = await self.get_organization_by_id(organization_id)
        if not organization:
            raise NotFoundError("Organization not found")

        # Update fields
        for field, value in update_data.items():
            if hasattr(organization, field):
                setattr(organization, field, value)

        await self.db.commit()
        await self.db.refresh(organization)

        return organization

    async def deactivate_organization(self, organization_id: int) -> None:
        """Deactivate organization."""

        organization = await self.get_organization_by_id(organization_id)
        if not organization:
            raise NotFoundError("Organization not found")

        organization.is_active = False
        await self.db.commit()

    async def get_organization_members(
        self,
        organization_id: int,
        page: int = 1,
        per_page: int = 20,
    ) -> tuple[list[tuple[User, Membership]], int]:
        """Get organization members."""

        skip = (page - 1) * per_page

        result = await self.db.execute(
            select(User, Membership)
            .join(Membership, User.id == Membership.user_id)
            .where(
                Membership.organization_id == organization_id,
                Membership.is_active,
                User.is_active,
            )
            .offset(skip)
            .limit(per_page)
        )

        user_memberships = result.all()

        # Count total
        count_result = await self.db.execute(
            select(User, Membership)
            .join(Membership, User.id == Membership.user_id)
            .where(
                Membership.organization_id == organization_id,
                Membership.is_active,
                User.is_active,
            )
        )
        total = len(count_result.all())

        return user_memberships, total

    async def add_member(
        self,
        organization_id: int,
        user_id: int,
        role: Role,
    ) -> Membership:
        """Add member to organization."""

        # Check if membership already exists
        result = await self.db.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.organization_id == organization_id,
            )
        )
        existing_membership = result.scalar_one_or_none()

        if existing_membership:
            if existing_membership.is_active:
                raise ValidationError("User is already a member of this organization")
            else:
                # Reactivate membership
                existing_membership.is_active = True
                existing_membership.role = role
                await self.db.commit()
                return existing_membership

        # Create new membership
        membership = Membership(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
            is_active=True,
        )

        self.db.add(membership)
        await self.db.commit()
        await self.db.refresh(membership)

        return membership

    async def remove_member(
        self,
        organization_id: int,
        user_id: int,
    ) -> None:
        """Remove member from organization."""

        result = await self.db.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.organization_id == organization_id,
                Membership.is_active,
            )
        )
        membership = result.scalar_one_or_none()

        if not membership:
            raise NotFoundError("Membership not found")

        membership.is_active = False
        await self.db.commit()

    async def update_member_role(
        self,
        organization_id: int,
        user_id: int,
        new_role: Role,
    ) -> Membership:
        """Update member role in organization."""

        result = await self.db.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.organization_id == organization_id,
                Membership.is_active,
            )
        )
        membership = result.scalar_one_or_none()

        if not membership:
            raise NotFoundError("Membership not found")

        membership.role = new_role
        await self.db.commit()
        await self.db.refresh(membership)

        return membership

    async def get_organization_stats(self, organization_id: int) -> dict:
        """Get organization statistics."""

        # Count active members
        members_result = await self.db.execute(
            select(Membership).where(
                Membership.organization_id == organization_id,
                Membership.is_active,
            )
        )
        member_count = len(members_result.scalars().all())

        # Count by role
        role_counts = {}
        for role in Role:
            role_result = await self.db.execute(
                select(Membership).where(
                    Membership.organization_id == organization_id,
                    Membership.role == role,
                    Membership.is_active,
                )
            )
            role_counts[role.value] = len(role_result.scalars().all())

        return {
            "member_count": member_count,
            "role_distribution": role_counts,
        }
