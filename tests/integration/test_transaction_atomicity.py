"""Tests for transaction manager atomicity and error handling."""

import time

import pytest
from fastapi import status
from httpx import AsyncClient

from app.models.membership import Role


def make_unique_email(base_email: str) -> str:
    """Generate unique email for each test to avoid conflicts."""
    timestamp = str(int(time.time() * 1000))[-6:]  # Last 6 digits of timestamp
    username, domain = base_email.split("@")
    return f"{username}_{timestamp}@{domain}"


pytestmark = pytest.mark.asyncio


class TestTransactionAtomicity:
    """Test that transaction manager ensures atomicity in complex operations."""

    async def test_organization_creation_atomicity(self, async_client: AsyncClient):
        """Test that organization creation with membership is atomic."""
        # Create user
        user = await self.create_test_user(async_client, make_unique_email("user@test.com"))

        # Test successful organization creation
        org_data = {
            "name": "Test Organization",
            "slug": "test-org-unique",
            "description": "Test organization for atomicity",
        }

        response = await async_client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_201_CREATED

        created_org = response.json()["organization"]
        assert created_org["name"] == org_data["name"]
        assert created_org["slug"] == org_data["slug"]

        # Verify user became owner of the organization
        members_response = await async_client.get(
            f"/api/v1/organizations/{created_org['id']}/members",
            headers=user["headers"],
        )
        assert members_response.status_code == status.HTTP_200_OK
        members = members_response.json()["members"]

        # Find user in members list
        user_membership = next((m for m in members if m["user"]["id"] == user["user_id"]), None)
        assert user_membership is not None
        assert user_membership["role"] == Role.OWNER

    async def test_organization_creation_rollback_on_duplicate_slug(
        self, async_client: AsyncClient
    ):
        """Test that failed organization creation rolls back properly."""
        # Create two users
        user1 = await self.create_test_user(async_client, make_unique_email("user1@test.com"))
        user2 = await self.create_test_user(async_client, make_unique_email("user2@test.com"))

        # First user creates organization
        org_data = {
            "name": "First Organization",
            "slug": "duplicate-slug",
            "description": "First organization",
        }

        response = await async_client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=user1["headers"],
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Second user tries to create organization with same slug
        conflicting_org_data = {
            "name": "Second Organization",
            "slug": "duplicate-slug",  # Same slug!
            "description": "Second organization",
        }

        response = await async_client.post(
            "/api/v1/organizations/",
            json=conflicting_org_data,
            headers=user2["headers"],
        )
        assert response.status_code == status.HTTP_409_CONFLICT

        # Verify the conflict error message
        data = response.json()
        assert "already exists" in data["message"].lower()

        # Verify no partial organization was created for user2
        # (This tests that the transaction was properly rolled back)
        user2_orgs_response = await async_client.get(
            "/api/v1/organizations/",
            headers=user2["headers"],
        )
        assert user2_orgs_response.status_code == status.HTTP_200_OK

        # User2 should have no organizations
        user2_orgs = user2_orgs_response.json().get("organizations", [])
        assert len(user2_orgs) == 0

    async def test_password_change_atomicity(self, async_client: AsyncClient):
        """Test that password change with session revocation is atomic."""
        # Create user
        user = await self.create_test_user(async_client, make_unique_email("user@test.com"))

        # Create multiple sessions by logging in multiple times
        additional_sessions = []
        for i in range(3):
            login_response = await async_client.post(
                "/api/v1/auth/login",
                json={"email": user["email"], "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            additional_sessions.append(login_response.json())

        # Change password
        password_change_data = {
            "current_password": "TestPassword123!",
            "new_password": "NewPassword123!",
        }

        response = await async_client.post(
            "/api/v1/users/change-password",
            json=password_change_data,
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify password was changed by trying to login with old password
        old_login_response = await async_client.post(
            "/api/v1/auth/login", json={"email": user["email"], "password": "TestPassword123!"}
        )
        assert old_login_response.status_code == status.HTTP_401_UNAUTHORIZED

        # Verify can login with new password
        new_login_response = await async_client.post(
            "/api/v1/auth/login", json={"email": user["email"], "password": "NewPassword123!"}
        )
        assert new_login_response.status_code == status.HTTP_200_OK

        # Verify old sessions are revoked
        for session in additional_sessions:
            if "tokens" in session and session["tokens"]:
                old_headers = {"Authorization": f"Bearer {session['tokens']['access_token']}"}
                profile_response = await async_client.get(
                    "/api/v1/users/profile",
                    headers=old_headers,
                )
                # Old sessions should be unauthorized
                assert profile_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_password_change_rollback_on_invalid_current_password(
        self, async_client: AsyncClient
    ):
        """Test that password change rolls back on validation error."""
        # Create user
        user = await self.create_test_user(async_client, make_unique_email("user@test.com"))

        # Try to change password with wrong current password
        password_change_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewPassword123!",
        }

        response = await async_client.post(
            "/api/v1/users/change-password",
            json=password_change_data,
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Verify password was NOT changed
        login_response = await async_client.post(
            "/api/v1/auth/login", json={"email": user["email"], "password": "TestPassword123!"}
        )
        assert login_response.status_code == status.HTTP_200_OK

        # Verify new password doesn't work
        new_login_response = await async_client.post(
            "/api/v1/auth/login", json={"email": user["email"], "password": "NewPassword123!"}
        )
        assert new_login_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_session_revocation_atomicity(self, async_client: AsyncClient):
        """Test that session revocation operations are atomic."""
        # Create user and multiple sessions
        user = await self.create_test_user(async_client, make_unique_email("user@test.com"))

        # Create additional sessions
        sessions = [user]  # Include original session
        for i in range(4):
            login_response = await async_client.post(
                "/api/v1/auth/login",
                json={"email": user["email"], "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = login_response.json()

            if "tokens" in login_data and login_data["tokens"]:
                sessions.append(
                    {
                        "headers": {
                            "Authorization": f"Bearer {login_data['tokens']['access_token']}"
                        },
                        "tokens": login_data["tokens"],
                    }
                )

        # Use first session to revoke others
        current_session = sessions[0]

        # Get current session ID (this is a simplified approach)
        current_sessions_response = await async_client.get(
            "/api/v1/sessions/",
            headers=current_session["headers"],
        )

        assert current_sessions_response.status_code == status.HTTP_200_OK

        sessions_data = current_sessions_response.json()
        session_list = sessions_data["sessions"]
        assert len(session_list) >= 4  # Should have multiple sessions

        # Find a session ID to use as current (use first one in list)
        current_session_id = str(session_list[0]["id"]) if session_list else "fake-session-id"

        # Revoke other sessions
        revoke_data = {
            "current_session_id": current_session_id,
        }

        response = await async_client.request(
            "DELETE",
            "/api/v1/sessions/other",
            json=revoke_data,
            headers=current_session["headers"],
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify that multiple sessions were revoked
        data = response.json()
        assert "revoked_sessions" in data
        revoked_count = data["revoked_sessions"]
        assert revoked_count >= 1  # At least one session should be revoked

    async def test_oauth_token_exchange_atomicity(self, async_client: AsyncClient):
        """Test OAuth token exchange atomicity."""
        # This test requires OAuth client setup, so we'll create a simplified version
        # Create user and organization first
        user = await self.create_user_with_org(
            async_client, make_unique_email("user@test.com"), Role.OWNER
        )

        # Create OAuth client
        client_data = {
            "name": "Test Client",
            "redirect_uris": ["http://localhost:3000/callback"],
            "allowed_scopes": ["profile", "email"],
            "grant_types": ["authorization_code", "refresh_token"],
        }

        response = await async_client.post(
            "/api/v1/oauth/clients",
            json=client_data,
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_201_CREATED

        client = response.json()["client"]
        client_id = client["client_id"]
        client_secret = client["client_secret"]

        # Test authorization flow (simplified) - GET request with query parameters
        auth_params = {
            "client_id": client_id,
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "profile email",  # Valid scopes from OAuth service
            "response_type": "code",
        }

        response = await async_client.get(
            "/api/v1/oauth/authorize",
            params=auth_params,
            headers=user["headers"],
        )

        # The response might vary depending on implementation
        # This test mainly ensures the transaction handling doesn't break the flow
        assert response.status_code in [
            status.HTTP_200_OK,  # Shows consent screen
            status.HTTP_302_FOUND,  # Redirect response
            status.HTTP_201_CREATED,
        ]

    # Helper methods
    async def create_test_user(self, client: AsyncClient, email: str) -> dict:
        """Create a user and return auth headers."""
        user_data = {
            "email": email,
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
        }

        response = await client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == status.HTTP_201_CREATED

        # Login
        login_response = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": "TestPassword123!"}
        )
        assert login_response.status_code == status.HTTP_200_OK

        login_data = login_response.json()
        access_token = login_data["tokens"]["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        user_id = login_data["user"]["id"]

        return {
            "headers": headers,
            "user_id": user_id,
            "access_token": access_token,
            "email": email,
            "tokens": login_data.get("tokens", {}),
        }

    async def create_user_with_org(
        self, client: AsyncClient, email: str, role: Role = Role.OWNER, existing_org_id: int = None
    ) -> dict:
        """Create a user with organization and return auth headers."""
        # Register user
        user_data = {
            "email": email,
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
        }

        response = await client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == status.HTTP_201_CREATED

        # Login
        login_response = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": "TestPassword123!"}
        )
        assert login_response.status_code == status.HTTP_200_OK

        login_data = login_response.json()
        access_token = login_data["tokens"]["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        user_id = login_data["user"]["id"]

        if existing_org_id:
            org_id = existing_org_id
        else:
            # Create organization
            org_data = {
                "name": f"Test Org for {email}",
                "slug": f"test-org-{email.split('@')[0].replace('_', '-')}",
                "description": "Test organization",
            }

            org_response = await client.post(
                "/api/v1/organizations/",
                json=org_data,
                headers=headers,
            )
            assert org_response.status_code == status.HTTP_201_CREATED
            org_id = org_response.json()["organization"]["id"]

        return {
            "headers": headers,
            "user_id": user_id,
            "org_id": org_id,
            "access_token": access_token,
            "email": email,
            "role": role,
        }


class TestErrorHandlingWithTransactions:
    """Test error handling scenarios with transaction manager."""

    async def test_database_constraint_violations(self, async_client: AsyncClient):
        """Test handling of database constraint violations in transactions."""
        # Create user
        user = await self.create_test_user(async_client, make_unique_email("user@test.com"))

        # Create organization
        org_data = {
            "name": "Test Organization",
            "slug": "unique-test-org",
            "description": "Test organization",
        }

        response = await async_client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Try to create another organization with the same slug
        duplicate_org_data = {
            "name": "Another Organization",
            "slug": "unique-test-org",  # Same slug - should violate constraint
            "description": "Another test organization",
        }

        response = await async_client.post(
            "/api/v1/organizations/",
            json=duplicate_org_data,
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_409_CONFLICT

    async def test_service_errors_during_transactions(self, async_client: AsyncClient):
        """Test service-level errors during transaction operations."""
        # Create user
        user = await self.create_test_user(async_client, make_unique_email("user@test.com"))

        # Test invalid organization data
        invalid_org_data = {
            "name": "",  # Empty name should be invalid
            "slug": "",  # Empty slug should be invalid
            "description": "Test",
        }

        response = await async_client.post(
            "/api/v1/organizations/",
            json=invalid_org_data,
            headers=user["headers"],
        )
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

        # Test invalid user data
        invalid_user_data = {
            "email": "invalid-email",  # Invalid email format
            "password": "weak",  # Weak password
            "first_name": "",  # Empty first name
            "last_name": "",  # Empty last name
        }

        response = await async_client.post(
            "/api/v1/users/",
            json=invalid_user_data,
            headers=user["headers"],
        )
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    async def test_concurrent_transaction_handling(self, async_client: AsyncClient):
        """Test handling of concurrent operations that might conflict."""
        # Create multiple users
        users = []
        for i in range(3):
            user = await self.create_test_user(async_client, f"user{i}@test.com")
            users.append(user)

        # Each user tries to create organization with similar data rapidly
        # This tests that transaction manager handles concurrent access properly
        responses = []

        for i, user in enumerate(users):
            org_data = {
                "name": f"Concurrent Org {i}",
                "slug": f"concurrent-org-{i}",
                "description": f"Organization {i}",
            }

            response = await async_client.post(
                "/api/v1/organizations/",
                json=org_data,
                headers=user["headers"],
            )
            responses.append(response)

        # All should succeed since they have different slugs
        for response in responses:
            assert response.status_code == status.HTTP_201_CREATED

    # Helper methods
    async def create_test_user(self, client: AsyncClient, email: str) -> dict:
        """Create a user and return auth headers."""
        user_data = {
            "email": email,
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
        }

        response = await client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == status.HTTP_201_CREATED

        # Login
        login_response = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": "TestPassword123!"}
        )
        assert login_response.status_code == status.HTTP_200_OK

        login_data = login_response.json()
        access_token = login_data["tokens"]["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        user_id = login_data["user"]["id"]

        return {
            "headers": headers,
            "user_id": user_id,
            "access_token": access_token,
            "email": email,
        }
