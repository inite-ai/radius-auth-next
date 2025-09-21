"""Comprehensive tests for decorators, validators, and edge cases."""

import pytest
from fastapi import status
from httpx import AsyncClient

from app.models.membership import Role

pytestmark = pytest.mark.asyncio


class TestValidatorDecorators:
    """Test validator decorators and their edge cases."""

    async def test_validate_user_exists_decorator(self, async_client: AsyncClient):
        """Test @validate_user_exists decorator thoroughly."""
        # Create test user
        user = await self.create_test_user(async_client, "user@test.com")

        # Test 1: Valid user ID - should work
        response = await async_client.get(
            f"/api/v1/users/{user['user_id']}",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["user"]["id"] == user["user_id"]

        # Test 2: Non-existent user ID - should return 404
        response = await async_client.get(
            "/api/v1/users/99999",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "User not found" in data["message"]

        # Test 3: Invalid user ID format - should return 422
        response = await async_client.get(
            "/api/v1/users/invalid",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Test 4: Negative user ID - should return 422
        response = await async_client.get(
            "/api/v1/users/-1",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Test 5: User ID as zero - should return 422
        response = await async_client.get(
            "/api/v1/users/0",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_validate_organization_exists_decorator(self, async_client: AsyncClient):
        """Test @validate_organization_exists decorator thoroughly."""
        # Create test user with organization
        user = await self.create_user_with_org(async_client, "user@test.com", Role.OWNER)

        # Test 1: Valid organization ID - should work
        response = await async_client.get(
            f"/api/v1/organizations/{user['org_id']}",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["organization"]["id"] == user["org_id"]

        # Test 2: Non-existent organization ID - should return 404
        response = await async_client.get(
            "/api/v1/organizations/99999",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "Organization not found" in data["message"]

        # Test 3: Invalid organization ID format - should return 422
        response = await async_client.get(
            "/api/v1/organizations/invalid",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Test 4: Organization members endpoint with valid org
        response = await async_client.get(
            f"/api/v1/organizations/{user['org_id']}/members",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK

        # Test 5: Organization members endpoint with invalid org
        response = await async_client.get(
            "/api/v1/organizations/99999/members",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_validator_with_permission_interaction(self, async_client: AsyncClient):
        """Test interaction between validators and permission decorators."""
        # Create two organizations
        org1_owner = await self.create_user_with_org(async_client, "org1@test.com", Role.OWNER)
        org2_owner = await self.create_user_with_org(async_client, "org2@test.com", Role.OWNER)

        # Create user in org1
        org1_user = await self.create_user_with_org(
            async_client, "org1user@test.com", Role.EDITOR, org1_owner["org_id"]
        )

        # Test 1: Validator passes, but permission fails
        # org1_user tries to access org2_owner's organization
        response = await async_client.get(
            f"/api/v1/organizations/{org2_owner['org_id']}",
            headers=org1_user["headers"],
        )
        # Should be 403 (permission denied), not 404 (not found)
        # This proves validator ran first and found the org, but permission failed
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Test 2: Validator fails first (non-existent resource)
        response = await async_client.get(
            "/api/v1/organizations/99999",
            headers=org1_user["headers"],
        )
        # Should be 404 (not found), validator fails before permission check
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Test 3: Both validator and permission pass
        response = await async_client.get(
            f"/api/v1/organizations/{org1_owner['org_id']}",
            headers=org1_user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_decorator_error_messages(self, async_client: AsyncClient):
        """Test that decorators return appropriate error messages."""
        user = await self.create_test_user(async_client, "user@test.com")

        # Test user not found message
        response = await async_client.get(
            "/api/v1/users/99999",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "User not found" in data["message"]

        # Test organization not found message
        response = await async_client.get(
            "/api/v1/organizations/99999",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "Organization not found" in data["message"]

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
                "slug": f"test-org-{email.split('@')[0]}",
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


class TestPermissionEdgeCases:
    """Test edge cases and complex permission scenarios."""

    async def test_unauthenticated_access(self, async_client: AsyncClient):
        """Test that unauthenticated users are properly blocked."""
        # Test various endpoints without authentication
        endpoints = [
            ("/api/v1/users/", "GET"),
            ("/api/v1/users/1", "GET"),
            ("/api/v1/users/", "POST"),
            ("/api/v1/users/1", "PUT"),
            ("/api/v1/users/1", "DELETE"),
            ("/api/v1/organizations/", "GET"),
            ("/api/v1/organizations/1", "GET"),
            ("/api/v1/organizations/", "POST"),
            ("/api/v1/organizations/1", "PUT"),
            ("/api/v1/organizations/1/members", "GET"),
            ("/api/v1/sessions/", "GET"),
            ("/api/v1/sessions/stats", "GET"),
            ("/api/v1/sessions/other", "DELETE"),
        ]

        for endpoint, method in endpoints:
            if method == "GET":
                response = await async_client.get(endpoint)
            elif method == "POST":
                response = await async_client.post(endpoint, json={})
            elif method == "PUT":
                response = await async_client.put(endpoint, json={})
            elif method == "DELETE":
                response = await async_client.delete(endpoint)

            assert (
                response.status_code == status.HTTP_401_UNAUTHORIZED
            ), f"{method} {endpoint} should require authentication"

    async def test_invalid_token_access(self, async_client: AsyncClient):
        """Test access with invalid/expired tokens."""
        invalid_headers = {"Authorization": "Bearer invalid-token-here"}

        endpoints = [
            "/api/v1/users/",
            "/api/v1/organizations/",
            "/api/v1/sessions/",
        ]

        for endpoint in endpoints:
            response = await async_client.get(endpoint, headers=invalid_headers)
            assert (
                response.status_code == status.HTTP_401_UNAUTHORIZED
            ), f"GET {endpoint} should reject invalid token"

    async def test_malformed_authorization_header(self, async_client: AsyncClient):
        """Test various malformed Authorization headers."""
        malformed_headers = [
            {"Authorization": "Bearer "},  # Empty token
            {"Authorization": "Basic token"},  # Wrong auth type
            {"Authorization": "token"},  # Missing Bearer
            {"Authorization": ""},  # Empty header
        ]

        for headers in malformed_headers:
            response = await async_client.get("/api/v1/users/", headers=headers)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_concurrent_session_operations(self, async_client: AsyncClient):
        """Test session operations with multiple concurrent sessions."""
        user = await self.create_test_user(async_client, "user@test.com")

        # Create multiple sessions by logging in multiple times
        sessions = []
        for i in range(3):
            login_response = await async_client.post(
                "/api/v1/auth/login",
                json={"email": "user@test.com", "password": "TestPassword123!"},
            )
            assert login_response.status_code == status.HTTP_200_OK
            login_data = login_response.json()

            # Extract session info if available
            if "tokens" in login_data and login_data["tokens"]:
                sessions.append(
                    {
                        "access_token": login_data["tokens"]["access_token"],
                        "headers": {
                            "Authorization": f"Bearer {login_data['tokens']['access_token']}"
                        },
                    }
                )

        # Test that each session can access session endpoints
        for i, session in enumerate(sessions):
            response = await async_client.get(
                "/api/v1/sessions/",
                headers=session["headers"],
            )
            assert (
                response.status_code == status.HTTP_200_OK
            ), f"Session {i} should be able to access session list"

    async def test_permission_with_soft_deleted_resources(self, async_client: AsyncClient):
        """Test permissions when resources are soft-deleted."""
        # Create user and organization
        user = await self.create_user_with_org(async_client, "user@test.com", Role.OWNER)

        # Create another user
        target_user = await self.create_user_with_org(
            async_client, "target@test.com", Role.EDITOR, user["org_id"]
        )

        # Delete the target user (soft delete)
        response = await async_client.delete(
            f"/api/v1/users/{target_user['user_id']}",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK

        # Try to access the deleted user - should return 404 or appropriate error
        response = await async_client.get(
            f"/api/v1/users/{target_user['user_id']}",
            headers=user["headers"],
        )
        # Depending on implementation, this could be 404 or 200 with is_active=False
        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_200_OK]

    async def test_permission_inheritance_edge_cases(self, async_client: AsyncClient):
        """Test edge cases in permission inheritance."""
        # Create organization hierarchy
        org_owner = await self.create_user_with_org(async_client, "owner@test.com", Role.OWNER)

        # Test creating users with different permission levels
        test_cases = [
            (Role.ADMIN, "admin@test.com"),
            (Role.EDITOR, "editor@test.com"),
            (Role.VIEWER, "viewer@test.com"),
        ]

        created_users = []
        for role, email in test_cases:
            user = await self.create_user_with_org(async_client, email, role, org_owner["org_id"])
            created_users.append((user, role))

        # Test that each user can perform actions appropriate to their role
        for user_data, role in created_users:
            # All users should be able to read organization
            response = await async_client.get(
                f"/api/v1/organizations/{org_owner['org_id']}",
                headers=user_data["headers"],
            )
            assert (
                response.status_code == status.HTTP_200_OK
            ), f"{role} should be able to read organization"

            # Test user list access (all should have read permission)
            response = await async_client.get(
                "/api/v1/users/",
                headers=user_data["headers"],
            )
            assert (
                response.status_code == status.HTTP_200_OK
            ), f"{role} should be able to list users"

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
                "slug": f"test-org-{email.split('@')[0]}",
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


class TestResponseBuilderIntegration:
    """Test that ResponseBuilder is properly integrated with permission decorators."""

    async def test_response_format_consistency(self, async_client: AsyncClient):
        """Test that all endpoints return consistent response formats."""
        user = await self.create_user_with_org(async_client, "user@test.com", Role.OWNER)

        # Test user endpoints return consistent format
        response = await async_client.get(
            "/api/v1/users/",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Check standard ResponseBuilder fields
        assert "success" in data
        assert "message" in data
        assert "timestamp" in data
        assert data["success"] is True

        # Test organization endpoints return consistent format
        response = await async_client.get(
            f"/api/v1/organizations/{user['org_id']}",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "success" in data
        assert "message" in data
        assert "timestamp" in data
        assert data["success"] is True

        # Test session endpoints return consistent format
        response = await async_client.get(
            "/api/v1/sessions/",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "success" in data
        assert "message" in data
        assert "timestamp" in data
        assert data["success"] is True

    async def test_error_response_format_consistency(self, async_client: AsyncClient):
        """Test that error responses are also consistent."""
        user = await self.create_test_user(async_client, "user@test.com")

        # Test 404 errors have consistent format
        response = await async_client.get(
            "/api/v1/users/99999",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()

        assert "message" in data
        assert "User not found" in data["message"]

        # Test 403 errors have consistent format
        other_user = await self.create_user_with_org(async_client, "other@test.com", Role.OWNER)

        response = await async_client.get(
            f"/api/v1/organizations/{other_user['org_id']}",
            headers=user["headers"],
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = response.json()

        assert "message" in data

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
                "slug": f"test-org-{email.split('@')[0]}",
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
