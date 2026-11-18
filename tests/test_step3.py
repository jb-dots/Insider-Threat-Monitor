"""Test suite for Step 3: Registration, login, logout, and account suspension."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from db import (
    User,
    authenticate_user,
    check_password,
    get_session,
    init_db,
    register_user,
)

def run_tests():
    print("=" * 65)
    print("STEP 3 VERIFICATION: AUTHENTICATION & ACCESS CONTROL TEST SUITE")
    print("=" * 65)

    init_db()

    # 1. Test Registration
    print("\n[TEST 1] Registering a new user...")
    user, err = register_user("Alice Security", "alice@enterprise.com", "SecurePass123!")
    assert err is None, f"Expected successful registration, got: {err}"
    assert user is not None
    assert user["email"] == "alice@enterprise.com"
    assert user["is_super_admin"] is False, "Security violation: is_super_admin must be False!"
    print(f"  Success: Created user '{user['full_name']}' ({user['email']}) with ID: {user['user_id']}")
    print(f"  is_super_admin: {user['is_super_admin']}")

    # Verify bcrypt hashing in database
    with get_session() as s:
        db_user = s.query(User).filter_by(email="alice@enterprise.com").first()
        assert db_user is not None
        assert db_user.password_hash.startswith("$2b$") or db_user.password_hash.startswith("$2a$")
        assert check_password("SecurePass123!", db_user.password_hash)
        print(f"  Bcrypt Hash Verified: {db_user.password_hash[:25]}...")

    # 2. Test Duplicate Email Rejection
    print("\n[TEST 2] Rejecting duplicate email registration...")
    dup_user, dup_err = register_user("Alice Impostor", "alice@enterprise.com", "AnotherPass456!")
    assert dup_user is None
    assert dup_err == "An account with this email already exists."
    print(f"  Success: Correctly rejected duplicate email with message: '{dup_err}'")

    # 3. Test Short Password Rejection (< 8 chars)
    print("\n[TEST 3] Rejecting short password (< 8 chars)...")
    short_user, short_err = register_user("Bob Short", "bob@enterprise.com", "short")
    assert short_user is None
    assert "at least 8 characters" in short_err
    print(f"  Success: Correctly rejected short password with message: '{short_err}'")

    # 4. Test Login with Wrong Password
    print("\n[TEST 4] Logging in with wrong password...")
    wrong_user, wrong_err = authenticate_user("alice@enterprise.com", "WrongPassword!")
    assert wrong_user is None
    assert wrong_err == "Invalid email or password."
    print(f"  Success: Correctly rejected with message: '{wrong_err}'")

    # 5. Test Successful Login
    print("\n[TEST 5] Logging in with valid credentials...")
    login_user, login_err = authenticate_user("alice@enterprise.com", "SecurePass123!")
    assert login_err is None
    assert login_user is not None
    assert login_user["email"] == "alice@enterprise.com"
    print(f"  Success: Successfully authenticated '{login_user['full_name']}' ({login_user['email']})")

    # 6. Simulate Session Storage & Logout
    print("\n[TEST 6] Simulating Streamlit session state login and logout...")
    session_state = {}
    session_state["logged_in_user"] = login_user
    print(f"  Session Active: User '{session_state['logged_in_user']['email']}' stored in session_state.")
    # Logout
    session_state.clear()
    assert "logged_in_user" not in session_state
    print("  Session Cleared: User logged out successfully.")

    # 7. Test Blocked Login for Suspended User (manually set in database)
    print("\n[TEST 7] Creating suspended account and attempting login...")
    with get_session() as s:
        # Create user Charlie and set status to suspended
        charlie = s.query(User).filter_by(email="charlie@enterprise.com").first()
        if not charlie:
            charlie = User(
                user_id="usr_charlie_test",
                email="charlie@enterprise.com",
                password_hash=db_user.password_hash, # use valid hash
                full_name="Charlie Suspended",
                status="suspended", # Manually set to suspended
                is_super_admin=False,
            )
            s.add(charlie)
            s.commit()
        else:
            charlie.status = "suspended"
            s.commit()

    susp_user, susp_err = authenticate_user("charlie@enterprise.com", "SecurePass123!")
    assert susp_user is None
    expected_msg = "Your account has been suspended. Contact the administrator."
    assert susp_err == expected_msg, f"Expected '{expected_msg}', got '{susp_err}'"
    print(f"  Success: Blocked suspended user login with message: '{susp_err}'")

    # 8. Test Blocked Login for Banned User
    print("\n[TEST 8] Testing banned account status...")
    with get_session() as s:
        charlie = s.query(User).filter_by(email="charlie@enterprise.com").first()
        charlie.status = "banned"
        s.commit()

    banned_user, banned_err = authenticate_user("charlie@enterprise.com", "SecurePass123!")
    assert banned_user is None
    assert banned_err == expected_msg
    print(f"  Success: Blocked banned user login with message: '{banned_err}'")

    print("\n" + "=" * 65)
    print("ALL STEP 3 AUTHENTICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()

