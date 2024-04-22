Feature: register user
  As a user,
  I want to register with valid credentials,
  So that I can access the system

  Scenario: Duplicate Username
    Given a user with the username "testuser" is already registered,
    When I attempt to register with the same username,
    Then the system should return an error message indicating that the username already exists.
  



