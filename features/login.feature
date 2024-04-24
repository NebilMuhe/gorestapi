Feature: login user

    Scenario: validate the input
        Given User is on login page
        When User enters "<Username>" and "<Password>"
        Then The system sholud return an error "<ErrorMessage>"
        Examples:
        | Username   | Password              | ErrorMessage                                        |
        |            | 12QWas@#              | username required.                                  |
        | Matheo     |                       | password required.                                  |
        | 123455     | 12QWas@#              | username must be valid.                             |
        | dave       | 12QWas@#              | Username length must be atleast 5 characters.       |
        | david      | 12QWas                | Password length must be atleast 8 characters long.  |
        | david      | 12345678              | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | david      | 1234ABCD              | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | david      | 12ABCDab              | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | david1     | 12ABCD%$              | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
    
    Scenario: login request with invalid username
        Given User is on login page
        When I send "POST" request to url "/api/login" with payload:
        """
        {
            "username": "abebe1",
            "password": "12ABCD%$ab"
        }   
        """
        Then the response code should be 404 and error "not found"

    Scenario: login request with invalid password
        Given User is on login page
        When I send "POST" request to url "/api/login" with payload:
        """
        {
            "username": "abebe",
            "password": "12ABCD%$ab12"
        }   
        """
        Then the response code should be 400 and error "invalid password"

    Scenario: login request with valid username and password
        Given User is on login page
        When I send "POST" request to url "/api/login" with payload:
        """
        {
            "username": "abebe",
            "password": "12ABCD%$ab"
        }   
        """
        Then the response code should be 200 and issue JWT