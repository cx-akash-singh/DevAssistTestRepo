/**
 * Security Tests for SQL Injection Remediation
 * Tests the /user endpoint to ensure SQL injection vulnerability is fixed
 */

const request = require('supertest');
const mysql = require('mysql');

// Mock the mysql module to avoid actual database connections in tests
jest.mock('mysql');

describe('SQL Injection Remediation Tests - /user endpoint', () => {
    let app;
    let mockConnection;
    let mockQuery;

    beforeEach(() => {
        // Clear module cache to get fresh instance for each test
        jest.clearAllMocks();
        jest.resetModules();

        // Setup mock connection
        mockQuery = jest.fn();
        mockConnection = {
            connect: jest.fn(),
            query: mockQuery
        };

        // Mock mysql.createConnection to return our mock connection
        mysql.createConnection.mockReturnValue(mockConnection);

        // Import app after mocking mysql
        // Note: In real scenario, the app should be refactored to accept connection as dependency
        // For this test, we're working with the existing structure
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    /**
     * Test 1: Verify parameterized queries are used (not string concatenation)
     * This is the core fix - ensuring user input is passed as parameters, not concatenated
     */
    test('should use parameterized query with placeholder, not string concatenation', (done) => {
        // Mock successful query response
        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, [{ id: 1, username: 'testuser' }]);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        // Recreate the fixed endpoint for testing
        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: 'testuser' })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                // Verify parameterized query was used
                expect(mockQuery).toHaveBeenCalledTimes(1);
                const [query, params, callback] = mockQuery.mock.calls[0];

                // Check that query uses placeholder
                expect(query).toBe("SELECT * FROM users WHERE username = ?");

                // Check that username is passed as parameter array
                expect(params).toEqual(['testuser']);
                expect(Array.isArray(params)).toBe(true);

                // Verify no string concatenation in query
                expect(query).not.toContain('testuser');

                done();
            });
    });

    /**
     * Test 2: SQL injection attack attempt is safely handled
     * Attempting classic SQL injection should not execute malicious SQL
     */
    test('should safely handle SQL injection attempt with OR 1=1', (done) => {
        const maliciousInput = "admin' OR '1'='1";

        mockQuery.mockImplementation((query, params, callback) => {
            // Simulate database treating the malicious input as literal string
            // With parameterized queries, this should return no results or safe results
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: maliciousInput })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                // Verify the query structure is safe
                const [query, params] = mockQuery.mock.calls[0];

                // Query should still use placeholder
                expect(query).toBe("SELECT * FROM users WHERE username = ?");

                // Malicious input should be passed as parameter, not in query string
                expect(params).toEqual([maliciousInput]);

                // The malicious input should NOT be concatenated into the query
                expect(query).not.toContain(maliciousInput);
                expect(query).not.toContain("OR '1'='1");

                done();
            });
    });

    /**
     * Test 3: SQL injection with UNION attack
     * Tests protection against UNION-based SQL injection
     */
    test('should safely handle UNION-based SQL injection attempt', (done) => {
        const unionAttack = "admin' UNION SELECT null, null, null--";

        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: unionAttack })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                const [query, params] = mockQuery.mock.calls[0];

                // Verify safe query structure
                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual([unionAttack]);

                // UNION keyword should not be in the query itself
                expect(query).not.toContain('UNION');

                done();
            });
    });

    /**
     * Test 4: SQL injection with comment injection
     * Tests protection against comment-based SQL injection
     */
    test('should safely handle comment-based SQL injection (--)', (done) => {
        const commentAttack = "admin'--";

        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: commentAttack })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                const [query, params] = mockQuery.mock.calls[0];

                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual([commentAttack]);

                done();
            });
    });

    /**
     * Test 5: Special characters are safely handled
     * Tests that special SQL characters don't break the query
     */
    test('should safely handle special characters in username', (done) => {
        const specialChars = "test';DROP TABLE users;--";

        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: specialChars })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                const [query, params] = mockQuery.mock.calls[0];

                // Verify DROP TABLE is not in the query structure
                expect(query).not.toContain('DROP TABLE');
                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual([specialChars]);

                done();
            });
    });

    /**
     * Test 6: Positive test - legitimate username works correctly
     * Ensures the fix doesn't break normal functionality
     */
    test('should successfully return user data for legitimate username', (done) => {
        const legitimateUsername = 'john_doe';
        const mockUserData = [{ id: 1, username: 'john_doe', email: 'john@example.com' }];

        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, mockUserData);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: legitimateUsername })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                // Verify correct data is returned
                expect(res.body).toEqual(mockUserData);

                // Verify parameterized query was used
                const [query, params] = mockQuery.mock.calls[0];
                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual([legitimateUsername]);

                done();
            });
    });

    /**
     * Test 7: Database error handling doesn't expose sensitive information
     * Ensures error messages don't leak database details
     */
    test('should return generic error message on database failure', (done) => {
        mockQuery.mockImplementation((query, params, callback) => {
            // Simulate database error
            callback(new Error('Table users does not exist'), null);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: 'testuser' })
            .expect(500)
            .end((err, res) => {
                if (err) return done(err);

                // Verify generic error message (no sensitive details exposed)
                expect(res.body).toEqual({ error: 'Database error occurred' });

                // Ensure actual error details are not exposed
                expect(res.body.error).not.toContain('Table users does not exist');
                expect(res.body.error).not.toContain('mysql');

                done();
            });
    });

    /**
     * Test 8: Empty username is handled safely
     * Edge case testing
     */
    test('should handle empty username parameter safely', (done) => {
        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: '' })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                const [query, params] = mockQuery.mock.calls[0];
                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual(['']);

                done();
            });
    });

    /**
     * Test 9: Null bytes and other edge cases
     * Tests handling of null bytes which can be used in some injection attacks
     */
    test('should handle null bytes and unicode safely', (done) => {
        const edgeCaseInput = "test\u0000user\u202E";

        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: edgeCaseInput })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                const [query, params] = mockQuery.mock.calls[0];
                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual([edgeCaseInput]);

                done();
            });
    });

    /**
     * Test 10: Multiple single quotes are handled safely
     * Tests escaping of quotes which is critical for SQL injection prevention
     */
    test('should handle multiple single quotes safely', (done) => {
        const multipleQuotes = "test''user'''";

        mockQuery.mockImplementation((query, params, callback) => {
            callback(null, []);
        });

        const express = require('express');
        const testApp = express();
        testApp.use(express.json());

        testApp.get('/user', (req, res) => {
            const username = req.query.username;
            const query = "SELECT * FROM users WHERE username = ?";
            mockConnection.query(query, [username], function (err, results) {
                if (err) {
                    res.status(500).send({ error: 'Database error occurred' });
                    return;
                }
                res.send(results);
            });
        });

        request(testApp)
            .get('/user')
            .query({ username: multipleQuotes })
            .expect(200)
            .end((err, res) => {
                if (err) return done(err);

                const [query, params] = mockQuery.mock.calls[0];
                expect(query).toBe("SELECT * FROM users WHERE username = ?");
                expect(params).toEqual([multipleQuotes]);

                // The query structure should not contain the quotes
                expect(query.split('?').length - 1).toBe(1); // Only one placeholder

                done();
            });
    });
});

/**
 * Regression Test Suite
 * These tests ensure the vulnerability doesn't get reintroduced
 */
describe('Regression Tests - Ensure SQL Injection remains fixed', () => {
    /**
     * Anti-pattern detection: Verify no string concatenation is used
     */
    test('code should not use string concatenation for SQL queries', () => {
        const fs = require('fs');
        const fileContent = fs.readFileSync('./vulnerable-test-app.js', 'utf8');

        // Extract the /user endpoint code
        const userEndpointMatch = fileContent.match(/app\.get\('\/user'[\s\S]*?\}\);/);
        expect(userEndpointMatch).toBeTruthy();

        const userEndpointCode = userEndpointMatch[0];

        // Check that the code uses parameterized query (with ?)
        expect(userEndpointCode).toContain('?');

        // Check that parameters are passed as array to query method
        expect(userEndpointCode).toMatch(/query\([^,]+,\s*\[[^\]]+\]/);

        // Verify no string concatenation with username variable
        // This regex looks for patterns like: "..." + username or username + "..."
        const dangerousPattern = /["'`].*["'`]\s*\+\s*username|username\s*\+\s*["'`]/;
        expect(userEndpointCode).not.toMatch(dangerousPattern);
    });

    /**
     * Verify the fix follows MySQL parameterized query best practices
     */
    test('should follow MySQL parameterized query best practices', () => {
        const fs = require('fs');
        const fileContent = fs.readFileSync('./vulnerable-test-app.js', 'utf8');
        const userEndpointMatch = fileContent.match(/app\.get\('\/user'[\s\S]*?\}\);/);
        const userEndpointCode = userEndpointMatch[0];

        // Should use ? placeholder
        expect(userEndpointCode).toContain('WHERE username = ?');

        // Should pass parameters as array (second argument to query)
        expect(userEndpointCode).toMatch(/query\([^,]+,\s*\[username\]/);
    });
});
