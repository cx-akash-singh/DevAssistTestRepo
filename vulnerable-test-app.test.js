/**
 * Security Tests for SQL Injection Remediation
 * Tests the /user endpoint to ensure SQL injection vulnerability is fixed
 */

const request = require('supertest');
const mysql = require('mysql');

// Mock the mysql module to avoid actual database connections
jest.mock('mysql');

describe('SQL Injection Remediation Tests', () => {
    let app;
    let mockConnection;
    let mockQuery;

    beforeEach(() => {
        // Reset modules to get a fresh app instance
        jest.resetModules();

        // Setup mock connection and query function
        mockQuery = jest.fn();
        mockConnection = {
            connect: jest.fn(),
            query: mockQuery,
            end: jest.fn()
        };

        // Mock mysql.createConnection to return our mock connection
        mysql.createConnection.mockReturnValue(mockConnection);

        // Import app after mocking
        app = require('./vulnerable-test-app.js');
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Parameterized Query Implementation', () => {
        test('should use parameterized query with placeholder', (done) => {
            const testUsername = 'testuser';

            // Mock successful query response
            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, [{ id: 1, username: 'testuser' }]);
            });

            request(app)
                .get('/user')
                .query({ username: testUsername })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    // Verify parameterized query was used
                    expect(mockQuery).toHaveBeenCalledTimes(1);
                    const [query, params] = mockQuery.mock.calls[0];

                    // Check that query uses placeholder (?)
                    expect(query).toContain('?');
                    expect(query).not.toContain(testUsername);

                    // Check that parameters are passed as array
                    expect(Array.isArray(params)).toBe(true);
                    expect(params).toEqual([testUsername]);

                    done();
                });
        });

        test('should prevent SQL injection with malicious input - single quote', (done) => {
            const maliciousInput = "' OR '1'='1";

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: maliciousInput })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];

                    // Verify the malicious input is passed as parameter, not concatenated
                    expect(query).toContain('?');
                    expect(query).not.toContain("' OR '1'='1");
                    expect(params).toEqual([maliciousInput]);

                    // The malicious input should be treated as literal string by the database
                    expect(params[0]).toBe(maliciousInput);

                    done();
                });
        });

        test('should prevent SQL injection with UNION attack', (done) => {
            const maliciousInput = "' UNION SELECT * FROM admin_users--";

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: maliciousInput })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];

                    // Verify UNION attack is neutralized
                    expect(query).toContain('?');
                    expect(query).not.toContain('UNION');
                    expect(params).toEqual([maliciousInput]);

                    done();
                });
        });

        test('should prevent SQL injection with comment-based attack', (done) => {
            const maliciousInput = "admin'--";

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: maliciousInput })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];

                    // Verify comment-based attack is neutralized
                    expect(query).toContain('?');
                    expect(params).toEqual([maliciousInput]);

                    done();
                });
        });

        test('should prevent SQL injection with stacked queries', (done) => {
            const maliciousInput = "'; DROP TABLE users;--";

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: maliciousInput })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];

                    // Verify stacked query attack is neutralized
                    expect(query).toContain('?');
                    expect(query).not.toContain('DROP');
                    expect(params).toEqual([maliciousInput]);

                    done();
                });
        });
    });

    describe('Positive Functionality Tests', () => {
        test('should return user data for valid username', (done) => {
            const expectedUser = { id: 1, username: 'john', email: 'john@example.com' };

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, [expectedUser]);
            });

            request(app)
                .get('/user')
                .query({ username: 'john' })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    expect(res.body).toEqual([expectedUser]);
                    done();
                });
        });

        test('should handle username with spaces correctly', (done) => {
            const username = 'john doe';

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, [{ id: 2, username: 'john doe' }]);
            });

            request(app)
                .get('/user')
                .query({ username })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];
                    expect(params).toEqual([username]);

                    done();
                });
        });

        test('should handle username with special characters safely', (done) => {
            const username = "user@example.com";

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, [{ id: 3, username: 'user@example.com' }]);
            });

            request(app)
                .get('/user')
                .query({ username })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];
                    expect(params).toEqual([username]);

                    done();
                });
        });

        test('should return empty results for non-existent user', (done) => {
            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: 'nonexistent' })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    expect(res.body).toEqual([]);
                    done();
                });
        });
    });

    describe('Error Handling Tests', () => {
        test('should handle database errors gracefully', (done) => {
            mockQuery.mockImplementation((query, params, callback) => {
                callback(new Error('Database connection failed'), null);
            });

            request(app)
                .get('/user')
                .query({ username: 'testuser' })
                .expect(500)
                .end((err, res) => {
                    if (err) return done(err);

                    // Verify error message doesn't expose internal details
                    expect(res.body).toHaveProperty('error');
                    expect(res.body.error).toBe('Database query failed');
                    expect(res.body.error).not.toContain('Database connection failed');

                    done();
                });
        });

        test('should not expose stack traces in error responses', (done) => {
            const dbError = new Error('Internal database error');
            dbError.stack = 'Error: Internal database error\n    at Connection.query (/app/node_modules/mysql/lib/Connection.js:203:25)';

            mockQuery.mockImplementation((query, params, callback) => {
                callback(dbError, null);
            });

            request(app)
                .get('/user')
                .query({ username: 'testuser' })
                .expect(500)
                .end((err, res) => {
                    if (err) return done(err);

                    const responseText = JSON.stringify(res.body);
                    expect(responseText).not.toContain('node_modules');
                    expect(responseText).not.toContain('Connection.js');
                    expect(responseText).not.toContain(dbError.stack);

                    done();
                });
        });
    });

    describe('Edge Cases and Boundary Tests', () => {
        test('should handle undefined username parameter', (done) => {
            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];
                    expect(params).toBeDefined();
                    expect(Array.isArray(params)).toBe(true);

                    done();
                });
        });

        test('should handle empty string username', (done) => {
            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: '' })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];
                    expect(params).toEqual(['']);

                    done();
                });
        });

        test('should handle very long username strings', (done) => {
            const longUsername = 'a'.repeat(1000);

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: longUsername })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];
                    expect(params[0]).toBe(longUsername);
                    expect(params[0].length).toBe(1000);

                    done();
                });
        });

        test('should handle username with null bytes', (done) => {
            const usernameWithNull = "user\x00admin";

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            request(app)
                .get('/user')
                .query({ username: usernameWithNull })
                .expect(200)
                .end((err, res) => {
                    if (err) return done(err);

                    const [query, params] = mockQuery.mock.calls[0];
                    expect(params).toEqual([usernameWithNull]);

                    done();
                });
        });
    });

    describe('Regression Prevention Tests', () => {
        test('should never concatenate user input into SQL query string', (done) => {
            const testInputs = [
                "normal_user",
                "' OR '1'='1",
                "admin'--",
                "'; DROP TABLE users;--",
                "' UNION SELECT * FROM passwords--"
            ];

            let completed = 0;

            testInputs.forEach(input => {
                mockQuery.mockImplementation((query, params, callback) => {
                    callback(null, []);
                });

                request(app)
                    .get('/user')
                    .query({ username: input })
                    .expect(200)
                    .end((err, res) => {
                        if (err) return done(err);

                        const [query, params] = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];

                        // Critical: Query string should NEVER contain the actual user input
                        expect(query).not.toContain(input);
                        // Query should use placeholder
                        expect(query).toContain('?');
                        // Input should be in parameters array
                        expect(params).toContain(input);

                        completed++;
                        if (completed === testInputs.length) {
                            done();
                        }
                    });
            });
        });

        test('should maintain parameterized query format across multiple requests', (done) => {
            let requestCount = 0;
            const totalRequests = 5;

            mockQuery.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            for (let i = 0; i < totalRequests; i++) {
                request(app)
                    .get('/user')
                    .query({ username: `user${i}` })
                    .expect(200)
                    .end((err, res) => {
                        if (err) return done(err);

                        requestCount++;

                        if (requestCount === totalRequests) {
                            // Verify all calls used parameterized queries
                            expect(mockQuery).toHaveBeenCalledTimes(totalRequests);

                            mockQuery.mock.calls.forEach(([query, params], index) => {
                                expect(query).toContain('?');
                                expect(Array.isArray(params)).toBe(true);
                                expect(params).toEqual([`user${index}`]);
                            });

                            done();
                        }
                    });
            }
        });
    });
});
