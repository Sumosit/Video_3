import { test, expect } from '@playwright/test';

const apiBaseUrl = 'http://localhost:8000'; // Adjust if your server runs elsewhere

test.describe('Authorization API End-to-End Tests', () => {
  let registeredUserEmail = 'testuser@example.com';
  const password = 'SecurePass123!';
  let accessToken = '';

  test('User Registration', async ({ request }) => {
    const response = await request.post(`${apiBaseUrl}/register`, {
      data: {
        email: registeredUserEmail,
        password: password,
        full_name: 'Test User',
        role: 'user'
      }
    });
    expect(response.status()).toBe(201);
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('id');
    expect(responseBody).toHaveProperty('email', registeredUserEmail);
  });

  test('User Login and Token Generation', async ({ request }) => {
    const response = await request.post(`${apiBaseUrl}/token`, {
      data: {
        username: registeredUserEmail,
        password: password
      }
    });
    expect(response.status()).toBe(200);
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('access_token');
    accessToken = responseBody.access_token;
  });

  test('Access Protected Route with Valid Token', async ({ request }) => {
    const response = await request.get(`${apiBaseUrl}/users/me`, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    expect(response.status()).toBe(200);
    const userData = await response.json();
    expect(userData).toHaveProperty('email', registeredUserEmail);
  });

  test('Access Protected Route without Token should Fail', async ({ request }) => {
    const response = await request.get(`${apiBaseUrl}/users/me`);
    expect(response.status()).toBe(401);
  });

  test('Access Protected Route with Invalid Token should Fail', async ({ request }) => {
    const response = await request.get(`${apiBaseUrl}/users/me`, {
      headers: {
        Authorization: `Bearer invalidtoken123`
      }
    });
    expect(response.status()).toBe(401);
  });

  test('RSA Encryption and Decryption of JWT', async ({ request }) => {
    // Generate encrypted JWT
    const generateResponse = await request.post(`${apiBaseUrl}/generate-rsa-jwt`);
    expect(generateResponse.status()).toBe(200);
    const generateBody = await generateResponse.json();
    const encryptedHex = generateBody['§14'];
    expect(encryptedHex).toBeDefined();

    // Verify encrypted JWT
    const verifyResponse = await request.post(`${apiBaseUrl}/verify-rsa-jwt`, {
      data: { encrypted_token_hex: encryptedHex }
    });
    expect(verifyResponse.status()).toBe(200);
    const verifyBody = await verifyResponse.json();
    expect(verifyBody).toHaveProperty('sub');
    expect(verifyBody).toHaveProperty('role');
  });

  test('Ensure Protected Route is Secure Against XSS', async ({ page }) => {
    // Attempt to inject script via token (simulate XSS attack)
    const maliciousToken = '<script>alert(1)</script>';
    const response = await page.request.get(`${apiBaseUrl}/users/me`, {
      headers: {
        Authorization: `Bearer ${maliciousToken}`
      }
    });
    expect(response.status()).toBe(401); // Should not execute script, just reject
  });
});