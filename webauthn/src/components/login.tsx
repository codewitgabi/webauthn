"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { useState } from "react";

const API_URL = import.meta.env.VITE_API_URL;

function Login() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");

  const handleLogin = async () => {
    try {
      // Get authentication options
      const optionsResponse = await fetch(`${API_URL}/api/auth/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const options = await optionsResponse.json();

      // Start WebAuthn authentication
      const authResponse = await startAuthentication(options);

      // Verify authentication
      const verificationResponse = await fetch(`${API_URL}/api/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          response: authResponse,
          challenge: options.challenge,
        }),
      });
      const verification = await verificationResponse.json();

      if (verification.verified) {
        setMessage("Login successful!");
      } else {
        setMessage("Login failed.");
      }
    } catch (error) {
      setMessage(
        `Error: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  };

  return (
    <div>
      <h2 className="text-lg font-medium">Login with Biometrics</h2>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter email"
        className="outline-none border border-gray-300 p-2 rounded-md w-full inline-block mt-4"
      />
      <button
        onClick={handleLogin}
        className="py-2 px-4 rounded-lg text-base border border-teal-200 hover:bg-teal-200 hover:text-white transition-all duration-300 mt-4 inline-block"
      >
        Login
      </button>
      <p className="text-sm text-gray-500 mt-2">{message}</p>
    </div>
  );
}

export default Login;
