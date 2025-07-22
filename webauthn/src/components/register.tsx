"use client";

import { startRegistration } from "@simplewebauthn/browser";
import { useState } from "react";

const API_URL = import.meta.env.VITE_API_URL;

function Register() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");

  const handleRegister = async () => {
    try {
      // Get registration options from FastAPI
      const optionsResponse = await fetch(`${API_URL}/api/register/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const options = await optionsResponse.json();

      // Start WebAuthn registration
      const regResponse = await startRegistration(options);

      // Verify registration
      const verificationResponse = await fetch(
        `${API_URL}/api/register/verify`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email,
            response: regResponse,
            challenge: options.challenge,
          }),
        }
      );
      const verification = await verificationResponse.json();

      if (verification.verified) {
        setMessage("Registration successful!");
      } else {
        setMessage("Registration failed.");
      }
    } catch (error) {
      setMessage(
        `Error: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  };

  return (
    <div className="">
      <h2 className="text-lg font-medium">Register with Biometrics</h2>

      <input
        type="email"
        name="email"
        required
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter email"
        className="outline-none border border-gray-300 p-2 rounded-md w-full inline-block mt-4"
      />

      <button
        onClick={handleRegister}
        className="py-2 px-4 rounded-lg text-base border border-teal-200 hover:bg-teal-200 hover:text-white transition-all duration-300 mt-4 inline-block"
      >
        Register
      </button>

      <p className="text-sm text-gray-500 mt-2">{message}</p>
    </div>
  );
}

export default Register;
